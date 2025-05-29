#include "mrpa.hpp"

#include <libxml++/attribute.h>
#include <libxml++/libxml++.h>
#include <libxml++/nodes/element.h>
#include <libxml++/validators/xsdvalidator.h>
#include <libxml++/xsdschema.h>

#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <cstddef>
#include <exception>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <optional>
#include <string>
#include <type_traits>
#include <utility>

#include "logger_utils.hpp"
#include "mrpa_defs.hpp"
#include "xsd1.hpp"

namespace mrpa {

Mrpa::Mrpa(const std::string& filename) noexcept
  : filename_(filename), logger_(pdfcsp::logger::InitLog()) {
  if (filename.empty() || !std::filesystem::exists(filename)) {
    return;
  }
  // auto mrpa = std::make_unique<xmlpp::DomParser>();
  try {
    const std::string xsd(mrpa::xsd1.cbegin(), mrpa::xsd1.cend());
    auto schema = std::make_unique<xmlpp::XsdSchema>();
    schema->parse_memory(xsd);
    auto validator = std::make_unique<xmlpp::XsdValidator>();
    validator->set_schema(schema.get(), false);
    auto mrpa = std::make_unique<xmlpp::DomParser>();
    mrpa->parse_file(filename);
    xmlpp::Document* doc = mrpa->get_document();
    validator->validate(doc);
    if (!validator || !mrpa || doc == nullptr) {
      return;
    }
    doc_ = doc;
    dom_parser = std::move(mrpa);
    ParseFlags();
    if (!flags_valid_) {
      return;
    }
    ParseName();
    if (!name_valid_) {
      return;
    }
    CheckHeader();
    if (!header_valid_) {
      return;
    }
    is_valid_ = true;
  } catch (const std::exception& ex) {
    std::cerr << "[MRPA] error parsing the MRPA: " << ex.what() << "\n";
    err_string_.emplace(ex.what());
  }
}

void Mrpa::ParseFlags() {
  flags_valid_ = false;
  if (doc_ == nullptr) {
    return;
  }
  const xmlpp::Element* root_node = doc_->get_root_node();
  if (root_node == nullptr) {
    return;
  }
  const xmlpp::Attribute* attribute_flags =
    root_node->get_attribute(kAttributeFlags);
  if (attribute_flags == nullptr) {
    return;
  }
  auto val = attribute_flags->get_value();
  if (val.size() != kFlagsValLen) {
    return;
  }
  for (size_t i = 0; i < kFlagsValLen; ++i) {
    if (val[i] == '0') {
      flags_.reset(i);
    } else if (val[i] == '1') {
      flags_.set(i);
    } else {
      return;
    }
  }
  // this flags should always be false
  const bool always_false_invalid = flags_.test(0) || flags_.test(4) ||
                                    flags_.test(5) || flags_.test(6) ||
                                    flags_.test(7);
  flags_valid_ = !always_false_invalid;
}

void Mrpa::ParseName() {
  const xmlpp::Element* root_node = doc_->get_root_node();
  if (root_node == nullptr || !flags_valid_) {
    return;
  }
  // compare the file id with the filename
  name_valid_ = false;
  // file ID normal attribute
  const xmlpp::Attribute* attribute_file_id =
    root_node->get_attribute(kAttributeFileID);
  if (attribute_file_id == nullptr) {
    return;
  }
  auto val_file_id = attribute_file_id->get_value();
  // file ID for tax cervice attribute
  const xmlpp::Attribute* attribute_file_id_tax =
    root_node->get_attribute(kAttributeFileIDTax);
  std::optional<std::string> file_id_tax_val;
  if (flags_.test(kFlagDovelPos) && attribute_file_id_tax != nullptr) {
    file_id_tax_val = attribute_file_id_tax->get_value();
  }
  std::string filename_stem;
  filename_stem = std::filesystem::path(filename_).stem().string();

// REGION start Only for test
// remove prefix from file (to use with the test set of file);
#ifdef MRPA_REMOVE_PREFIX
  {
    std::cerr
      << "[WARNING] This is a test build, removing prefixe the from filename\n";
    std::string::size_type pos_start = filename_stem.find("ON");
    if (pos_start != std::string::npos && pos_start != 0) {
      filename_stem.erase(0, pos_start);
    }
    std::cout << filename_stem << "\n";
    // std::cout << val_file_id << "\n";
  }
#endif
  // REGION end Only for test
  const bool file_is_named_for_tax =
    file_id_tax_val.has_value() && filename_stem == file_id_tax_val;
  if (filename_stem != val_file_id && !file_is_named_for_tax) {
    return;
  }
  // if for tax file_id_tax_val must start with "ON_DOVEL"
  if (flags_.test(kFlagDovelPos) &&
      !boost::algorithm::starts_with(file_id_tax_val.value_or(""),
                                     kPrefixTax)) {
    return;
  }
  // if not for tax service filename_stem must start with ON_EMCHD
  if (!flags_.test(kFlagDovelPos) &&
      !boost::algorithm::starts_with(filename_stem, kPrefixNormal)) {
    return;
  }
  const auto attorney_uid = GetMRPAGuid(doc_);
  if (!attorney_uid.has_value()) {
    return;
  }
  if (!boost::algorithm::ends_with(filename_stem, attorney_uid.value())) {
    return;
  }
  name_valid_ = true;
}

void Mrpa::CheckHeader() {
  if (filename_.empty() || !std::filesystem::exists(filename_)) {
    return;
  }
  using DeleterType = void (*)(std::basic_ifstream<char>*);
  auto file = std::unique_ptr<std::basic_ifstream<char>, DeleterType>(
    new std::ifstream(filename_),
    [](std::basic_ifstream<char>* file) { file->close(); });
  if (!file && !file->is_open()) {
    return;
  }
  std::string first_line;
  std::getline(*file, first_line);
  if (first_line.empty() ||
      !boost::algorithm::ends_with(first_line, kHeaderString)) {
    if (logger_) {
      logger_->warn("[Mrpa::CheckHeader] Invalid header {}", first_line);
      logger_->warn("[Mrpa::CheckHeader] expected: {}", kHeaderString);
    }
    return;
  }
  header_valid_ = true;
}

// ------------------------------
// Free functions

/// @brief get the MRPA uid from XML
std::optional<std::string> GetMRPAGuid(xmlpp::Document* doc) noexcept {
  if (doc == nullptr) {
    return std::nullopt;
  }
  const auto* root = doc->get_root_node();
  if (root == nullptr) {
    return std::nullopt;
  }
  const auto* el_document = root->get_first_child(kNodeDocument);
  if (el_document == nullptr) {
    return std::nullopt;
  }
  const auto* el_attorney = el_document->get_first_child(kNodeAttorney);
  if (el_attorney == nullptr) {
    return std::nullopt;
  }
  const auto* el_attorney_info = dynamic_cast<const xmlpp::Element*>(
    el_attorney->get_first_child(kNodeAttorneyInfo));
  if (el_attorney_info == nullptr) {
    return std::nullopt;
  }
  const auto* attrib_attorney_id =
    el_attorney_info->get_attribute(kAttributeAttorneyID);
  if (attrib_attorney_id == nullptr) {
    return std::nullopt;
  }
  return attrib_attorney_id->get_value();
}

}  // namespace mrpa
