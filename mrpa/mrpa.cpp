/* File: mrpa.cpp
Copyright (C) Basealt LLC,  2025
Author: Oleg Proskurin, <proskurinov@basealt.ru>

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with this program; if not, write to the Free Software Foundation,
Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

#include "mrpa.hpp"

#include <libxml++/attribute.h>
#include <libxml++/libxml++.h>
#include <libxml++/nodes/element.h>
#include <libxml++/validators/xsdvalidator.h>
#include <libxml++/xsdschema.h>

#include <algorithm>
#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/case_conv.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/algorithm/string/trim.hpp>
#include <boost/json.hpp>
#include <boost/json/array.hpp>
#include <boost/json/object.hpp>
#include <boost/json/parse.hpp>
#include <boost/json/serialize.hpp>
#include <boost/json/string.hpp>
#include <boost/json/string_view.hpp>
#include <boost/lexical_cast.hpp>
#include <chrono>
#include <cstddef>
#include <ctime>
#include <exception>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>

#include "c_bridge.hpp"
#include "common_utils.hpp"
#include "grantors.hpp"
#include "logger_utils.hpp"
#include "mrpa_defs.hpp"
#include "pod_structs.hpp"
#include "typedefs.hpp"
#include "utils_mrpa.hpp"
#include "xsd1.hpp"

namespace mrpa {

Mrpa::Mrpa(const std::string& filename) noexcept
  : filename_(filename), logger_(pdfcsp::logger::InitLog()) {
  if (filename.empty() || !std::filesystem::exists(filename)) {
    logger_->error("[MRPA] file not found {}", filename);
    return;
  }
  try {
    logger_->debug("[MRPA] Start validation of {}",
                   std::filesystem::path(filename).stem().string());
    const std::string xsd(mrpa::xsd1.cbegin(), mrpa::xsd1.cend());
    auto schema = std::make_unique<xmlpp::XsdSchema>();
    schema->parse_memory(xsd);
    auto validator = std::make_unique<xmlpp::XsdValidator>();
    validator->set_schema(schema.get(), false);
    auto mrpa = std::make_unique<xmlpp::DomParser>();
    mrpa->parse_file(filename);
    xmlpp::Document* doc = mrpa->get_document();
    validator->validate(doc);
    if (doc == nullptr) {
      logger_->error("[Mrpa] the scheme is not valid for {}", filename);
      return;
    }
    doc_ = doc;
    dom_parser = std::move(mrpa);
    ParseFlags();
    logger_->debug("[MRPA] Flags valid {}", flags_valid_);
    // save JSON representation
    json_val_ = utils::MrpaToJsonObject(doc_);
    if (!json_val_.has_value()) {
      logger_->error("[MRPA] error convertring the mrpa to JSON");
      return;
    }
    // std::cout << boost::json::serialize(json_val_.value()) << "\n";
    logger_->debug("[MRPA] convert to JSON:{}",
                   (json_val_.has_value() ? "OK" : "FAILED"));
    ParseGrantors();
    logger_->debug("[MRPA] parse grantors:{}",
                   (grantor_.has_value() ? "OK" : "FAILED"));

    // std::cout << boost::json::serialize(grantor_->ToJson());
    ParseNotaries();
    ParseRepresentatives();
    ParseTime();
    logger_->debug("[MRPA] parse representatives result:{} person(s)",
                   persons_representative_.size());
    if (!flags_valid_) {
      return;
    }
    ParseName();
    logger_->debug("[MRPA] name valid: {}", (name_valid_ ? "TRUE" : "FALSE"));
    if (!name_valid_) {
      return;
    }
    CheckHeader();
    logger_->debug("[MRPA] header valid: {}",
                   (header_valid_ ? "TRUE" : "FALSE"));
    if (!header_valid_) {
      return;
    }
    is_valid_ = true;
  } catch (const std::exception& ex) {
    logger_->debug("[MRPA] error parsing the MRPA: {}", ex.what());
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

void Mrpa::ParseRepresentatives() {
  const auto& attorney = utils::GetAttorneyObj(json_val_);
  persons_representative_ = utils::ParseAllRepresentativePersons(attorney);
}

void Mrpa::ParseGrantors() {
  constexpr const char* parse_err =
    "[Mrpa::ParseGrantors] parse grantors error";
  const auto& attorney = utils::GetAttorneyObj(json_val_);
  const auto& grantor_top = attorney.at(kXMLGrantorInfoTop).as_object();
  if (!grantor_top.contains(kGranterTypeAttr) ||
      !grantor_top.contains(kXMLGrantor)) {
    throw std::runtime_error(parse_err);
  }
  auto gr_type = boost::lexical_cast<int>(
    grantor_top.at(kGranterTypeAttr).as_string().c_str(),
    grantor_top.at(kGranterTypeAttr).as_string().size());
  if (gr_type < 0 || gr_type > 4) {
    throw std::runtime_error(parse_err);
  }
  auto grantor_type = static_cast<GrantorType>(gr_type);
  logger_->debug("[Mrpa::ParseGrantors] grantor_type {}",
                 ToString(grantor_type));
  switch (grantor_type) {
    case GrantorType::kCompany: {
      const auto& russian_company_grantor = grantor_top.at(kXMLGrantor)
                                              .as_object()
                                              .at(kXMLGrantorRussianCompany)
                                              .as_object();
      grantor_.emplace(
        mrpa::utils::ParseCompanyGrantor(russian_company_grantor));
      break;
    }
    case GrantorType::kForeignCompany: {
      const auto& foreign_company_grantor = grantor_top.at(kXMLGrantor)
                                              .as_object()
                                              .at(kXMLGrantorForeignCompany)
                                              .as_object();
      grantor_.emplace(
        mrpa::utils::ParseForeignCompanyGrantor(foreign_company_grantor));
      break;
    }
    case GrantorType::kIP: {
      const auto& ip_grantor =
        grantor_top.at(kXMLGrantor).as_object().at(kXMLGrantorIp).as_object();
      grantor_.emplace(utils::ParseIPGrantor(ip_grantor));
      break;
    }
    case GrantorType::kPerson: {
      const auto& person_grantor = grantor_top.at(kXMLGrantor)
                                     .as_object()
                                     .at(kXMLGrantorPerson)
                                     .as_object();
      grantor_.emplace(utils::ParsePersonGrantor(person_grantor));
      break;
    }
    default:
      throw std::runtime_error(parse_err);
  }
}

void Mrpa::ParseNotaries() {
  if (!grantor_.has_value()) {
    logger_->info("[Mrpa::ParseNotaries] empty grantor object");
    return;
  }
  if (!json_val_) {
    logger_->info("[Mrpa::ParseNotaries] empty json representation");
    return;
  }
  const auto& attorney = utils::GetAttorneyObj(json_val_);
  if (!attorney.contains(kXMLNotaryInfo)) {
    logger_->info("[Mrpa::ParseNotaries] notary info object not found");
    return;
  }
  const auto& notary_info = attorney.at(kXMLNotaryInfo).as_object();
  if (!notary_info.contains(kXMLNotaryPersonInfo)) {
    logger_->info("[Mrpa::ParseNotaries] notaries not found");
    return;
  }
  const auto& notary_person_info =
    notary_info.at(kXMLNotaryPersonInfo).as_object();
  if (!notary_person_info.contains(kXMLNotaryPersonNameInfo)) {
    logger_->error("[Mrpa::ParseNotaries] notary person name not found,{}",
                   kXMLNotaryPersonInfo);
    return;
  }
  const auto& fio = notary_person_info.at(kXMLNotaryPersonNameInfo).as_object();
  logger_->debug(boost::json::serialize(fio));
  PhysicalPerson notary;
  notary.last_name = fio.at(kPersonLastName).as_string().c_str();
  notary.name = fio.at(kPersonName).as_string().c_str();
  if (fio.contains(kPersonPatronymic)) {
    notary.patronymic.emplace(fio.at(kPersonPatronymic).as_string().c_str());
  }
  logger_->info("[Mrpa::ParseNotaries] notary found:{} {} {}", notary.last_name,
                notary.name, notary.patronymic.value_or(""));
  grantor_->all_persons.emplace_back(std::move(notary));
  // parse <ВриоНот>
  if (notary_info.contains(kXMLNotaryExecutorPersonInfo)) {
    const auto& notary_executor_info =
      notary_info.at(kXMLNotaryExecutorPersonInfo).as_object();
    if (notary_executor_info.contains(kXMLNotaryExecutorPersonInfoName)) {
      const auto& notary_executor_fio =
        notary_executor_info.at(kXMLNotaryExecutorPersonInfoName).as_object();
      PhysicalPerson notary_executor;
      notary_executor.last_name =
        notary_executor_fio.at(kPersonLastName).as_string().c_str();
      notary_executor.name =
        notary_executor_fio.at(kPersonName).as_string().c_str();
      if (notary_executor_fio.contains(kPersonPatronymic)) {
        notary_executor.patronymic.emplace(
          notary_executor_fio.at(kPersonPatronymic).as_string().c_str());
      }
      logger_->info(
        "[Mrpa::ParseNotaries] notary executor person found:{} {} {}",
        notary_executor.last_name, notary_executor.name,
        notary_executor.patronymic.value_or(""));
      grantor_->all_persons.emplace_back(std::move(notary_executor));
    }
  }
}

void Mrpa::ParseName() {
  const xmlpp::Element* root_node = doc_->get_root_node();
  if (root_node == nullptr || !flags_valid_) {
    logger_->error("[Mrpa::ParseName] invalid document");
  }
  // compare the file id with the filename
  name_valid_ = false;
  // file ID normal attribute
  const xmlpp::Attribute* attribute_file_id =
    root_node->get_attribute(kAttributeFileID);
  if (attribute_file_id == nullptr) {
    logger_->error("[MRPA::ParseName] {} not found", kAttributeFileID);
    return;
  }
  auto val_file_id = attribute_file_id->get_value();
  // file ID for tax service attribute
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
      << "[WARNING] This is a test build, removing prefix the from filename\n";
    const std::string::size_type pos_start = filename_stem.find("ON");
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
  logger_->debug("[MRPA::ParseName] file is for tax: {}",
                 file_is_named_for_tax);
  if (filename_stem != val_file_id && !file_is_named_for_tax) {
    return;
  }
  // if for tax file_id_tax_val must start with "ON_DOVEL"
  if (flags_.test(kFlagDovelPos) &&
      !boost::algorithm::starts_with(file_id_tax_val.value_or(""),
                                     kPrefixTax)) {
    logger_->error("[MRPA:ParseName] wrong filename for tax");
    return;
  }
  // if not for tax service filename_stem must start with ON_EMCHD
  if (!flags_.test(kFlagDovelPos) &&
      !boost::algorithm::starts_with(filename_stem, kPrefixNormal)) {
    logger_->error("[MRPA:ParseName] ON_EMCHD prefix is expected");
    return;
  }
  auto attorney_uid = utils::GetMRPAGuid(doc_);
  logger_->debug("[MRPA::ParseName] GetMRPAGuid:{}",
                 (attorney_uid.has_value() ? "OK" : "FAILED"));
  if (!attorney_uid.has_value()) {
    return;
  }
  boost::algorithm::to_upper(*attorney_uid);
  std::string stem_upper = boost::algorithm::to_upper_copy(filename_stem);
  boost::algorithm::trim(stem_upper);
  if (!boost::algorithm::ends_with(stem_upper, attorney_uid.value())) {
    logger_->error("[MRPA::ParseName] the filename should end with {}",
                   attorney_uid.value());
    return;
  }
  name_valid_ = true;
}

/**
 * @brief Parse issue date,expire date
 * @details called on non-default construct
 * @throws runtime_error
 */
void Mrpa::ParseTime() {
  const auto& attorney = utils::GetAttorneyObj(json_val_);
  const auto& attorney_info = attorney.at(kNodeAttorneyInfo).as_object();
  const std::string issue_date =
    attorney_info.at(kAttorneyIssueDate).as_string().c_str();
  const std::string expire_date =
    attorney_info.at(kAttorneyExpireDate).as_string().c_str();
  const time_t not_before = utils::ParseXMLDate(issue_date);
  const time_t not_after = utils::ParseXMLDate(expire_date);
  auto const now = std::chrono::system_clock::now();
  const std::time_t newt = std::chrono::system_clock::to_time_t(now);
  if (newt > not_before && newt < not_after) {
    time_valid_ = true;
  } else {
    logger_->warn(
      "[Mrpa::ParseTime] The MRPA time is invalid: NotBefore: {}, NotAfter:{}",
      issue_date, expire_date);
  }
}

void Mrpa::CheckHeader() {
  if (filename_.empty() || !std::filesystem::exists(filename_)) {
    return;
  }
  using DeleterType = void (*)(std::basic_ifstream<char>*);
  auto file = std::unique_ptr<std::basic_ifstream<char>, DeleterType>(
    new std::ifstream(filename_), [](std::basic_ifstream<char>* file) {
      file->close();
      delete file;  // NOLINT
    });
  if (!file && !file->is_open()) {
    return;
  }
  std::string first_line;
  std::getline(*file, first_line);
  std::string upper_case_header = boost::algorithm::to_upper_copy(first_line);
  pdfcsp::utils::RemoveWhiteSpacesInline(upper_case_header);
  std::string upper_case_expected =
    boost::algorithm::to_upper_copy(std::string(kHeaderString));
  pdfcsp::utils::RemoveWhiteSpacesInline(upper_case_expected);
  if (first_line.empty() ||
      (!boost::algorithm::ends_with(first_line, kHeaderString) &&
       !boost::algorithm::ends_with(upper_case_header, upper_case_expected))) {
    if (logger_) {
      logger_->warn("[Mrpa::CheckHeader] Invalid header {}", upper_case_header);
      logger_->warn("[Mrpa::CheckHeader] expected: {}", upper_case_expected);
    }
    return;
  }
  header_valid_ = true;
}

/// @brief set signature file
void Mrpa::setSignature(const std::string& sig_filename) noexcept {
  if (sig_filename.empty() || !std::filesystem::exists(sig_filename)) {
    return;
  }
  // check if the signature is attached
  pdfcsp::c_bridge::SeparateSignatureParams cparams{};
  cparams.sig_file_path = sig_filename.c_str();
  cparams.sig_file_path_size = sig_filename.size();
  if (pdfcsp::c_bridge::IsMessageAttached(&cparams) == 1 && logger_) {
    logger_->error("The MRPA signature must be a detached signature");
    return;
  }
  // read the signature
  const auto sig_raw = pdfcsp::utils::FileToVector(sig_filename);
  if (!sig_raw) {
    if (logger_) {
      logger_->error("Can not read the signature file");
    }
    return;
  }
  if (filename_.empty() && logger_) {
    logger_->error("No path for MRPA XML is set");
    return;
  }
  // check the signature
  const auto params = std::make_unique<pdfcsp::c_bridge::CPodParam>();
  params->raw_signature_data = sig_raw->data();
  params->raw_signature_size = sig_raw->size();
  params->file_path = filename_.c_str();
  params->file_path_size = filename_.size();
  auto check_result = std::shared_ptr<pdfcsp::c_bridge::CPodResult>(
    pdfcsp::c_bridge::CheckSimpleDetached(*params),
    pdfcsp::c_bridge::CFreeResult);
  if (!check_result) {
    if (logger_) {
      logger_->error("Failed to check signature {};", sig_filename);
    }
    return;
  }
  setSignature(check_result);
}

void Mrpa::setSignature(
  const std::shared_ptr<pdfcsp::c_bridge::CPodResult>& check_result) noexcept {
  sig_valid_ = false;
  signer_valid_ = false;
  if (!check_result) {
    return;
  }
  sig_valid_ = check_result->bres.check_summary;
  logger_->debug("Signature basic correctness:{}", sig_valid_);
  // get the signer's info
  SignaturePersonInfo info = utils::ExtractSignerInfo(check_result, logger_);
  // find the matches
  bool match_found = false;
  if (grantor_.has_value()) {
    logger_->info(
      "[Mrpa::setSignature] looking for inn: {}, surname: {},given_name: {} in "
      "grantor",
      info.signer_inn.value_or(""), info.signer_surname.value_or(""),
      info.signer_given_name.value_or(""));
    match_found = std::any_of(
      grantor_->all_persons.cbegin(), grantor_->all_persons.cend(),
      [&info](const PhysicalPerson& person) { return person == info; });
  }
  if (match_found) {
    logger_->info("[Mrpa::setSignature] match persons:OK");
    signer_valid_ = true;
  } else {
    logger_->warn(
      "[Mrpa::setSignature] signer does not match the MRPA grantor");
  }
}

}  // namespace mrpa