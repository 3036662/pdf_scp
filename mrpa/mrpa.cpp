#include "mrpa.hpp"

#include <libxml++/libxml++.h>
#include <libxml++/validators/xsdvalidator.h>
#include <libxml++/xsdschema.h>

#include <exception>
#include <filesystem>
#include <iostream>
#include <utility>

#include "xsd1.hpp"

namespace mrpa {

Mrpa::Mrpa(const std::string& filename) noexcept {
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
    if (validator && mrpa) {
      dom_parser = std::move(mrpa);
      is_valid_ = true;
    }
  } catch (const std::exception& ex) {
    std::cerr << "[MRPA] error parsing the MRPA: " << ex.what() << "\n";
    err_string_.emplace(ex.what());
  }
}

}  // namespace mrpa
