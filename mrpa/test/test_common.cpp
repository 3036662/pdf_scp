#include <libxml++/document.h>
#include <libxml++/parsers/domparser.h>
#include <linux-default/include/asm-generic/errno.h>

#include <algorithm>
#include <boost/algorithm/string/erase.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/json/serialize.hpp>
#include <boost/property_tree/ptree_fwd.hpp>
#include <chrono>
#include <cstddef>
#include <fstream>
#include <ios>
#include <thread>

#include "grantors.hpp"
#include "mrpa.hpp"
#include "mrpa_typedefs.hpp"
#include "typedefs.hpp"
#define CATCH_CONFIG_MAIN

#include <libxml++/libxml++.h>
#include <libxml++/validators/xsdvalidator.h>
#include <libxml++/xsdschema.h>

#include <catch2/catch.hpp>
#include <filesystem>
#include <iostream>
#include <memory>
#include <string>

#include "c_bridge.hpp"
#include "common_utils.hpp"
#include "string_defs.hpp"
#include "utils_mrpa.hpp"
#include "xsd1.hpp"

namespace {

inline std::string fn(size_t num) {
  return file_name_tmpl_head + std::to_string(num) + file_name_tmpl_tail;
}

}  // namespace

TEST_CASE("Initial_test") {
  REQUIRE(true);
  REQUIRE(std::filesystem::exists(test_files_dir));
  REQUIRE(std::filesystem::exists(mrpa_scheme));
  REQUIRE(std::filesystem::exists(mrpa1_valid));
}

TEST_CASE("Load_scheme") {
  REQUIRE(std::filesystem::exists(mrpa_scheme));
  auto schema = std::make_unique<xmlpp::XsdSchema>();
  // non existing file
  REQUIRE_THROWS(schema->parse_file("non_existing_file"));
  // non schema
  REQUIRE_THROWS(schema->parse_file(mrpa1_valid));
  // valid file
  REQUIRE_NOTHROW(schema->parse_file(mrpa_scheme));
}

TEST_CASE("Load_MRPA") {
  REQUIRE(std::filesystem::exists(mrpa1_valid));
  auto mrpa = std::make_unique<xmlpp::DomParser>();
  // non existing file
  REQUIRE_THROWS(mrpa->parse_file("non_existing_file"));
  // invalid xml
  REQUIRE_THROWS(mrpa->parse_file(mrpa1_invalid_broken));
  // valid file
  REQUIRE_NOTHROW(mrpa->parse_file(mrpa1_valid));
}

TEST_CASE("Validate_XML_with_XSD") {
  REQUIRE(std::filesystem::exists(mrpa_scheme));
  REQUIRE(std::filesystem::exists(mrpa1_valid));

  // load the XSD
  auto schema = std::make_unique<xmlpp::XsdSchema>();
  REQUIRE_NOTHROW(schema->parse_file(mrpa_scheme));
  // validator
  auto validator = std::make_unique<xmlpp::XsdValidator>();
  REQUIRE_NOTHROW(validator->set_schema(schema.get(), false));
  REQUIRE(validator);

  SECTION("VALID") {
    // load the valid
    auto mrpa = std::make_unique<xmlpp::DomParser>();
    REQUIRE_NOTHROW(mrpa->parse_file(mrpa1_valid));
    REQUIRE(mrpa->operator bool());
    // validate
    xmlpp::Document* doc = mrpa->get_document();
    REQUIRE(doc != nullptr);
    REQUIRE_NOTHROW(validator->validate(doc));
  }

  SECTION("INVALID1") {
    REQUIRE(std::filesystem::exists(mrpa_deleted_el1));
    // load the doc
    auto mrpa = std::make_unique<xmlpp::DomParser>();
    REQUIRE_NOTHROW(mrpa->parse_file(mrpa_deleted_el1));
    REQUIRE(mrpa->operator bool());
    // validate
    xmlpp::Document* doc = mrpa->get_document();
    REQUIRE(doc != nullptr);
    REQUIRE_THROWS_AS(validator->validate(doc), xmlpp::validity_error);
  }

  SECTION("INVALID2") {
    REQUIRE(std::filesystem::exists(mrpa_deleted_el2));
    // load the doc
    auto mrpa = std::make_unique<xmlpp::DomParser>();
    REQUIRE_NOTHROW(mrpa->parse_file(mrpa_deleted_el2));
    REQUIRE(mrpa->operator bool());
    // validate
    xmlpp::Document* doc = mrpa->get_document();
    REQUIRE(doc != nullptr);
    REQUIRE_THROWS_AS(validator->validate(doc), xmlpp::validity_error);
  }

  SECTION("INVALID3") {
    REQUIRE(std::filesystem::exists(mrpa_deleted_el3));
    // load the doc
    auto mrpa = std::make_unique<xmlpp::DomParser>();
    REQUIRE_NOTHROW(mrpa->parse_file(mrpa_deleted_el3));
    REQUIRE(mrpa->operator bool());
    // validate
    xmlpp::Document* doc = mrpa->get_document();
    REQUIRE(doc != nullptr);
    REQUIRE_THROWS_AS(validator->validate(doc), xmlpp::validity_error);
  }

  SECTION("INVALID4") {
    REQUIRE(std::filesystem::exists(mrpa_deleted_el4));
    // load the doc
    auto mrpa = std::make_unique<xmlpp::DomParser>();
    REQUIRE_NOTHROW(mrpa->parse_file(mrpa_deleted_el4));
    REQUIRE(mrpa->operator bool());
    // validate
    xmlpp::Document* doc = mrpa->get_document();
    REQUIRE(doc != nullptr);
    REQUIRE_THROWS_AS(validator->validate(doc), xmlpp::validity_error);
  }

  SECTION("INVALID4") {
    REQUIRE(std::filesystem::exists(mrpa_deleted_el4));
    // load the doc
    auto mrpa = std::make_unique<xmlpp::DomParser>();
    REQUIRE_NOTHROW(mrpa->parse_file(mrpa_deleted_el4));
    REQUIRE(mrpa->operator bool());
    // validate
    xmlpp::Document* doc = mrpa->get_document();
    REQUIRE(doc != nullptr);
    REQUIRE_THROWS_AS(validator->validate(doc), xmlpp::validity_error);
  }

  SECTION("INVALID5") {
    REQUIRE(std::filesystem::exists(mrpa_invalid_length_5));
    // load the doc
    auto mrpa = std::make_unique<xmlpp::DomParser>();
    REQUIRE_NOTHROW(mrpa->parse_file(mrpa_invalid_length_5));
    REQUIRE(mrpa->operator bool());
    // validate
    xmlpp::Document* doc = mrpa->get_document();
    REQUIRE(doc != nullptr);
    // REQUIRE_NOTHROW(validator->validate(doc));
    REQUIRE_THROWS_AS(validator->validate(doc), xmlpp::validity_error);
  }

  SECTION("INVALID6") {
    REQUIRE(std::filesystem::exists(mrpa_invalid_deleted_attr6));
    // load the doc
    auto mrpa = std::make_unique<xmlpp::DomParser>();
    REQUIRE_NOTHROW(mrpa->parse_file(mrpa_invalid_deleted_attr6));
    REQUIRE(mrpa->operator bool());
    // validate
    xmlpp::Document* doc = mrpa->get_document();
    REQUIRE(doc != nullptr);
    // REQUIRE_NOTHROW(validator->validate(doc));
    REQUIRE_THROWS_AS(validator->validate(doc), xmlpp::validity_error);
  }

  SECTION("INVALID7") {
    REQUIRE(std::filesystem::exists(mrpa_invalid_unexpected_attr_7));
    // load the doc
    auto mrpa = std::make_unique<xmlpp::DomParser>();
    REQUIRE_NOTHROW(mrpa->parse_file(mrpa_invalid_unexpected_attr_7));
    REQUIRE(mrpa->operator bool());
    // validate
    xmlpp::Document* doc = mrpa->get_document();
    REQUIRE(doc != nullptr);
    // REQUIRE_NOTHROW(validator->validate(doc));
    REQUIRE_THROWS_AS(validator->validate(doc), xmlpp::validity_error);
  }

  SECTION("INVALID8") {
    REQUIRE(std::filesystem::exists(fn(8)));
    // load the doc
    auto mrpa = std::make_unique<xmlpp::DomParser>();
    REQUIRE_NOTHROW(mrpa->parse_file(fn(8)));
    REQUIRE(mrpa->operator bool());
    // validate
    xmlpp::Document* doc = mrpa->get_document();
    REQUIRE(doc != nullptr);
    // REQUIRE_NOTHROW(validator->validate(doc));
    REQUIRE_THROWS_AS(validator->validate(doc), xmlpp::validity_error);
  }

  SECTION("INVALID9") {
    REQUIRE(std::filesystem::exists(fn(9)));
    // load the doc
    auto mrpa = std::make_unique<xmlpp::DomParser>();
    REQUIRE_NOTHROW(mrpa->parse_file(fn(9)));
    REQUIRE(mrpa->operator bool());
    // validate
    xmlpp::Document* doc = mrpa->get_document();
    REQUIRE(doc != nullptr);
    // REQUIRE_NOTHROW(validator->validate(doc));
    REQUIRE_THROWS_AS(validator->validate(doc), xmlpp::validity_error);
  }

  SECTION("INVALID10") {
    REQUIRE(std::filesystem::exists(fn(10)));
    // load the doc
    auto mrpa = std::make_unique<xmlpp::DomParser>();
    REQUIRE_NOTHROW(mrpa->parse_file(fn(10)));
    REQUIRE(mrpa->operator bool());
    // validate
    xmlpp::Document* doc = mrpa->get_document();
    REQUIRE(doc != nullptr);
    // REQUIRE_NOTHROW(validator->validate(doc));
    REQUIRE_THROWS_AS(validator->validate(doc), xmlpp::validity_error);
  }

  SECTION("INVALID11") {
    REQUIRE(std::filesystem::exists(fn(11)));
    // load the doc
    auto mrpa = std::make_unique<xmlpp::DomParser>();
    REQUIRE_NOTHROW(mrpa->parse_file(fn(11)));
    REQUIRE(mrpa->operator bool());
    // validate
    xmlpp::Document* doc = mrpa->get_document();
    REQUIRE(doc != nullptr);
    // REQUIRE_NOTHROW(validator->validate(doc));
    REQUIRE_THROWS_AS(validator->validate(doc), xmlpp::validity_error);
  }

  SECTION("INVALID12") {
    REQUIRE(std::filesystem::exists(fn(12)));
    // load the doc
    auto mrpa = std::make_unique<xmlpp::DomParser>();
    REQUIRE_NOTHROW(mrpa->parse_file(fn(12)));
    REQUIRE(mrpa->operator bool());
    // validate
    xmlpp::Document* doc = mrpa->get_document();
    REQUIRE(doc != nullptr);
    REQUIRE_NOTHROW(
      validator->validate(doc));  //  optional attribute was deleted
    // REQUIRE_THROWS_AS(validator->validate(doc), xmlpp::validity_error);
  }

  SECTION("INVALID13") {
    REQUIRE(std::filesystem::exists(fn(13)));
    // load the doc
    auto mrpa = std::make_unique<xmlpp::DomParser>();
    REQUIRE_NOTHROW(mrpa->parse_file(fn(13)));
    REQUIRE(mrpa->operator bool());
    // validate
    xmlpp::Document* doc = mrpa->get_document();
    REQUIRE(doc != nullptr);
    // REQUIRE_NOTHROW(validator->validate(doc));
    REQUIRE_THROWS_AS(validator->validate(doc), xmlpp::validity_error);
  }

  SECTION("INVALID14") {
    REQUIRE(std::filesystem::exists(fn(14)));
    // load the doc
    auto mrpa = std::make_unique<xmlpp::DomParser>();
    REQUIRE_NOTHROW(mrpa->parse_file(fn(14)));
    REQUIRE(mrpa->operator bool());
    // validate
    xmlpp::Document* doc = mrpa->get_document();
    REQUIRE(doc != nullptr);
    // REQUIRE_NOTHROW(validator->validate(doc));
    REQUIRE_THROWS_AS(validator->validate(doc), xmlpp::validity_error);
  }

  SECTION("INVALID15") {
    REQUIRE(std::filesystem::exists(fn(15)));
    // load the doc
    auto mrpa = std::make_unique<xmlpp::DomParser>();
    REQUIRE_NOTHROW(mrpa->parse_file(fn(15)));
    REQUIRE(mrpa->operator bool());
    // validate
    xmlpp::Document* doc = mrpa->get_document();
    REQUIRE(doc != nullptr);
    REQUIRE_NOTHROW(validator->validate(doc));  // allowed empty sequence
    // REQUIRE_THROWS_AS(validator->validate(doc), xmlpp::validity_error);
  }

  SECTION("INVALID16") {
    REQUIRE(std::filesystem::exists(fn(16)));
    // load the doc
    auto mrpa = std::make_unique<xmlpp::DomParser>();
    REQUIRE_NOTHROW(mrpa->parse_file(fn(16)));
    REQUIRE(mrpa->operator bool());
    // validate
    xmlpp::Document* doc = mrpa->get_document();
    REQUIRE(doc != nullptr);
    // REQUIRE_NOTHROW(validator->validate(doc));
    REQUIRE_THROWS_AS(validator->validate(doc), xmlpp::validity_error);
  }

  SECTION("INVALID17") {
    REQUIRE(std::filesystem::exists(fn(17)));
    // load the doc
    auto mrpa = std::make_unique<xmlpp::DomParser>();
    REQUIRE_NOTHROW(mrpa->parse_file(fn(17)));
    REQUIRE(mrpa->operator bool());
    // validate
    xmlpp::Document* doc = mrpa->get_document();
    REQUIRE(doc != nullptr);
    REQUIRE_NOTHROW(validator->validate(doc));  // allowed element copy
    // REQUIRE_THROWS_AS(validator->validate(doc), xmlpp::validity_error);
  }

  SECTION("INVALID18") {
    REQUIRE(std::filesystem::exists(fn(18)));
    // load the doc
    auto mrpa = std::make_unique<xmlpp::DomParser>();
    REQUIRE_NOTHROW(mrpa->parse_file(fn(18)));
    REQUIRE(mrpa->operator bool());
    // validate
    xmlpp::Document* doc = mrpa->get_document();
    REQUIRE(doc != nullptr);
    // REQUIRE_NOTHROW(validator->validate(doc));
    REQUIRE_THROWS_AS(validator->validate(doc), xmlpp::validity_error);
  }

  SECTION("INVALID19") {
    REQUIRE(std::filesystem::exists(fn(19)));
    // load the doc
    auto mrpa = std::make_unique<xmlpp::DomParser>();
    REQUIRE_NOTHROW(mrpa->parse_file(fn(19)));
    REQUIRE(mrpa->operator bool());
    // validate
    xmlpp::Document* doc = mrpa->get_document();
    REQUIRE(doc != nullptr);
    // REQUIRE_NOTHROW(validator->validate(doc));
    REQUIRE_THROWS_AS(validator->validate(doc), xmlpp::validity_error);
  }

  SECTION("INVALID20") {
    REQUIRE(std::filesystem::exists(fn(20)));
    // load the doc
    auto mrpa = std::make_unique<xmlpp::DomParser>();
    REQUIRE_NOTHROW(mrpa->parse_file(fn(20)));
    REQUIRE(mrpa->operator bool());
    // validate
    xmlpp::Document* doc = mrpa->get_document();
    REQUIRE(doc != nullptr);
    // REQUIRE_NOTHROW(validator->validate(doc));
    REQUIRE_THROWS_AS(validator->validate(doc), xmlpp::validity_error);
  }

  SECTION("INVALID21") {
    REQUIRE(std::filesystem::exists(fn(21)));
    // load the doc
    auto mrpa = std::make_unique<xmlpp::DomParser>();
    REQUIRE_NOTHROW(mrpa->parse_file(fn(21)));
    REQUIRE(mrpa->operator bool());
    // validate
    xmlpp::Document* doc = mrpa->get_document();
    REQUIRE(doc != nullptr);
    // REQUIRE_NOTHROW(validator->validate(doc));
    REQUIRE_THROWS_AS(validator->validate(doc), xmlpp::validity_error);
  }

  SECTION("INVALID22") {
    REQUIRE(std::filesystem::exists(fn(22)));
    // load the doc
    auto mrpa = std::make_unique<xmlpp::DomParser>();
    REQUIRE_NOTHROW(mrpa->parse_file(fn(22)));
    REQUIRE(mrpa->operator bool());
    // validate
    xmlpp::Document* doc = mrpa->get_document();
    REQUIRE(doc != nullptr);
    // REQUIRE_NOTHROW(validator->validate(doc));
    REQUIRE_THROWS_AS(validator->validate(doc), xmlpp::validity_error);
  }
  SECTION("INVALID23") {
    REQUIRE(std::filesystem::exists(fn(23)));
    // load the doc
    auto mrpa = std::make_unique<xmlpp::DomParser>();
    REQUIRE_NOTHROW(mrpa->parse_file(fn(23)));
    REQUIRE(mrpa->operator bool());
    // validate
    xmlpp::Document* doc = mrpa->get_document();
    REQUIRE(doc != nullptr);
    // REQUIRE_NOTHROW(validator->validate(doc));
    REQUIRE_THROWS_AS(validator->validate(doc), xmlpp::validity_error);
  }

  SECTION("INVALID24") {
    REQUIRE(std::filesystem::exists(fn(24)));
    // load the doc
    auto mrpa = std::make_unique<xmlpp::DomParser>();
    REQUIRE_NOTHROW(mrpa->parse_file(fn(24)));
    REQUIRE(mrpa->operator bool());
    // validate
    xmlpp::Document* doc = mrpa->get_document();
    REQUIRE(doc != nullptr);
    // REQUIRE_NOTHROW(validator->validate(doc));
    REQUIRE_THROWS_AS(validator->validate(doc), xmlpp::validity_error);
  }

  SECTION("INVALID25") {
    REQUIRE(std::filesystem::exists(fn(25)));
    // load the doc
    auto mrpa = std::make_unique<xmlpp::DomParser>();
    REQUIRE_NOTHROW(mrpa->parse_file(fn(25)));
    REQUIRE(mrpa->operator bool());
    // validate
    xmlpp::Document* doc = mrpa->get_document();
    REQUIRE(doc != nullptr);
    // REQUIRE_NOTHROW(validator->validate(doc));
    REQUIRE_THROWS_AS(validator->validate(doc), xmlpp::validity_error);
  }

  SECTION("INVALID26") {
    REQUIRE(std::filesystem::exists(fn(26)));
    // load the doc
    auto mrpa = std::make_unique<xmlpp::DomParser>();
    REQUIRE_NOTHROW(mrpa->parse_file(fn(26)));
    REQUIRE(mrpa->operator bool());
    // validate
    xmlpp::Document* doc = mrpa->get_document();
    REQUIRE(doc != nullptr);
    // REQUIRE_NOTHROW(validator->validate(doc));
    REQUIRE_THROWS_AS(validator->validate(doc), xmlpp::validity_error);
  }

  SECTION("old_schema") {
    REQUIRE(std::filesystem::exists(old_schema));
    // load the doc
    auto mrpa = std::make_unique<xmlpp::DomParser>();
    REQUIRE_NOTHROW(mrpa->parse_file(old_schema));
    REQUIRE(mrpa->operator bool());
    // validate
    xmlpp::Document* doc = mrpa->get_document();
    REQUIRE(doc != nullptr);
    // REQUIRE_NOTHROW(validator->validate(doc));
    REQUIRE_THROWS_AS(validator->validate(doc), xmlpp::validity_error);
  }

  SECTION("VALID2") {
    REQUIRE(std::filesystem::exists(valid2));
    // load the doc
    auto mrpa = std::make_unique<xmlpp::DomParser>();
    REQUIRE_NOTHROW(mrpa->parse_file(valid2));
    REQUIRE(mrpa->operator bool());
    // validate
    xmlpp::Document* doc = mrpa->get_document();
    REQUIRE(doc != nullptr);
    REQUIRE_NOTHROW(validator->validate(doc));
    // REQUIRE_THROWS_AS(validator->validate(doc), xmlpp::validity_error);
  }

  SECTION("VALID3") {
    REQUIRE(std::filesystem::exists(valid3));
    // load the doc
    auto mrpa = std::make_unique<xmlpp::DomParser>();
    REQUIRE_NOTHROW(mrpa->parse_file(valid3));
    REQUIRE(mrpa->operator bool());
    // validate
    xmlpp::Document* doc = mrpa->get_document();
    REQUIRE(doc != nullptr);
    REQUIRE_NOTHROW(validator->validate(doc));
    // REQUIRE_THROWS_AS(validator->validate(doc), xmlpp::validity_error);
  }

  SECTION("VALID4") {
    REQUIRE(std::filesystem::exists(valid4));
    // load the doc
    auto mrpa = std::make_unique<xmlpp::DomParser>();
    REQUIRE_NOTHROW(mrpa->parse_file(valid4));
    REQUIRE(mrpa->operator bool());
    // validate
    xmlpp::Document* doc = mrpa->get_document();
    REQUIRE(doc != nullptr);
    REQUIRE_NOTHROW(validator->validate(doc));
    // REQUIRE_THROWS_AS(validator->validate(doc), xmlpp::validity_error);
  }
  SECTION("VALID5") {
    REQUIRE(std::filesystem::exists(valid5));
    // load the doc
    auto mrpa = std::make_unique<xmlpp::DomParser>();
    REQUIRE_NOTHROW(mrpa->parse_file(valid5));
    REQUIRE(mrpa->operator bool());
    // validate
    xmlpp::Document* doc = mrpa->get_document();
    REQUIRE(doc != nullptr);
    REQUIRE_NOTHROW(validator->validate(doc));
    // REQUIRE_THROWS_AS(validator->validate(doc), xmlpp::validity_error);
  }
  SECTION("VALID6") {
    REQUIRE(std::filesystem::exists(valid6));
    // load the doc
    auto mrpa = std::make_unique<xmlpp::DomParser>();
    REQUIRE_NOTHROW(mrpa->parse_file(valid6));
    REQUIRE(mrpa->operator bool());
    // validate
    xmlpp::Document* doc = mrpa->get_document();
    REQUIRE(doc != nullptr);
    REQUIRE_NOTHROW(validator->validate(doc));
    // REQUIRE_THROWS_AS(validator->validate(doc), xmlpp::validity_error);
  }
  SECTION("VALID7") {
    REQUIRE(std::filesystem::exists(valid7));
    // load the doc
    auto mrpa = std::make_unique<xmlpp::DomParser>();
    REQUIRE_NOTHROW(mrpa->parse_file(valid7));
    REQUIRE(mrpa->operator bool());
    // validate
    xmlpp::Document* doc = mrpa->get_document();
    REQUIRE(doc != nullptr);
    REQUIRE_NOTHROW(validator->validate(doc));
    // REQUIRE_THROWS_AS(validator->validate(doc), xmlpp::validity_error);
  }
}

TEST_CASE("LoadEmbeddedXSD") {
  REQUIRE(mrpa::xsd1.size() > 0);
  const std::string xsd(mrpa::xsd1.cbegin(), mrpa::xsd1.cend());
  auto schema_xml = std::make_unique<xmlpp::DomParser>();
  // REQUIRE_NOTHROW(schema_xml->parse_memory_raw(mrpa::xsd1, mrpa::xsd_len));
  auto schema = std::make_unique<xmlpp::XsdSchema>();
  REQUIRE_NOTHROW(schema->parse_memory(xsd));
  REQUIRE(schema);
  REQUIRE(std::filesystem::exists(valid7));
  auto mrpa = std::make_unique<xmlpp::DomParser>();
  REQUIRE_NOTHROW(mrpa->parse_file(valid7));
  auto validator = std::make_unique<xmlpp::XsdValidator>();
  REQUIRE_NOTHROW(validator->set_schema(schema.get(), false));
  REQUIRE(validator);

  REQUIRE(mrpa->operator bool());
  xmlpp::Document* doc = mrpa->get_document();
  REQUIRE(doc != nullptr);
  REQUIRE_NOTHROW(validator->validate(doc));
}

TEST_CASE("MrpaClass") {
  SECTION("Basic") {
    REQUIRE_FALSE(mrpa::Mrpa("").IsValid());
    REQUIRE(std::filesystem::exists(fn(26)));
    REQUIRE_NOTHROW(mrpa::Mrpa(fn(26)));
    REQUIRE_FALSE(mrpa::Mrpa(fn(26)).IsValid());
    std::unique_ptr<mrpa::Mrpa> mrpa;
    REQUIRE_NOTHROW(mrpa = std::make_unique<mrpa::Mrpa>(valid4));
    REQUIRE(mrpa->IsValid());
    REQUIRE_NOTHROW(mrpa = std::make_unique<mrpa::Mrpa>(valid3));
    REQUIRE(mrpa->IsValid());
  }

  SECTION("InvalidName") {
    std::unique_ptr<mrpa::Mrpa> mrpa;
    REQUIRE(std::filesystem::exists(invalid29));
    REQUIRE_NOTHROW(mrpa = std::make_unique<mrpa::Mrpa>(invalid29));
    REQUIRE_FALSE(mrpa->IsValid());
    REQUIRE(std::filesystem::exists(invalid30));
    REQUIRE_NOTHROW(mrpa = std::make_unique<mrpa::Mrpa>(invalid30));
    REQUIRE_FALSE(mrpa->IsValid());
    REQUIRE(std::filesystem::exists(invalid31));
    REQUIRE_NOTHROW(mrpa = std::make_unique<mrpa::Mrpa>(invalid31));
    REQUIRE_FALSE(mrpa->IsValid());
  }

  SECTION("InvalidFlags") {
    std::unique_ptr<mrpa::Mrpa> mrpa;
    REQUIRE(std::filesystem::exists(invalid27));
    REQUIRE_NOTHROW(mrpa = std::make_unique<mrpa::Mrpa>(invalid27));
    REQUIRE_FALSE(mrpa->IsValid());
    REQUIRE(std::filesystem::exists(invalid28));
    REQUIRE_NOTHROW(mrpa = std::make_unique<mrpa::Mrpa>(invalid28));
    REQUIRE_FALSE(mrpa->IsValid());
  }

  SECTION("InvalidHeader") {
    std::unique_ptr<mrpa::Mrpa> mrpa;
    REQUIRE(std::filesystem::exists(invalid34));
    REQUIRE_NOTHROW(mrpa = std::make_unique<mrpa::Mrpa>(invalid34));
    REQUIRE_FALSE(mrpa->IsValid());
    REQUIRE_NOTHROW(mrpa = std::make_unique<mrpa::Mrpa>("non existing"));
    REQUIRE_FALSE(mrpa->IsValid());
  }
}

TEST_CASE("GetMRPAGuid") {
  REQUIRE_FALSE(mrpa::utils::GetMRPAGuid(nullptr));
  auto mrpa = std::make_unique<xmlpp::DomParser>();
  REQUIRE_NOTHROW(mrpa->parse_file(mrpa_deleted_el1));
  REQUIRE_FALSE(mrpa::utils::GetMRPAGuid(mrpa->get_document()));
  REQUIRE_NOTHROW(mrpa->parse_file(mrpa_deleted_el2));
  REQUIRE_FALSE(mrpa::utils::GetMRPAGuid(mrpa->get_document()));
  REQUIRE_NOTHROW(mrpa->parse_file(mrpa_deleted_el3));
  REQUIRE_FALSE(mrpa::utils::GetMRPAGuid(mrpa->get_document()));
  REQUIRE_NOTHROW(mrpa->parse_file(fn(32)));
  REQUIRE_FALSE(mrpa::utils::GetMRPAGuid(mrpa->get_document()).has_value());
  REQUIRE_THROWS(mrpa->parse_file(fn(33)));
}

TEST_CASE("XMLtoJSON") {
  SECTION("1") {
    auto mrpa = std::make_unique<xmlpp::DomParser>();
    REQUIRE_NOTHROW(mrpa->parse_file(valid7));
    auto* doc = mrpa->get_document();
    REQUIRE(doc != nullptr);
    std::optional<std::string> res = mrpa::utils::XmlToJson(nullptr);
    REQUIRE_FALSE(res.has_value());
    res = mrpa::utils::XmlToJson(doc);
    REQUIRE(res.has_value());
    std::cout << res.value() << "\n\n";
  }
  std::cout << "\n\n";
  SECTION("2") {
    auto mrpa = std::make_unique<xmlpp::DomParser>();
    REQUIRE_NOTHROW(mrpa->parse_file(valid4));
    auto* doc = mrpa->get_document();
    REQUIRE(doc != nullptr);
    std::optional<std::string> res = mrpa::utils::XmlToJson(nullptr);
    REQUIRE_FALSE(res.has_value());
    res = mrpa::utils::XmlToJson(doc);
    REQUIRE(res.has_value());
    std::cout << res.value() << "\n\n";
  }

  SECTION("Default constructed") {
    mrpa::Mrpa mrpa;
    REQUIRE_FALSE(mrpa.IsValid());
    REQUIRE_FALSE(mrpa.toJson().has_value());
  }

  SECTION("Valid") {
    mrpa::Mrpa mrpa(valid3);
    REQUIRE(mrpa.IsValid());
    REQUIRE(mrpa.toJson().has_value());
  }
}

TEST_CASE("XML_Bomb") {
  auto mrpa = std::make_unique<xmlpp::DomParser>();
  REQUIRE_THROWS(mrpa->parse_file(xml_bomb));
}

TEST_CASE("HugeNestingLevel") {
  xmlpp::Document doc("1.0");
  xmlpp::Element* root = doc.create_root_node("root");
  xmlpp::Element* current = root;
  for (int i = 1; i <= 101; ++i) {
    xmlpp::Element* child =
      current->add_child_element("level" + std::to_string(i));
    current = child;
  }
  // Save the document to a file
  const std::string target_file =
    std::string(TEST_DIR) + "nested_101_levels.xml";
  doc.write_to_file_formatted(target_file);
  REQUIRE(std::filesystem::exists(target_file));
  std::cout << "XML with 101 nested levels created successfully.\n";
  auto mrpa = std::make_unique<xmlpp::DomParser>();
  REQUIRE_NOTHROW(mrpa->parse_file(target_file));
  auto json_val = mrpa::utils::XmlToJson(mrpa->get_document());
  REQUIRE_FALSE(json_val.has_value());
}

TEST_CASE("TestSigIfAttached") {
  SECTION("Detached") {
    REQUIRE(std::filesystem::exists(mrpa1_sig));
    pdfcsp::c_bridge::SeparateSignatureParams cparams{};
    cparams.sig_file_path = mrpa1_sig.c_str();
    cparams.sig_file_path_size = mrpa1_sig.size();
    REQUIRE_FALSE(IsMessageAttached(&cparams) == 1);
  }

  SECTION("Attached") {
    REQUIRE(std::filesystem::exists(sig_attached1));
    pdfcsp::c_bridge::SeparateSignatureParams cparams{};
    cparams.sig_file_path = sig_attached1.c_str();
    cparams.sig_file_path_size = sig_attached1.size();
    REQUIRE(IsMessageAttached(&cparams) == 1);
  }

  SECTION("Attached") {
    REQUIRE(std::filesystem::exists(sig_detached2));
    pdfcsp::c_bridge::SeparateSignatureParams cparams{};
    cparams.sig_file_path = sig_detached2.c_str();
    cparams.sig_file_path_size = sig_detached2.size();
    REQUIRE_FALSE(IsMessageAttached(&cparams) == 1);
  }

  SECTION("NotASignature") {
    REQUIRE(std::filesystem::exists(mrpa_scheme));
    pdfcsp::c_bridge::SeparateSignatureParams cparams{};
    cparams.sig_file_path = mrpa_scheme.c_str();
    cparams.sig_file_path_size = mrpa_scheme.size();
    REQUIRE_FALSE(IsMessageAttached(&cparams) == 1);
    REQUIRE(pdfcsp::c_bridge::IsMessageAttached(&cparams) == -1);
  }
}

TEST_CASE("MRPA_sig") {
  SECTION("empty_sig_name") {
    REQUIRE(std::filesystem::exists(valid3));
    std::unique_ptr<mrpa::Mrpa> mrpa;
    REQUIRE_NOTHROW(mrpa = std::make_unique<mrpa::Mrpa>(valid3));
    REQUIRE(mrpa->IsValid());
    REQUIRE_NOTHROW(mrpa->setSignature(""));
    REQUIRE_FALSE(mrpa->IsValidSignature());
  }

  SECTION("non_existing_sig_file") {
    REQUIRE(std::filesystem::exists(valid3));
    REQUIRE_FALSE(std::filesystem::exists("blabla"));
    std::unique_ptr<mrpa::Mrpa> mrpa;
    REQUIRE_NOTHROW(mrpa = std::make_unique<mrpa::Mrpa>(valid3));
    REQUIRE(mrpa->IsValid());
    REQUIRE_NOTHROW(mrpa->setSignature("blabla"));
    REQUIRE_FALSE(mrpa->IsValidSignature());
  }

  SECTION("attached_sig_name") {
    REQUIRE(std::filesystem::exists(valid3));
    REQUIRE(std::filesystem::exists(sig_attached3));
    std::unique_ptr<mrpa::Mrpa> mrpa;
    REQUIRE_NOTHROW(mrpa = std::make_unique<mrpa::Mrpa>(valid3));
    REQUIRE(mrpa->IsValid());
    REQUIRE_NOTHROW(mrpa->setSignature(sig_attached3));
    REQUIRE_FALSE(mrpa->IsValidSignature());
  }

  SECTION("Revoked_T") {
    REQUIRE(std::filesystem::exists(valid3));
    REQUIRE(std::filesystem::exists(mrpa1_sig));
    std::unique_ptr<mrpa::Mrpa> mrpa;
    REQUIRE_NOTHROW(mrpa = std::make_unique<mrpa::Mrpa>(valid3));
    REQUIRE(mrpa->IsValid());
    REQUIRE_NOTHROW(mrpa->setSignature(mrpa1_sig));
    REQUIRE_FALSE(mrpa->IsValidSignature());
  }

  SECTION("NoMRPA") {
    REQUIRE(std::filesystem::exists(mrpa1_sig));
    std::unique_ptr<mrpa::Mrpa> mrpa;
    REQUIRE_NOTHROW(mrpa = std::make_unique<mrpa::Mrpa>());
    REQUIRE_NOTHROW(mrpa->setSignature(mrpa1_sig));
    REQUIRE_FALSE(mrpa->IsValidSignature());
  }

#ifndef SKIP_SENSITIVE_DATA
  SECTION("Basic") {
    const std::string sig_path =
      test_files_dir +
      "sensitive/"
      "ON_EMCHD_20241210_5fd0cfce-3587-4b00-8501-1a6aebcacda9.sig";
    const std::string src_path =
      test_files_dir +
      "sensitive/"
      "ON_EMCHD_20241210_5fd0cfce-3587-4b00-8501-1a6aebcacda9.xml";
    if (std::filesystem::exists(sig_path) &&
        std::filesystem::exists(src_path)) {
      std::unique_ptr<mrpa::Mrpa> mrpa;
      REQUIRE_NOTHROW(mrpa = std::make_unique<mrpa::Mrpa>(src_path));
      REQUIRE(mrpa->IsValid());
      REQUIRE_NOTHROW(mrpa->setSignature(sig_path));
      REQUIRE_FALSE(mrpa->IsValidSignature());
    }
  }
#endif
}

TEST_CASE("NonReadable") {
  SECTION("NotReadableSig") {
    const std::string dst = std::string(TEST_DIR) + "non_readable.sig";
    std::ofstream file(dst, std::ios_base::binary);
    file.open(dst);
    file.close();
    REQUIRE(std::filesystem::exists(dst));
    std::filesystem::permissions(dst, std::filesystem::perms::owner_write);
    std::unique_ptr<mrpa::Mrpa> mrpa;
    REQUIRE_NOTHROW(mrpa = std::make_unique<mrpa::Mrpa>(valid3));
    REQUIRE_NOTHROW(mrpa->setSignature(dst));
    REQUIRE_FALSE(mrpa->IsValidSignature());
    REQUIRE(std::filesystem::remove(dst));
  }
  SECTION("NotReadableXML") {
    const std::string dst = std::string(TEST_DIR) + "non_readable.xml";
    std::ofstream file(dst, std::ios_base::binary);
    file.open(dst);
    file.close();
    REQUIRE(std::filesystem::exists(dst));
    std::filesystem::permissions(dst, std::filesystem::perms::owner_write);
    std::unique_ptr<mrpa::Mrpa> mrpa;
    REQUIRE_NOTHROW(mrpa = std::make_unique<mrpa::Mrpa>(dst));
    REQUIRE_FALSE(mrpa->IsValid());
    REQUIRE(std::filesystem::remove(dst));
  }
}

TEST_CASE("signersCertJson") {
  const std::string test_json =
    R"([{"trust_status":true,"certs":[{"version":2,"serial":"02db56c90080b1749545ff87d1f452dcd5","issuer":"ОРГН=1047707030513, ИНН=7707329152, STREET=ул. Неглинная, д. 23, C=RU, S=77 Москва, L=г. Москва, O=Федеральная налоговая служба, CN=Федеральная налоговая служба","issuer_common_name":"Федеральная налоговая служба","subject":"ОРГН=1117777777777, ИНН=123456789101, STREET=ул БАГРАТИОНОВСКАЯ, Д.1, К.12, ПОМ.33, C=RU, S=77 г. Москва, L=Г.МОСКВА, O=ООО \"ВСЕФИЛЬТРЫ.РУ\", CN=ООО \"ВСЕФИЛЬТРЫ.РУ\", SNILS=07777777777","subject_common_name":"ООО \"ВСЕФИЛЬТРЫ.РУ\"","not_before":1717070583,"not_before_readable":"2024-05-30 12:03:03 UTC","not_after":1756555983,"not_after_readable":"2025-08-30 12:13:03 UTC","key_usage":"1111","trust_status":true,"subject_dname":{"surname":"Бахрудинов","givenName":"Кирилл Петрович","countryName":"RU","commonName":"ООО \"ВСЕФИЛЬТРЫ.РУ\"","localityName":"Г.МОСКВА","stateOrProvinceName":"77 г. Москва","streetAddress":"ул БАГРАТИОНОВСКАЯ, Д.1, К.12, ПОМ.33","organizationName":"ООО \"ВСЕФИЛЬТРЫ.РУ\"","title":"ГЕНЕРАЛЬНЫЙ ДИРЕКТОР","emailAddress":"test@test.ru","inn":"123456789101","ogrn":"1117777777777","snils":"07777777777"}},{"version":2,"serial":"4268c57a000000000833","issuer":"ОРГН=1047702026701, ИНН=7710474375, STREET=Пресненская набережная, дом 10, строение 2, C=RU, S=77 Москва, L=г. Москва, O=Минцифры России, CN=Минцифры России","issuer_common_name":"Минцифры России","subject":"ОРГН=1047707030513, ИНН=7707329152, STREET=ул. Неглинная, д. 23, C=RU, S=77 Москва, L=г. Москва, O=Федеральная налоговая служба, CN=Федеральная налоговая служба","subject_common_name":"Федеральная налоговая служба","not_before":1689945164,"not_before_readable":"2023-07-21 13:12:44 UTC","not_after":2163330764,"not_after_readable":"2038-07-21 13:12:44 UTC","key_usage":"1000011","trust_status":true,"subject_dname":{"countryName":"RU","commonName":"Федеральная налоговая служба","localityName":"г. Москва","stateOrProvinceName":"77 Москва","streetAddress":"ул. Неглинная, д. 23","organizationName":"Федеральная налоговая служба","emailAddress":"uc@tax.gov.ru","inn":"7707329152","ogrn":"1047707030513"}},{"version":2,"serial":"00951fa3477c61043aadfa858627823442","issuer":"ОРГН=1047702026701, ИНН=7710474375, STREET=Пресненская набережная, дом 10, строение 2, C=RU, S=77 Москва, L=г. Москва, O=Минцифры России, CN=Минцифры России","issuer_common_name":"Минцифры России","subject":"ОРГН=1047702026701, ИНН=7710474375, STREET=Пресненская набережная, дом 10, строение 2, C=RU, S=77 Москва, L=г. Москва, O=Минцифры России, CN=Минцифры России","subject_common_name":"Минцифры России","not_before":1641648759,"not_before_readable":"2022-01-08 13:32:39 UTC","not_after":2209642359,"not_after_readable":"2040-01-08 13:32:39 UTC","key_usage":"0000011","trust_status":true,"subject_dname":{"countryName":"RU","commonName":"Минцифры России","localityName":"г. Москва","stateOrProvinceName":"77 Москва","streetAddress":"Пресненская набережная, дом 10, строение 2","organizationName":"Минцифры России","emailAddress":"dit@digital.gov.ru","inn":"7710474375","ogrn":"1047702026701"}}]}])";

  SECTION("Normal") {
    const auto res1 = mrpa::utils::SignersCertJson(
      test_json, "02db56c90080b1749545ff87d1f452dcd5");
    REQUIRE(res1.has_value());
  }

  SECTION("Not found") {
    const auto res1 = mrpa::utils::SignersCertJson(
      test_json, "22db56c90080b1749545ff87d1f452dcd5");
    REQUIRE_FALSE(res1.has_value());
  }

  SECTION("Invalid JSON") {
    const auto res1 = mrpa::utils::SignersCertJson(
      "blabla", "02db56c90080b1749545ff87d1f452dcd5");
    REQUIRE_FALSE(res1.has_value());
  }
  SECTION("Empty JSON object") {
    const auto res1 =
      mrpa::utils::SignersCertJson("{}", "02db56c90080b1749545ff87d1f452dcd5");
    REQUIRE_FALSE(res1.has_value());
  }
  SECTION("Empty chain") {
    const auto res1 = mrpa::utils::SignersCertJson(
      "[{}]", "02db56c90080b1749545ff87d1f452dcd5");
    REQUIRE_FALSE(res1.has_value());
  }
  SECTION("invalid certs field") {
    const auto res1 = mrpa::utils::SignersCertJson(
      R"([{"certs":"no_certs"}])", "02db56c90080b1749545ff87d1f452dcd5");
    REQUIRE_FALSE(res1.has_value());
  }
  SECTION("cert is not an object") {
    const auto res1 = mrpa::utils::SignersCertJson(
      R"([{ "certs":[[]] } ] )", "02db56c90080b1749545ff87d1f452dcd5");
    REQUIRE_FALSE(res1.has_value());
  }
  SECTION("no serial") {
    const auto res1 = mrpa::utils::SignersCertJson(
      R"([{"certs":[{}]}])", "02db56c90080b1749545ff87d1f452dcd5");
    REQUIRE_FALSE(res1.has_value());
  }
  SECTION("serial is not a string") {
    const auto res1 = mrpa::utils::SignersCertJson(
      R"([{"certs":[{"serial":[]}]}])", "02db56c90080b1749545ff87d1f452dcd5");
    REQUIRE_FALSE(res1.has_value());
  }
}

TEST_CASE("GrantorUtils") {
  // SECTION("1") {
  //   const std::string mrpa1_file =
  //     test_files_dir +
  //     "sintetic/"
  //     "no_person_id_doc_numner_ON_EMCHD_20241203_c61a40df-d38f-4800-9ba4-"
  //     "61a2df016993.xml";
  //   mrpa::Mrpa mrpa1(mrpa1_file);
  //   REQUIRE_FALSE(mrpa1.IsValid());
  // }

  SECTION("ValidBasic") {
    mrpa::Mrpa mrpa1{valid3};
    REQUIRE(mrpa1.IsValid());
    const auto& grantor = mrpa1.getGrantor();
    REQUIRE(grantor.has_value());
    constexpr const char* expceted =
      R"({"type":"Company","company_name":"ОБЩЕСТВО С ОГРАНИЧЕННОЙ ОТВЕТСТВЕННОСТЬЮ \"БАЗАЛЬТ СВОБОДНОЕ ПРОГРАММНОЕ ОБЕСПЕЧЕНИЕ\"","inn_le":"7714350892","kpp":"771401001","ogrn":"1157746734837","reg_address":{"region":"77","address":"127015, Г.МОСКВА, УЛ. БУТЫРСКАЯ, Д. 75, ОФИС 307"},"persons":[{"last_name":"ПРАВДИН","name":"СЕРБЕК","patronymic":"ИВАНОВИЧ","inn_person":"590411005641","snils_person":"041-855-494 65","duty":"ГЕНЕРАЛЬНЫЙ ДИРЕКТОР"}],"all_persons":[{"last_name":"ПРАВДИН","name":"СЕРБЕК","patronymic":"ИВАНОВИЧ","inn_person":"590411005641","snils_person":"041-855-494 65","duty":"ГЕНЕРАЛЬНЫЙ ДИРЕКТОР"}]})";
    REQUIRE(boost::json::serialize(grantor->ToJson()) == expceted);
    constexpr const char* expected_repr =
      R"({"last_name":"ЛАМИМОВА","name":"АННА","patronymic":"СЕРГЕЕВНА","birth_date":"1978-07-12","personal_id_doc":{"doc_number":"45 23 707774","date_issued":"2023-08-30","issuer":"ГУ МВД России по г. Бишкек","issuer_id":"770-101"},"inn_person":"510103034646","snils_person":"052-951-639 83"})";
    REQUIRE(boost::json::serialize(mrpa1.getRepresentatives().at(0).ToJson()) ==
            expected_repr);
    // std::cout << "\n\n";
  }

  SECTION("fias_address_and_id_male_person") {
    const std::string mrpa2_file = test_files_dir +
                                   "sintetic/"
                                   "plus_fies_addr_ON_EMCHD_20241203_c61a40df-"
                                   "d38f-4800-9ba4-61a2df016993.xml";
    REQUIRE(std::filesystem::exists(mrpa2_file));
    mrpa::Mrpa mrpa2(mrpa2_file);
    REQUIRE(mrpa2.IsValid());
    const auto& grantor = mrpa2.getGrantor();
    REQUIRE(grantor->all_persons.size() == 1);
    REQUIRE(grantor->all_persons.at(0).sex == mrpa::Sex::kMale);
    REQUIRE(grantor->reg_address.has_value());
    REQUIRE(grantor->reg_address->fias_address.value() ==
            "127015, Г.МОСКВА, УЛ. БУТЫРСКАЯ, Д. 75, ОФИС 307");
    // std::cout << boost::json::serialize(grantor->ToJson());
  }

  SECTION("female") {
    const std::string mrpa2_file = test_files_dir +
                                   "sintetic/"
                                   "plus_fies_addr_female_ON_EMCHD_20241203_"
                                   "c61a40df-d38f-4800-9ba4-61a2df016993.xml";
    REQUIRE(std::filesystem::exists(mrpa2_file));
    mrpa::Mrpa mrpa2(mrpa2_file);
    REQUIRE(mrpa2.IsValid());
    const auto& grantor = mrpa2.getGrantor();
    REQUIRE(grantor->all_persons.size() == 1);
    REQUIRE(grantor->all_persons.at(0).sex == mrpa::Sex::kFemale);
  }

  SECTION("sitizenRu") {
    const std::string mrpa2_file =
      test_files_dir +
      "sintetic/"
      "citizenRU_ON_EMCHD_20241203_c61a40df-d38f-4800-9ba4-61a2df016993.xml";
    REQUIRE(std::filesystem::exists(mrpa2_file));
    mrpa::Mrpa mrpa2(mrpa2_file);
    REQUIRE(mrpa2.IsValid());
    const auto& grantor = mrpa2.getGrantor();
    REQUIRE(grantor->all_persons.size() == 1);
    REQUIRE(grantor->all_persons.at(0).citizenship ==
            mrpa::Citizenship::kRussia);
  }

  SECTION("citizenForeign") {
    const std::string mrpa2_file = test_files_dir +
                                   "sintetic/"
                                   "citizenForeign_ON_EMCHD_20241203_c61a40df-"
                                   "d38f-4800-9ba4-61a2df016993.xml";
    REQUIRE(std::filesystem::exists(mrpa2_file));
    mrpa::Mrpa mrpa2(mrpa2_file);
    REQUIRE(mrpa2.IsValid());
    const auto& grantor = mrpa2.getGrantor();
    REQUIRE(grantor->all_persons.size() == 1);
    REQUIRE(grantor->all_persons.at(0).citizenship ==
            mrpa::Citizenship::kForeign);
    REQUIRE(grantor->all_persons.at(0).ToJson().at("citizenship") == "Foreign");
  }

  SECTION("citizenNo") {
    const std::string mrpa2_file =
      test_files_dir +
      "sintetic/"
      "citizenNoCit_ON_EMCHD_20241203_c61a40df-d38f-4800-9ba4-61a2df016993.xml";
    REQUIRE(std::filesystem::exists(mrpa2_file));
    mrpa::Mrpa mrpa2(mrpa2_file);
    REQUIRE(mrpa2.IsValid());
    const auto& grantor = mrpa2.getGrantor();
    REQUIRE(grantor->all_persons.size() == 1);
    REQUIRE(grantor->all_persons.at(0).citizenship ==
            mrpa::Citizenship::kNoCitizenship);
    REQUIRE(grantor->all_persons.at(0).ToJson().at("citizenship").as_string() ==
            "NoCitizenShip");
  }

  SECTION("egrn_person") {
    const std::string mrpa2_file =
      test_files_dir +
      "sintetic/"
      "egrn_person_ON_EMCHD_20241203_c61a40df-d38f-4800-9ba4-61a2df016993.xml";
    REQUIRE(std::filesystem::exists(mrpa2_file));
    mrpa::Mrpa mrpa2(mrpa2_file);
    REQUIRE(mrpa2.IsValid());
    const auto& grantor = mrpa2.getGrantor();
    REQUIRE(grantor->all_persons.size() == 1);
    REQUIRE(grantor->all_persons.at(0).egrn.has_value());
    REQUIRE(grantor->all_persons.at(0).egrn.value() == "111111111111");
    std::cout << boost::json::serialize(grantor->all_persons.at(0).ToJson())
              << "\n";
    REQUIRE(grantor->all_persons.at(0).ToJson().at("sex").as_string() ==
            "Female");
    REQUIRE(grantor->reg_address->ToJson().at("fias_address") ==
            "127015, Г.МОСКВА, УЛ. БУТЫРСКАЯ, Д. 75, ОФИС 307");
  }

  SECTION("egrn_person") {
    const std::string mrpa2_file =
      test_files_dir +
      "sintetic/"
      "egrn_person_ON_EMCHD_20241203_c61a40df-d38f-4800-9ba4-61a2df016993.xml";
    REQUIRE(std::filesystem::exists(mrpa2_file));
    mrpa::Mrpa mrpa2(mrpa2_file);
    REQUIRE(mrpa2.IsValid());
    const auto& grantor = mrpa2.getGrantor();
    REQUIRE(grantor->all_persons.size() == 1);
    REQUIRE(grantor->all_persons.at(0).egrn.has_value());
    REQUIRE(grantor->all_persons.at(0).egrn.value() == "111111111111");
  }
  SECTION("male") {
    const std::string mrpa2_file = test_files_dir +
                                   "sintetic/"
                                   "plus_fies_addr_ON_EMCHD_20241203_c61a40df-"
                                   "d38f-4800-9ba4-61a2df016993.xml";
    REQUIRE(std::filesystem::exists(mrpa2_file));
    mrpa::Mrpa mrpa2(mrpa2_file);
    REQUIRE(mrpa2.IsValid());
    const auto& grantor = mrpa2.getGrantor();
    REQUIRE(grantor->all_persons.size() == 1);
    REQUIRE(grantor->all_persons.at(0).ToJson().at("sex").as_string() ==
            "Male");
  }

  SECTION("person_info") {
    const std::string mrpa2_file =
      test_files_dir +
      "sintetic/"
      "egrn_person_ON_EMCHD_20241203_c61a40df-d38f-4800-9ba4-61a2df016993.xml";
    REQUIRE(std::filesystem::exists(mrpa2_file));
    mrpa::Mrpa mrpa2(mrpa2_file);
    REQUIRE(mrpa2.IsValid());
    const auto& grantor = mrpa2.getGrantor();
    REQUIRE(grantor->all_persons.size() == 1);
    const auto& person = grantor->all_persons[0];
    REQUIRE(person.birth_place);
    REQUIRE(person.birth_place.value() == "Бишкек");
    REQUIRE(person.citizenship_country.value() == "123");
    REQUIRE(person.phone.value() == "123456789");
    REQUIRE(person.email.value() == "a@a.aa");
    REQUIRE(person.address->region == "77");
    REQUIRE(
      boost::json::serialize(person.authority_confirmation_doc->ToJson()) ==
      R"({"doc_name":"НаимДок","date_issued":"2020-11-11","issuer":"КемВыдКемВыдКемВыд","doc_info":"СвУдДокСвУдДокСвУдДок"})");

    REQUIRE(person.member_status.value() == "101");
    REQUIRE(mrpa2.getRepresentatives().at(0).birth_date.value() ==
            "1978-07-12");
    REQUIRE(grantor->incorp_doc.value() == "НаимУчрДок123");
    REQUIRE(grantor->department_reg_number.value() == "РегНомер1");
    REQUIRE(grantor->phone.value() == "12345667");
    REQUIRE(grantor->email.value() == "a@a.ra");
    REQUIRE(grantor->notarial_status.value() == "101");
    REQUIRE(
      boost::json::serialize(grantor->authority_confirmation_doc->ToJson()) ==
      R"({"doc_name":"НаимДок","date_issued":"2020-11-11","issuer":"КемВыдКемВыдКемВыд","doc_info":"СвУдДокСвУдДокСвУдДок"})");
  }

  SECTION("no_person") {
    const std::string mrpa2_file = test_files_dir +
                                   "sintetic/"
                                   "egrn_no_person_ON_EMCHD_20241203_c61a40df-"
                                   "d38f-4800-9ba4-61a2df016993.xml";
    REQUIRE(std::filesystem::exists(mrpa2_file));
    mrpa::Mrpa mrpa2(mrpa2_file);
    REQUIRE(mrpa2.IsValid());
    REQUIRE(mrpa2.getGrantor()->all_persons.empty());
  }

  SECTION("many_persons") {
    const std::string mrpa2_file = test_files_dir +
                                   "sintetic/"
                                   "egrn_many_person_ON_EMCHD_20241203_"
                                   "c61a40df-d38f-4800-9ba4-61a2df016993.xml";
    REQUIRE(std::filesystem::exists(mrpa2_file));
    mrpa::Mrpa mrpa2(mrpa2_file);
    REQUIRE_FALSE(mrpa2.IsValid());
  }

  SECTION("Two_entities") {
    const std::string mrpa2_file =
      test_files_dir +
      "sintetic/"
      "two_entities_ON_EMCHD_20241203_c61a40df-d38f-4800-9ba4-61a2df016993.xml";
    REQUIRE(std::filesystem::exists(mrpa2_file));
    mrpa::Mrpa mrpa2(mrpa2_file);
    REQUIRE(mrpa2.IsValid());
    REQUIRE(mrpa2.getGrantor().has_value());
    const auto& grantor = mrpa2.getGrantor();
    REQUIRE(grantor->all_persons.size() == 2);
  }
}

TEST_CASE("Foreign") {
  SECTION("foreign_company") {
    const std::string mrpa2_file =
      test_files_dir +
      "sintetic/"
      "foreign_comp_ON_EMCHD_20241203_c61a40df-d38f-4800-9ba4-61a2df016993.xml";
    REQUIRE(std::filesystem::exists(mrpa2_file));
    mrpa::Mrpa mrpa2(mrpa2_file);
    REQUIRE(mrpa2.IsValid());
    REQUIRE(mrpa2.getGrantor().has_value());
    const auto& grantor = mrpa2.getGrantor();
    REQUIRE(grantor->all_persons.size() == 1);
    REQUIRE(ToString(grantor->type) == "ForeignCompany");
    REQUIRE(mrpa::ToString(mrpa::GrantorType::kUnknown) == "Unknown");
  }
}

TEST_CASE("IP") {
  SECTION("ip") {
    const std::string mrpa2_file =
      test_files_dir +
      "sintetic/"
      "ip_ON_EMCHD_20241203_c61a40df-d38f-4800-9ba4-61a2df016993.xml";
    REQUIRE(std::filesystem::exists(mrpa2_file));
    mrpa::Mrpa mrpa2(mrpa2_file);
    REQUIRE(mrpa2.IsValid());
    REQUIRE(mrpa2.getGrantor().has_value());
    const auto& grantor = mrpa2.getGrantor();
    REQUIRE(grantor->all_persons.size() == 1);
    REQUIRE(grantor->ToJson().at("ip_name") == "НаименованиеИП");
    REQUIRE(mrpa2.getRepresentatives().at(0).ToJson().at("snils_person") ==
            "052-951-639 83");
  }
}

TEST_CASE("executive_comp") {
  SECTION("executive_comp") {
    const std::string mrpa2_file = test_files_dir +
                                   "sintetic/"
                                   "executive_company_ON_EMCHD_20241203_"
                                   "c61a40df-d38f-4800-9ba4-61a2df016993.xml";
    REQUIRE(std::filesystem::exists(mrpa2_file));
    mrpa::Mrpa mrpa2(mrpa2_file);
    REQUIRE(mrpa2.IsValid());
    REQUIRE(mrpa2.getGrantor().has_value());
    const auto& grantor = mrpa2.getGrantor();
    REQUIRE(grantor->all_persons.size() == 1);
    REQUIRE_FALSE(
      grantor->ToJson().at("executive_companies").as_array().empty());
  }

  SECTION("two_executive_comp") {
    const std::string mrpa2_file = test_files_dir +
                                   "sintetic/"
                                   "two_executive_companies_ON_EMCHD_20241203_"
                                   "c61a40df-d38f-4800-9ba4-61a2df016993.xml";
    REQUIRE(std::filesystem::exists(mrpa2_file));
    mrpa::Mrpa mrpa2(mrpa2_file);
    REQUIRE(mrpa2.IsValid());
    REQUIRE(mrpa2.getGrantor().has_value());
    const auto& grantor = mrpa2.getGrantor();
    REQUIRE(grantor->all_persons.size() == 2);
  }

  SECTION("no_executive_comp") {
    const std::string mrpa2_file =
      test_files_dir +
      "sintetic/"
      "no_executive_companies_ON_EMCHD_20241203_c61a40df-d38f-4800-9ba4-"
      "61a2df016993.xml";
    REQUIRE(std::filesystem::exists(mrpa2_file));
    mrpa::Mrpa mrpa2(mrpa2_file);
    REQUIRE(mrpa2.IsValid());
    REQUIRE(mrpa2.getGrantor().has_value());
    const auto& grantor = mrpa2.getGrantor();
    REQUIRE(grantor->all_persons.size() == 0);
  }
}

TEST_CASE("Executive_ip") {
  SECTION("one_ip") {
    const std::string mrpa2_file =
      test_files_dir +
      "sintetic/"
      "exec_ip_ON_EMCHD_20241203_c61a40df-d38f-4800-9ba4-61a2df016993.xml";
    REQUIRE(std::filesystem::exists(mrpa2_file));
    mrpa::Mrpa mrpa2(mrpa2_file);
    REQUIRE(mrpa2.IsValid());
    REQUIRE(mrpa2.getGrantor().has_value());
    const auto& grantor = mrpa2.getGrantor();
    REQUIRE(grantor->all_persons.size() == 1);
    REQUIRE_FALSE(grantor->ToJson().at("executive_ips").as_array().empty());
  }
  SECTION("two_ip") {
    const std::string mrpa2_file =
      test_files_dir +
      "sintetic/"
      "exec_two_ip_ON_EMCHD_20241203_c61a40df-d38f-4800-9ba4-61a2df016993.xml";
    REQUIRE(std::filesystem::exists(mrpa2_file));
    mrpa::Mrpa mrpa2(mrpa2_file);
    REQUIRE(mrpa2.IsValid());
    REQUIRE(mrpa2.getGrantor().has_value());
    const auto& grantor = mrpa2.getGrantor();
    REQUIRE(grantor->all_persons.size() == 2);
  }
}

TEST_CASE("Grantor_person") {
  SECTION("1") {
    const std::string mrpa2_file = test_files_dir +
                                   "sintetic/"
                                   "grantorPerson_ON_EMCHD_20241203_c61a40df-"
                                   "d38f-4800-9ba4-61a2df016993.xml";
    REQUIRE(std::filesystem::exists(mrpa2_file));
    mrpa::Mrpa mrpa2(mrpa2_file);
    REQUIRE(mrpa2.IsValid());
    REQUIRE(mrpa2.getGrantor().has_value());
    const auto& grantor = mrpa2.getGrantor();
    REQUIRE(grantor->all_persons.size() == 1);
    REQUIRE(grantor->ToJson().at("snils_person").as_string() ==
            "052-951-639 83");
    REQUIRE(mrpa::ToString(grantor->type) == "Person");
  }

  SECTION("incapacity") {
    const std::string mrpa2_file = test_files_dir +
                                   "sintetic/"
                                   "incapacity_grantorPerson_ON_EMCHD_20241203_"
                                   "c61a40df-d38f-4800-9ba4-61a2df016993.xml";
    REQUIRE(std::filesystem::exists(mrpa2_file));
    mrpa::Mrpa mrpa2(mrpa2_file);
    REQUIRE(mrpa2.IsValid());
    REQUIRE(mrpa2.getGrantor().has_value());
    const auto& grantor = mrpa2.getGrantor();
    REQUIRE(grantor->all_persons.size() == 1);
    REQUIRE(grantor->all_persons.at(0).last_name == "ПредставительПРАВДИН");
    const auto json_obj = grantor->all_persons.at(0).ToJson();
  }
}

TEST_CASE("Representative") {
  SECTION("1") {
    const std::string mrpa2_file =
      test_files_dir +
      "sintetic/"
      "repr1_ON_EMCHD_20241203_c61a40df-d38f-4800-9ba4-61a2df016993.xml";
    REQUIRE(std::filesystem::exists(mrpa2_file));
    mrpa::Mrpa mrpa2(mrpa2_file);
    REQUIRE(mrpa2.IsValid());
    REQUIRE(mrpa2.getGrantor().has_value());
    const auto& grantor = mrpa2.getGrantor();
    REQUIRE(grantor->all_persons.size() == 1);
    REQUIRE(mrpa2.getRepresentatives().size() == 0);
    REQUIRE(grantor->ToJson().at("incorp_doc").as_string() == "НаимУчрДок123");
    REQUIRE(grantor->ToJson().at("department_reg_number").as_string() ==
            "РегНомер1");
  }
  SECTION("2") {
    const std::string mrpa2_file =
      test_files_dir +
      "sintetic/"
      "repr2_ON_EMCHD_20241203_c61a40df-d38f-4800-9ba4-61a2df016993.xml";
    REQUIRE(std::filesystem::exists(mrpa2_file));
    mrpa::Mrpa mrpa2(mrpa2_file);
    REQUIRE(mrpa2.IsValid());
    REQUIRE(mrpa2.getGrantor().has_value());
    const auto& grantor = mrpa2.getGrantor();
    REQUIRE(grantor->all_persons.size() == 1);
    REQUIRE(mrpa2.getRepresentatives().size() == 1);
    constexpr const char* expexted_repr =
      R"({"last_name":"ЛАМИМОВА","name":"АННА","patronymic":"СЕРГЕЕВНА","birth_date":"1978-07-12","personal_id_doc":{"doc_number":"45 23 707774","date_issued":"2023-08-30","issuer":"ГУ МВД России по г. Бишкек","issuer_id":"770-101"},"inn_person":"510103034646","snils_person":"052-951-639 83"})";
    REQUIRE(boost::json::serialize(mrpa2.getRepresentatives().at(0).ToJson()) ==
            expexted_repr);
  }
  SECTION("3") {
    const std::string mrpa2_file =
      test_files_dir +
      "sintetic/"
      "repr3_ON_EMCHD_20241203_c61a40df-d38f-4800-9ba4-61a2df016993.xml";
    REQUIRE(std::filesystem::exists(mrpa2_file));
    mrpa::Mrpa mrpa2(mrpa2_file);
    REQUIRE_FALSE(mrpa2.IsValid());
  }
}

TEST_CASE("ExtractGrantors") {
  SECTION("DefaultConstructed") {
    mrpa::Mrpa mrpa;
    REQUIRE_THROWS(mrpa.ParseGrantors());
    REQUIRE_FALSE(mrpa.getGrantor());
  }
  SECTION("Empty Doc") {
    mrpa::Mrpa mrpa(xml_empty);
    REQUIRE_THROWS(mrpa.ParseGrantors());
    REQUIRE_FALSE(mrpa.getGrantor());
  }

  SECTION("Valid1") {
    mrpa::Mrpa mrpa(mrpa1_valid);
    REQUIRE(mrpa.IsValid());
    const auto& grantor = mrpa.getGrantor();
    REQUIRE(grantor.has_value());
    REQUIRE_FALSE(grantor->persons.empty());
    REQUIRE_FALSE(grantor->all_persons.empty());
    const auto& persons = mrpa.getRepresentatives();
    REQUIRE_FALSE(persons.empty());
    std::cout << "Grantors:\n";
    std::for_each(grantor->all_persons.cbegin(), grantor->all_persons.cend(),
                  [](const auto& pers) {
                    std::cout << boost::json::serialize(pers.ToJson());
                  });

    std::cout << "\nPersons:\n";
    std::for_each(persons.cbegin(), persons.cend(), [](const auto& pers) {
      std::cout << boost::json::serialize(pers.ToJson());
    });
  }
}

TEST_CASE("SoleExecutiveFabric") {
  REQUIRE(mrpa::makeExecutive(true, false, true) ==
          mrpa::SoleExecutive::kUnknown);
  REQUIRE(mrpa::makeExecutive(true, true, true) ==
          mrpa::SoleExecutive::kUnknown);
  REQUIRE(mrpa::makeExecutive(false, false, false) ==
          mrpa::SoleExecutive::kUnknown);
  REQUIRE(mrpa::makeExecutive(true, false, false) ==
          mrpa::SoleExecutive::kCompany);
  REQUIRE(mrpa::makeExecutive(false, true, false) == mrpa::SoleExecutive::kIP);
  REQUIRE(mrpa::makeExecutive(false, false, true) ==
          mrpa::SoleExecutive::kPerson);
}

#ifndef SKIP_SENSITIVE_DATA
TEST_CASE("Match_grantor") {
  SECTION("Basic") {
    const std::string sig_path =
      test_files_dir +
      "sensitive/"
      "ON_EMCHD_20241210_5fd0cfce-3587-4b00-8501-1a6aebcacda9.sig";
    const std::string src_path =
      test_files_dir +
      "sensitive/"
      "ON_EMCHD_20241210_5fd0cfce-3587-4b00-8501-1a6aebcacda9.xml";
    if (std::filesystem::exists(sig_path) &&
        std::filesystem::exists(src_path)) {
      std::unique_ptr<mrpa::Mrpa> mrpa;
      REQUIRE_NOTHROW(mrpa = std::make_unique<mrpa::Mrpa>(src_path));
      REQUIRE(mrpa->IsValid());
      REQUIRE_NOTHROW(mrpa->setSignature(sig_path));
      REQUIRE(!mrpa->IsValidSignature());
      const auto& grantor = mrpa->getGrantor();
      REQUIRE(grantor.has_value());
    }
  }

  SECTION("Fake_signature") {
    const std::string sig_path =
      test_files_dir +
      "sensitive/"
      "ON_EMCHD_20241210_5fd0cfce-3587-4b00-8501-1a6aebcacda9_FAKE.xml.sig";
    const std::string src_path =
      test_files_dir +
      "sensitive/"
      "ON_EMCHD_20241210_5fd0cfce-3587-4b00-8501-1a6aebcacda9.xml";
    if (std::filesystem::exists(sig_path) &&
        std::filesystem::exists(src_path)) {
      std::unique_ptr<mrpa::Mrpa> mrpa;
      REQUIRE_NOTHROW(mrpa = std::make_unique<mrpa::Mrpa>(src_path));
      REQUIRE(mrpa->IsValid());
      REQUIRE_NOTHROW(mrpa->setSignature(sig_path));
      REQUIRE_FALSE(mrpa->IsValidSignature());
      const auto& grantor = mrpa->getGrantor();
      REQUIRE(grantor.has_value());
    }
  }
}
#endif

#ifndef SKIP_SENSITIVE_DATA
TEST_CASE("Real_MRPA_list") {
  const std::string path_to_folder = test_files_dir + "sensitive/real_examples";
  SECTION("valid") {
    if (!std::filesystem::exists(path_to_folder)) {
      std::cerr << "Path does not found:" << path_to_folder << "\n";
      return;
    }
    int counter_invalid = 0;
    int counter_valid = 0;
    const auto dir_it = std::filesystem::directory_iterator(path_to_folder);
    std::for_each(
      std::filesystem::begin(dir_it), std::filesystem::end(dir_it),
      [&counter_invalid, &counter_valid](const auto& entry) {
        if (!entry.is_regular_file()) {
          return;
        }
        const std::filesystem::path& path = entry.path();
        if (path.extension() == ".xml") {
          std::unique_ptr<mrpa::Mrpa> mrpa1;
          REQUIRE_NOTHROW(mrpa1 = std::make_unique<mrpa::Mrpa>(path));
          std::string sig_file = entry.path().string();
          boost::algorithm::erase_last(sig_file,
                                       entry.path().extension().string());
          sig_file += ".sig";
          REQUIRE(std::filesystem::exists(sig_file));
          bool invalid_sig_expected = std::any_of(
            arr_invalid_mrpa1.cbegin(), arr_invalid_mrpa1.cend(),
            [&sig_file](const auto& val) {
              return val == std::filesystem::path(sig_file).filename().string();
            });
          std::cout << "invalid_sig_expected" << invalid_sig_expected << "\n";
          if (boost::algorithm::starts_with(entry.path().stem().string(),
                                            "ON_EMCHD")) {
            REQUIRE(mrpa1);
            REQUIRE(mrpa1->IsValid());
            // REQUIRE(mrpa1->IsTimeValid());
            if (!mrpa1->IsTimeValid()) {
              std::cout << "TIME_INVALID" << "\n";
            }
            ++counter_valid;
            std::cout << "\n\n\nTry to set signature:"
                      << std::filesystem::path(sig_file).stem().string()
                      << "\n";
            mrpa1->setSignature(sig_file);
            std::this_thread::sleep_for(std::chrono::seconds(1));
            if (!invalid_sig_expected) {
              REQUIRE(mrpa1->IsValidSignature());
            } else {
              REQUIRE_FALSE(mrpa1->IsValidSignature());
            }
          } else {
            REQUIRE(mrpa1);
            REQUIRE_FALSE(mrpa1->IsValid());
            ++counter_invalid;
          }
        }
      });
    std::cout << "Valid files number: " << counter_valid << "\n"
              << "Invalid files number: " << counter_invalid << "\n";
  }
}
#endif

#ifndef SKIP_SENSITIVE_DATA

TEST_CASE("Real_sigs") {
  const std::string path_to_folder =
    test_files_dir + "sensitive/task180656/all_sign";
  const std::string src_file = path_to_folder + "/signme.pdf";
  REQUIRE(std::filesystem::exists(path_to_folder));
  REQUIRE(std::filesystem::exists(src_file));
  const auto dir_it = std::filesystem::directory_iterator(path_to_folder);
  const auto src_data = pdfcsp::utils::FileToVector(src_file);
  REQUIRE(src_data.has_value());
  REQUIRE_FALSE(src_data->empty());

  // iterate files
  int counter = 0;
  int attached_count = 0;
  int detached_count = 0;
  std::map<pdfcsp::csp::CadesType, int> cades_types;
  std::for_each(
    std::filesystem::begin(dir_it), std::filesystem::end(dir_it),
    [&counter, &attached_count, &detached_count, &cades_types,
     &src_file](const auto& entry) {
      // if (counter > 10) {
      //   return;
      // }
      if (!entry.is_regular_file()) {
        return;
      }
      // skip non signature files
      const std::string f_extension = entry.path().extension().string();
      if (std::none_of(
            sig_files_extension.cbegin(), sig_files_extension.cend(),
            [&f_extension](const auto& ext) { return ext == f_extension; })) {
        return;
      }
      std::cout << "\n\n Test signature: " << entry.path().filename().string()
                << '\n';
      const std::string sig_file = entry.path().string();
      pdfcsp::c_bridge::SeparateSignatureParams params{};
      std::cout << sig_file << "\n";
      params.sig_file_path = sig_file.c_str();
      params.sig_file_path_size = sig_file.size();
      const bool is_attached =
        pdfcsp::c_bridge::IsMessageAttached(&params) == 1;
      std::cout << "Attached: " << is_attached << "\n";
      if (!is_attached) {
        pdfcsp::c_bridge::CPodParam params{};
        params.sig_file_path = sig_file.c_str();
        params.sig_file_path_size = sig_file.size();
        params.file_path = src_file.c_str();
        params.file_path_size = src_file.size();
        auto res = std::shared_ptr<pdfcsp::c_bridge::CPodResult>(
          CheckSimpleDetached(params), pdfcsp::c_bridge::CFreeResult);
        REQUIRE(res);
        // REQUIRE(res->bres.check_summary);
        ++cades_types[res->cades_type];
        ++detached_count;
      } else {
        pdfcsp::c_bridge::CPodParam params{};
        params.sig_file_path = sig_file.c_str();
        params.sig_file_path_size = sig_file.size();
        params.file_path_size = src_file.size();
        auto res = std::shared_ptr<pdfcsp::c_bridge::CPodResult>(
          CheckSimpleAttached(params), pdfcsp::c_bridge::CFreeResult);
        REQUIRE(res);
        // REQUIRE(res->bres.check_summary);
        ++cades_types[res->cades_type];
        ++attached_count;
      }
      ++counter;
    });
  std::cout << "TOTAL SIGNATURES: " << counter << "\n";
  std::cout << "Attached :" << attached_count << "\n";
  std::cout << "Detached :" << detached_count << "\n";
  std::for_each(cades_types.cbegin(), cades_types.cend(),
                [](const auto& pairval) {
                  switch (pairval.first) {
                    case pdfcsp::csp::CadesType::kCadesBes:
                      std::cout << "BES :" << pairval.second << "\n";
                      break;
                    case pdfcsp::csp::CadesType::kCadesT:
                      std::cout << "T :" << pairval.second << "\n";
                      break;
                    case pdfcsp::csp::CadesType::kCadesXLong1:
                      std::cout << "X1 :" << pairval.second << "\n";
                      break;
                    case pdfcsp::csp::CadesType::kPkcs7:
                      std::cout << "PKCS7 :" << pairval.second << "\n";
                      break;
                    case pdfcsp::csp::CadesType::kUnknown:
                      std::cout << "Unknown :" << pairval.second << "\n";
                      break;
                  }
                });
}

#endif

TEST_CASE("SignaturePersonInfo_toJson") {
  mrpa::SignaturePersonInfo info;
  REQUIRE(boost::json::serialize(mrpa::utils::ToJson(info)) == "{}");
  info.signer_given_name = "GivenName";
  info.signer_surname = "Surname";
  info.signer_inn = "123";
  auto json = mrpa::utils::ToJson(info);
  REQUIRE(json.at("given_name").as_string().c_str() ==
          std::string("GivenName"));
  REQUIRE(json.at("surname").as_string().c_str() == std::string("Surname"));
  REQUIRE(json.at("inn").as_string().c_str() == std::string("123"));
}