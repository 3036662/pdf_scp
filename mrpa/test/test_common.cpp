#include <libxml++/document.h>
#include <libxml++/parsers/domparser.h>

#include <algorithm>
#include <boost/property_tree/ptree_fwd.hpp>
#include <cstddef>
#include <fstream>
#include <ios>

#include "mrpa.hpp"
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
  auto shema = std::make_unique<xmlpp::XsdSchema>();
  // non existing file
  REQUIRE_THROWS(shema->parse_file("non_existing_file"));
  // non shema
  REQUIRE_THROWS(shema->parse_file(mrpa1_valid));
  // valid file
  REQUIRE_NOTHROW(shema->parse_file(mrpa_scheme));
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
  auto shema = std::make_unique<xmlpp::XsdSchema>();
  REQUIRE_NOTHROW(shema->parse_file(mrpa_scheme));
  // validator
  auto validator = std::make_unique<xmlpp::XsdValidator>();
  REQUIRE_NOTHROW(validator->set_schema(shema.get(), false));
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
    REQUIRE(std::filesystem::exists(mrpa_invalid_unxpected_attr_7));
    // load the doc
    auto mrpa = std::make_unique<xmlpp::DomParser>();
    REQUIRE_NOTHROW(mrpa->parse_file(mrpa_invalid_unxpected_attr_7));
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
    REQUIRE_FALSE(IsMessageAttached(&cparams));
  }

  SECTION("Attached") {
    REQUIRE(std::filesystem::exists(sig_attached1));
    pdfcsp::c_bridge::SeparateSignatureParams cparams{};
    cparams.sig_file_path = sig_attached1.c_str();
    cparams.sig_file_path_size = sig_attached1.size();
    REQUIRE(IsMessageAttached(&cparams));
  }

  SECTION("Attached") {
    REQUIRE(std::filesystem::exists(sig_detached2));
    pdfcsp::c_bridge::SeparateSignatureParams cparams{};
    cparams.sig_file_path = sig_detached2.c_str();
    cparams.sig_file_path_size = sig_detached2.size();
    REQUIRE_FALSE(IsMessageAttached(&cparams));
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

  SECTION("Revoced_T") {
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
      REQUIRE(mrpa->IsValidSignature());
    }
  }
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

TEST_CASE("ExtractGrantors") {
  SECTION("DefaultConstructed") {
    mrpa::Mrpa mrpa;
    REQUIRE_THROWS(mrpa.ParseGrantors());
    REQUIRE(mrpa.getGrantors().empty());
  }
  SECTION("Empty Doc") {
    mrpa::Mrpa mrpa(xml_empty);
    REQUIRE_THROWS(mrpa.ParseGrantors());
    REQUIRE(mrpa.getGrantors().empty());
  }

  SECTION("Valid1") {
    mrpa::Mrpa mrpa(mrpa1_valid);
    REQUIRE(mrpa.IsValid());
    REQUIRE_NOTHROW(mrpa.ParseGrantors());
  }
}