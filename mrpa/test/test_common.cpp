#include <libxml++/document.h>
#include <libxml++/parsers/domparser.h>

#include <algorithm>
#include <boost/property_tree/ptree_fwd.hpp>
#include <cstddef>

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

#include "common_utils.hpp"
#include "string_defs.hpp"
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
  REQUIRE_FALSE(mrpa::GetMRPAGuid(nullptr));
  auto mrpa = std::make_unique<xmlpp::DomParser>();
  REQUIRE_NOTHROW(mrpa->parse_file(mrpa_deleted_el1));
  REQUIRE_FALSE(mrpa::GetMRPAGuid(mrpa->get_document()));
  REQUIRE_NOTHROW(mrpa->parse_file(mrpa_deleted_el2));
  REQUIRE_FALSE(mrpa::GetMRPAGuid(mrpa->get_document()));
  REQUIRE_NOTHROW(mrpa->parse_file(mrpa_deleted_el3));
  REQUIRE_FALSE(mrpa::GetMRPAGuid(mrpa->get_document()));
  REQUIRE_NOTHROW(mrpa->parse_file(fn(32)));
  REQUIRE_FALSE(mrpa::GetMRPAGuid(mrpa->get_document()).has_value());
  REQUIRE_THROWS(mrpa->parse_file(fn(33)));
}

TEST_CASE("XMLtoJSON") {
  SECTION("1") {
    auto mrpa = std::make_unique<xmlpp::DomParser>();
    REQUIRE_NOTHROW(mrpa->parse_file(valid7));
    auto* doc = mrpa->get_document();
    REQUIRE(doc != nullptr);
    std::optional<std::string> res = mrpa::XmlToJson(nullptr);
    REQUIRE_FALSE(res.has_value());
    res = mrpa::XmlToJson(doc);
    REQUIRE(res.has_value());
    std::cout << res.value() << "\n\n";
  }
  std::cout << "\n\n";
  SECTION("2") {
    auto mrpa = std::make_unique<xmlpp::DomParser>();
    REQUIRE_NOTHROW(mrpa->parse_file(valid4));
    auto* doc = mrpa->get_document();
    REQUIRE(doc != nullptr);
    std::optional<std::string> res = mrpa::XmlToJson(nullptr);
    REQUIRE_FALSE(res.has_value());
    res = mrpa::XmlToJson(doc);
    REQUIRE(res.has_value());
    std::cout << res.value() << "\n\n";
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
  auto json_val = mrpa::XmlToJson(mrpa->get_document());
  REQUIRE_FALSE(json_val.has_value());
}

TEST_CASE("ReadSigLowLevel") {
  REQUIRE(std::filesystem::exists(mrpa1_sig));
  auto sig_data = pdfcsp::utils::FileToVector(mrpa1_valid);
}