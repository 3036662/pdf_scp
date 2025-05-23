#include <libxml++/document.h>
#include <libxml++/parsers/domparser.h>
#define CATCH_CONFIG_MAIN

#include <libxml++/libxml++.h>
#include <libxml++/validators/xsdvalidator.h>
#include <libxml++/xsdschema.h>

#include <catch2/catch.hpp>
#include <filesystem>
#include <iostream>
#include <memory>
#include <string>

#include "string_defs.hpp"

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
    // REQUIRE_NOTHROW(validator->validate(doc));
    REQUIRE_THROWS_AS(validator->validate(doc), xmlpp::validity_error);
  }
}