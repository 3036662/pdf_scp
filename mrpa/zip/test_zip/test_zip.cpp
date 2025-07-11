#include <fmt/base.h>
#include <zipconf.h>
#define CATCH_CONFIG_MAIN
#include <libzip/zip.h>

#include <catch2/catch.hpp>
#include <filesystem>
#include <string_view>

#include "zip_cpp.hpp"

const std::string test_dir = std::string(TEST_FILES_DIR) + "mrpa/zip/";
const std::string zip1 = test_dir + "simple.zip";
const std::string zip_empty = test_dir + "empty.zip";
const std::string zip_nonzip = test_dir + "non_zip.zip";
const std::string zip_encrypted = test_dir + "encrypted.zip";

TEST_CASE("OpenZip") {
  REQUIRE(true);
  REQUIRE(std::filesystem::exists(zip1));
  int error_code = 0;
  zip_t* zfile = nullptr;
  SECTION("Normal") {
    zfile = zip_open(zip1.c_str(), ZIP_RDONLY, &error_code);
    REQUIRE(error_code == 0);
    REQUIRE(zfile != nullptr);
    zip_int64_t entries_count = zip_get_num_entries(zfile, ZIP_FL_UNCHANGED);
    REQUIRE(entries_count == 2);
    REQUIRE(zip_close(zfile) == 0);
  }
  SECTION("Empty") {
    zfile = zip_open(zip_empty.c_str(), ZIP_RDONLY, &error_code);
    REQUIRE(error_code == 0);
    REQUIRE(zfile != nullptr);
    zip_int64_t entries_count = zip_get_num_entries(zfile, ZIP_FL_UNCHANGED);
    REQUIRE(entries_count == 1);
    REQUIRE(zip_close(zfile) == 0);
  }
  SECTION("Broken") {
    zfile = zip_open(zip_nonzip.c_str(), ZIP_RDONLY, &error_code);
    REQUIRE(zfile == nullptr);
    zip_error_t error;
    zip_error_init_with_code(&error, error_code);
    REQUIRE(error_code == ZIP_ER_NOZIP);
    const char* err_c_str = zip_error_strerror(&error);
    REQUIRE(err_c_str != nullptr);
    const std::string err_str(err_c_str);
    REQUIRE_FALSE(err_str.empty());
    std::cout << "Error string:" << err_str << "\n";
    zip_error_fini(&error);
  }
}

TEST_CASE("ListFiles") {
  SECTION("Basic") {
    REQUIRE(std::filesystem::exists(zip1));
    int error_code = 0;
    zip_t* zfile = nullptr;
    zfile = zip_open(zip1.c_str(), ZIP_RDONLY, &error_code);
    REQUIRE(error_code == 0);
    REQUIRE(zfile != nullptr);
    zip_int64_t entries_count = zip_get_num_entries(zfile, ZIP_FL_UNCHANGED);
    REQUIRE(entries_count == 2);
    for (int i = 0; i < entries_count; ++i) {
      const char* cstr_filename =
        zip_get_name(zfile, i, ZIP_FL_ENC_RAW | ZIP_FL_ENC_GUESS);
      REQUIRE(cstr_filename != nullptr);
      const std::string filename(cstr_filename);
      std::cout << "File " << i << ":" << filename << "\n";
    }
    REQUIRE(zip_close(zfile) == 0);
  }
  SECTION("Empty") {
    REQUIRE(std::filesystem::exists(zip_empty));
    int error_code = 0;
    zip_t* zfile = nullptr;
    zfile = zip_open(zip_empty.c_str(), ZIP_RDONLY, &error_code);
    REQUIRE(error_code == 0);
    REQUIRE(zfile != nullptr);
    zip_int64_t entries_count = zip_get_num_entries(zfile, ZIP_FL_UNCHANGED);
    REQUIRE(entries_count > 0);
    for (int i = 0; i < entries_count; ++i) {
      const char* cstr_filename =
        zip_get_name(zfile, i, ZIP_FL_ENC_RAW | ZIP_FL_ENC_GUESS);
      REQUIRE(cstr_filename != nullptr);
      const std::string filename(cstr_filename);
      std::cout << "File " << i << ":" << filename << "\n";
    }
    REQUIRE(zip_close(zfile) == 0);
  }
  SECTION("Encrypted") {
    REQUIRE(std::filesystem::exists(zip_encrypted));
    int error_code = 0;
    zip_t* zfile = nullptr;
    zfile = zip_open(zip_encrypted.c_str(), ZIP_RDONLY, &error_code);
    REQUIRE(error_code == 0);
    REQUIRE(zfile != nullptr);
    REQUIRE(error_code == 0);
    zip_int64_t entries_count = zip_get_num_entries(zfile, ZIP_FL_UNCHANGED);
    REQUIRE(entries_count >= 1);
    for (int i = 0; i < entries_count; ++i) {
      const char* cstr_filename =
        zip_get_name(zfile, i, ZIP_FL_ENC_RAW | ZIP_FL_ENC_GUESS);
      REQUIRE(cstr_filename != nullptr);
      const std::string filename(cstr_filename);
      std::cout << "File " << i << ":" << filename << "\n";
    }
    REQUIRE(zip_close(zfile) == 0);
  }
}

TEST_CASE("TestInternals") {
  REQUIRE(zip_cpp::TestEmptyHandler());
  REQUIRE(zip_cpp::TestNormalHandler(zip1));
  REQUIRE(zip_cpp::TestMoveConstructorHandler(zip1));
  REQUIRE(zip_cpp::TestMoveAssignmentHandler(zip1));
  REQUIRE(zip_cpp::TestBoolOperatorHandler(zip1));
}

TEST_CASE("Check_if_zip") {
  SECTION("Normal") { REQUIRE(zip_cpp::IsZipArchive(zip1)); }
  SECTION("Empty") { REQUIRE(zip_cpp::IsZipArchive(zip_empty)); }
  SECTION("Encrypted") { REQUIRE(zip_cpp::IsZipArchive(zip_encrypted)); }
  SECTION("Non_zip") { REQUIRE_FALSE(zip_cpp::IsZipArchive(zip_nonzip)); }
  SECTION("Empty string") { REQUIRE_FALSE(zip_cpp::IsZipArchive("")); }
}

TEST_CASE("Zip_container") {
  REQUIRE(std::filesystem::exists(zip1));
  SECTION("empty") {
    zip_cpp::Zip zip_empty;
    REQUIRE(zip_empty.empty());
  }
  SECTION("basic") {
    zip_cpp::Zip zip_reader(zip1);
    REQUIRE(zip_reader.size() > 0);
    // TODO(Oleg)
  }
  SECTION("enctypted") {
    zip_cpp::Zip zip_reader(zip_encrypted);
    REQUIRE(zip_reader.size() > 0);
    // TODO(Oleg)
  }
}