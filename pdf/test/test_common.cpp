/* File: test_common.cpp
Copyright (C) Basealt LLC,  2024
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

#include <cstddef>
#include <filesystem>
#include <fstream>
#include <memory>
#include <optional>
#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

#include "common_defs.hpp"
#include "csppdf.hpp"
#include "pdf_utils.hpp"

#ifndef TEST_DIR
#define TEST_DIR "/home/oleg/"
#endif

using namespace pdfcsp::pdf;

constexpr const char *kFileWin = "valid_files/05_acrob_BES.pdf";

TEST_CASE("Test reading file") {
  const std::string kTestDir(TEST_DIR);
  SECTION("Test FileToVector") {
    constexpr const char *const kTestFile = "test_file1";
    const std::string kFile1full(kTestDir + kTestFile);
    REQUIRE(FileToVector("") == std::nullopt);
    REQUIRE(FileToVector("/var/sadl/ff") == std::nullopt);
    std::ofstream testfile(kFile1full, std::ios::out | std::ios::trunc);
    REQUIRE(testfile.is_open());
    auto res = FileToVector(kFile1full);
    REQUIRE((res.has_value() && res->empty()));
    for (int i = 0; i < 1024; ++i) {
      testfile.write("\1", 1);
    }
    testfile.flush();
    res = FileToVector(kFile1full);
    REQUIRE((res.has_value() && res->size() == 1024));
    size_t counter = 0;
    for (size_t i = 0; i < res->size(); ++i) {
      counter += res.value()[i];
    }
    REQUIRE(counter == res->size());
    testfile.close();
    std::filesystem::remove(kFile1full);
  }
}

TEST_CASE("Test read with byrearray") {
  SECTION("Invalid byterange") {
    std::string test_file_win(TEST_FILES_DIR);
    test_file_win += kFileWin;
    {
      auto vec = FileToVector(test_file_win, {{0, 0}, {0, 0}});
      REQUIRE(vec.has_value());
      REQUIRE(vec->empty());
    }
    {
      auto vec = FileToVector(test_file_win, {{0, -100}, {0, 1000}});
      REQUIRE_FALSE(vec.has_value());
    }
    {
      auto vec = FileToVector(test_file_win, {{-1, 0}, {0, 1000}});
      REQUIRE_FALSE(vec.has_value());
    }
    {
      auto vec = FileToVector(test_file_win, {{-1, 0}, {0, 1000}});
      REQUIRE_FALSE(vec.has_value());
    }
    {
      auto vec = FileToVector(test_file_win, {});
      REQUIRE(vec.has_value());
      REQUIRE(vec->empty());
    }
    {
      auto vec = FileToVector(test_file_win, {{0, 100}, {0, 1}});
      REQUIRE(vec.has_value());
      REQUIRE(vec->size() == 101);
    }
    {
      const std::string kTestDir(TEST_DIR);
      constexpr const char *const kTestFile = "test_file1";
      const std::string kFile1full(kTestDir + kTestFile);
      std::ofstream testfile(kFile1full, std::ios::out | std::ios::trunc);
      REQUIRE(testfile.is_open());
      for (int i = 0; i < 1024; ++i) {
        testfile.write("\1", 1);
      }
      testfile.flush();
      testfile.close();
      auto res = FileToVector(kFile1full, {{0, 100}, {101, 100}});
      REQUIRE(res.has_value());
      REQUIRE(res->size() == 200);
      size_t counter = 0;
      for (size_t i = 0; i < res->size(); ++i) {
        counter += res.value()[i];
      }
      REQUIRE(counter == res->size());
      std::filesystem::remove(kFile1full);
    }
  }
}

TEST_CASE("Test PDF class constructor") {
  std::unique_ptr<Pdf> pdf;
  REQUIRE_NOTHROW(pdf = std::make_unique<Pdf>());
  std::string test_file_win(TEST_FILES_DIR);
  test_file_win += kFileWin;
  REQUIRE_THROWS(pdf->Open("blablabla"));
  REQUIRE_THROWS(pdf->Open(""));
  std::cout << test_file_win;
  REQUIRE_NOTHROW(pdf->Open(test_file_win));
}

TEST_CASE("Test FindSignature") {
  SECTION("Find existing sig") {
    std::string test_file_win(TEST_FILES_DIR);
    test_file_win += kFileWin;
    std::unique_ptr<Pdf> pdf = std::make_unique<Pdf>(test_file_win);
    REQUIRE(pdf->FindSignatures());
  }

  SECTION("Find non-existing sig") {
    std::string test_file(TEST_FILES_DIR);
    test_file += "source_empty.pdf";
    std::unique_ptr<Pdf> pdf = std::make_unique<Pdf>(test_file);
    REQUIRE_FALSE(pdf->FindSignatures());
  }
}

TEST_CASE("Test get raw signature") {
  std::string test_file_win(TEST_FILES_DIR);
  test_file_win += kFileWin;
  std::unique_ptr<Pdf> pdf = std::make_unique<Pdf>(test_file_win);
  REQUIRE(pdf->FindSignatures());
  for (uint i = 0; i < pdf->GetSignaturesCount(); ++i) {
    REQUIRE(pdf->getRawSignature(i).size() > 0);
  }
}

TEST_CASE("Test get raw data") {
  std::string test_file_win(TEST_FILES_DIR);
  test_file_win += kFileWin;
  std::unique_ptr<Pdf> pdf = std::make_unique<Pdf>(test_file_win);
  REQUIRE(pdf->FindSignatures());
  for (uint i = 0; i < pdf->GetSignaturesCount(); ++i) {
    REQUIRE(pdf->getRawData(i).size() > 0);
  }
}
