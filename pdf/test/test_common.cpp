#include <cstddef>
#include <filesystem>
#include <fstream>
#include <memory>
#include <optional>
#define CATCH_CONFIG_MAIN
#include "common_defs.hpp"
#include "pdf.hpp"
#include "utils.hpp"
#include <catch2/catch.hpp>

#ifndef TEST_DIR
#define TEST_DIR "/home/oleg/"
#endif

using namespace pdfcsp::pdf;

constexpr const char *kFileWin = "0207_signed_win.pdf";

TEST_CASE("Test utils") {
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
