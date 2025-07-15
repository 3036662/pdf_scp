#include <zipconf.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <string>

#include "common_utils.hpp"
#define CATCH_CONFIG_MAIN
#include <libzip/zip.h>

#include <catch2/catch.hpp>
#include <filesystem>
#include <string_view>

#include "zip_cpp.hpp"

namespace {
std::vector<std::string> generate_combinations2(
  const std::vector<char>& chars) {
  std::vector<std::string> combinations;

  // Reserve space for efficiency (n² combinations)
  combinations.reserve(chars.size() * chars.size());

  // Generate all possible pairs
  for (char first : chars) {
    for (char second : chars) {
      combinations.emplace_back(std::string{first, second});
    }
  }
  return combinations;
}

std::vector<std::string> generate_combinations3(
  const std::vector<char>& chars) {
  std::vector<std::string> combinations;
  combinations.reserve(chars.size() * chars.size());
  // Generate all possible pairs
  for (char first : chars) {
    for (char second : chars) {
      for (char third : chars) {
        combinations.emplace_back(std::string{first, second, third});
      }
    }
  }
  return combinations;
}

std::vector<char> allCP866chars() {
  std::vector<char> res;
  for (unsigned char symbol = 0x20; symbol <= 0x7F; ++symbol) {
    res.push_back(static_cast<char>(symbol));
  }
  for (unsigned char symbol = 0x80; symbol <= 0xAF; ++symbol) {
    res.push_back(static_cast<char>(symbol));
  }
  for (unsigned char symbol = 0xE0; symbol < 0xFF; ++symbol) {
    res.push_back(static_cast<char>(symbol));
  }
  res.push_back(static_cast<char>(0xFF));
  return res;
}

}  // namespace

TEST_CASE("cp866vsUTF8") {
  SECTION("1") {
    std::string str1 = zip_cpp::utf8_to_cp866("Строка1");
    REQUIRE(zip_cpp::is_valid_cp866(str1));
    REQUIRE_FALSE(zip_cpp::is_valid_utf8(str1));
    std::cout << "Convert to UTF-8:" << zip_cpp::cp866_to_utf8(str1) << "\n";
  }
  SECTION("2") {
    std::string str1 = zip_cpp::utf8_to_cp866("аb");
    REQUIRE(zip_cpp::is_valid_cp866(str1));
    REQUIRE_FALSE(zip_cpp::is_valid_utf8(str1));
    std::cout << "Convert to UTF-8:" << zip_cpp::cp866_to_utf8(str1) << "\n";
  }
  SECTION("One symbol") {
    for (unsigned char symbol = 0x80; symbol <= 0xAF; ++symbol) {
      std::cout << "Symbol:" << std::to_string(symbol) << "\n";
      std::string str;
      str.push_back(static_cast<char>(symbol));
      std::cout << "Raw:" << str << "\n";
      // std::string str1 = zip_cpp::utf8_to_cp866(str);
      REQUIRE(zip_cpp::is_valid_cp866(str));
      REQUIRE_FALSE(zip_cpp::is_valid_utf8(str));
      std::cout << "Convert to UTF-8:" << zip_cpp::cp866_to_utf8(str) << "\n";
    }
    for (unsigned char symbol = 0xE0; symbol < 0xFF; ++symbol) {
      std::cout << "Symbol:" << std::to_string(symbol) << "\n";
      std::string str;
      str.push_back(static_cast<char>(symbol));
      std::cout << "Raw:" << str << "\n";
      // std::string str1 = zip_cpp::utf8_to_cp866(str);
      REQUIRE(zip_cpp::is_valid_cp866(str));
      REQUIRE_FALSE(zip_cpp::is_valid_utf8(str));
      std::cout << "Convert to UTF-8:" << zip_cpp::cp866_to_utf8(str) << "\n";
    }
  }

  SECTION("Two symbols") {
    auto vec_chars = allCP866chars();
    std::cout << "Total russin chars:" << vec_chars.size() << "\n";
    std::vector<std::string> strings = generate_combinations2(vec_chars);
    std::cout << "Total " << strings.size() << " two bytes combinations;\n";
    uint64_t failed = 0;
    for (const auto& str : strings) {
      REQUIRE(zip_cpp::is_valid_cp866(str));
      if (zip_cpp::is_valid_utf8(str)) {
        zip_cpp::cp866_to_utf8(str);
        ++failed;
      }
      // REQUIRE_FALSE(zip_cpp::is_valid_utf8(str));
    }
    std::cout << "Total failed:" << failed << "\n";
  }

  SECTION("Three_symbols") {
    auto vec_chars = allCP866chars();
    std::cout << "Total russin chars:" << vec_chars.size() << "\n";
    std::vector<std::string> strings = generate_combinations3(vec_chars);
    std::cout << "Total " << strings.size() << " three bytes combinations;\n";
    uint64_t failed = 0;
    for (const auto& str : strings) {
      REQUIRE(zip_cpp::is_valid_cp866(str));
      if (zip_cpp::is_valid_utf8(str)) {
        zip_cpp::cp866_to_utf8(str);
        ++failed;
      }
      // REQUIRE_FALSE(zip_cpp::is_valid_utf8(str));
    }
    std::cout << "Total failed:" << failed << "\n";
  }
}