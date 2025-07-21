#include "common_utils.hpp"
#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

#include "tree_context.hpp"

const std::string src_simple_zip =
  std::string(TEST_FILES_DIR) + "mrpa/zip/simple.zip";

TEST_CASE("Initial") { REQUIRE(true); }

TEST_CASE("DefaultConstructor") { REQUIRE_NOTHROW(mrpa::TreeContext()); }