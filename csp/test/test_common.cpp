#include "csp.hpp"
#include "resolve_symbols.hpp"
#include <memory>
#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

#include "message.hpp"

using namespace pdfcsp::csp;

TEST_CASE("Test resolve symbols") { REQUIRE_NOTHROW(Csp()); }

TEST_CASE("Test Open Detached Message") {
  REQUIRE_THROWS(Message(std::make_shared<ResolvedSymbols>(), {}, {}));
  REQUIRE_THROWS(Message(nullptr, {0, 0, 0}, {1, 1, 1}));
  REQUIRE_NOTHROW(Message(std::make_shared<ResolvedSymbols>(), {0, 0, 0},
                          {
                              1,
                              1,
                              1,
                          }));
}

TEST_CASE("Test CSP create message") {
  SECTION("Empty data") {
    Csp csp;
    REQUIRE(!csp.OpenDetached({}, {}));
  }
}