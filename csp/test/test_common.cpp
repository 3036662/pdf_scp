#include "csp.hpp"
#include "message_handler.hpp"
#include "pdf.hpp"
#include "resolve_symbols.hpp"
#include "typedefs.hpp"
#include <memory>
#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

#include "message.hpp"

using namespace pdfcsp::csp;

TEST_CASE("Test resolve symbols") { REQUIRE_NOTHROW(Csp()); }

TEST_CASE("Test Open Detached Message") {
  REQUIRE_THROWS(Message(std::make_shared<ResolvedSymbols>(), {}, {}));
  REQUIRE_THROWS(Message(nullptr, {0, 0, 0}, {1, 1, 1}));
  BytesVector vec = {0x30, 0x82, 0x58, 0x55, 0x06, 0x09, 0x2A, 0x86, 0xF7};
  REQUIRE_THROWS(Message(std::make_shared<ResolvedSymbols>(), std::move(vec),
                         {
                             1,
                             1,
                             1,
                         }));
  REQUIRE_THROWS(Message(std::make_shared<ResolvedSymbols>(), {0, 1, 2, 3},
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

TEST_CASE("Test MsgHandler constructor") {
  SECTION("Empty data") {
    REQUIRE_NOTHROW(MsgDescriptorWrapper());
    REQUIRE_THROWS(
        MsgDescriptorWrapper(nullptr, std::make_shared<ResolvedSymbols>()));
    int tmp = 1;
    REQUIRE_THROWS(MsgDescriptorWrapper(static_cast<void *>(&tmp), nullptr));
  }
}

constexpr const char *const test_file_dir = TEST_FILES_DIR;
constexpr const char *const file_win = "0207_signed_win.pdf";
TEST_CASE("Message_construction") {
  std::string fwin = test_file_dir;
  fwin += file_win;
  pdfcsp::pdf::Pdf pdf;
  pdfcsp::csp::Csp csp;
  PtrMsg msg;
  REQUIRE_NOTHROW(pdf.Open(fwin));
  REQUIRE_NOTHROW(pdf.FindSignature());
  // empty msg
  msg = csp.OpenDetached({}, pdf.getRawData());
  REQUIRE(!msg);
  // valid message
  // // std::cout << "size sig" << pdf.getRawSignature().size() << "\n";
  // // std::cout << "size data" << pdf.getRawData().size() << "\n";
  REQUIRE_NOTHROW(
      msg = csp.OpenDetached(pdf.getRawSignature(), pdf.getRawData()));
  REQUIRE(msg);
}