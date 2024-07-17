#include "csp.hpp"
#include "message_handler.hpp"
#include "pdf.hpp"
#include "resolve_symbols.hpp"
#include "typedefs.hpp"
#include <memory>
#include <type_traits>
#include <utils.hpp>
#include <vector>
#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Winvalid-utf8"
#include <CSP_WinCrypt.h> /// NOLINT
#include <CSP_WinDef.h>   /// NOLINT
#include <cades.h>        /// NOLINT
#pragma GCC diagnostic pop

// these macros can be redefined by cades.h - conflicts with std library
#undef __out
#undef __in
#undef __in_opt
#undef __out_opt
#undef __reserved

#include "message.hpp"

using namespace pdfcsp::csp;

// ---------------------------------------------------------------
// test utils

TEST_CASE("Test utils") {
  SECTION("Create buffer") {
    {
      auto buf = CreateBuffer(100);
      REQUIRE(buf.capacity() == 101);
    }
    {
      auto buf = CreateBuffer(0);
      REQUIRE(buf.capacity() == 1);
    }
    REQUIRE_THROWS(CreateBuffer(-100));
  }

  SECTION("IntBlobToVec") {
    REQUIRE(!IntBlobToVec(nullptr));
    CRYPT_INTEGER_BLOB blob;
    blob.cbData = 0;
    std::vector<unsigned char> src{'a', 'b', 'c'};
    blob.pbData = src.data();
    REQUIRE(!IntBlobToVec(&blob));
    blob.cbData = -100;
    REQUIRE(!IntBlobToVec(&blob));
    blob.cbData = src.size();
    std::vector<unsigned char> expected{'c', 'b', 'a'};
    auto res = IntBlobToVec(&blob);
    REQUIRE(res.has_value());
    REQUIRE(res.value() == expected);
  }

  SECTION("VecBytesStringRepresentation") {
    {
      std::vector<unsigned char> src = {0x00, 0x12, 0xFF};
      auto res = VecBytesStringRepresentation(src);
      REQUIRE(res == "012ff");
    }
    {
      std::vector<unsigned char> src;
      auto res = VecBytesStringRepresentation(src);
      REQUIRE(res.empty());
    }
  }
}

// ---------------------------------------------------------------

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

// -------------------------------------------------------------

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
  REQUIRE_NOTHROW(
      msg = csp.OpenDetached(pdf.getRawSignature(), pdf.getRawData()));
  REQUIRE(msg);
}

TEST_CASE("Message properties") {
  std::string fwin = test_file_dir;
  fwin += file_win;
  pdfcsp::pdf::Pdf pdf;
  pdfcsp::csp::Csp csp;
  PtrMsg msg;
  REQUIRE_NOTHROW(pdf.Open(fwin));
  REQUIRE_NOTHROW(pdf.FindSignature());
  // valid message
  REQUIRE_NOTHROW(
      msg = csp.OpenDetached(pdf.getRawSignature(), pdf.getRawData()));
  REQUIRE(msg);
  SECTION("Message type") {
    auto type = msg->GetCadesType();
    REQUIRE(type == CadesType::kCadesBes);
  }
  SECTION("Number of signers") {
    auto numb = msg->GetSignersCount();
    REQUIRE(numb.has_value());
    REQUIRE(numb.value() == 1);
  }
  SECTION("Number of revokes") {
    auto numb = msg->GetRevokedCertsCount();
    REQUIRE(numb.has_value());
    REQUIRE(numb.value() == 0);
  }
  SECTION("Number of certificates") {
    auto numb = msg->GetCertCount();
    REQUIRE(numb.has_value());
    REQUIRE(numb.value() == 1);
  }
  SECTION("Get raw certificate") {
    auto numb = msg->GetCertCount();
    REQUIRE(numb.has_value());
    for (size_t i = 0; i < numb.value(); ++i) {
      auto raw_cert = msg->GetRawCertificate(i);
      REQUIRE(raw_cert.has_value());
      REQUIRE(!raw_cert.value().empty());
    }
  }

  SECTION("GetSignerCertId") {
    auto res = msg->GetSignerCertId(0);
    REQUIRE(res.has_value());
    constexpr const char *const issuer_expected =
        "ОГРН=1234567890123, ИНН=001234567890, STREET=ул. Сущёвский вал д. 18, "
        "C=RU, S=г. Москва, L=Москва, O=\"ООО \"\"КРИПТО-ПРО\"\"\", "
        "CN=\"Тестовый УЦ ООО \"\"КРИПТО-ПРО\"\"\"";
    constexpr const char *const serial_expected =
        "7c01576777625ad53cb96c4a080157677";
    REQUIRE(std::string(issuer_expected).size() == res->issuer.size());
    REQUIRE(res->issuer == issuer_expected);
    REQUIRE(VecBytesStringRepresentation(res->serial) == serial_expected);
  }
}
