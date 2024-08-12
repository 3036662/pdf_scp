#include "asn1.hpp"
#include "crypto_attribute.hpp"
#include "csp.hpp"
#include "message_handler.hpp"
#include "pdf.hpp"
#include "resolve_symbols.hpp"
#include "typedefs.hpp"
#include "utils.hpp"
#include <memory>
#include <stdexcept>
#include <string>
#include <type_traits>
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

using namespace pdfcsp::csp::asn;
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
  REQUIRE_THROWS(
      Message(std::make_shared<ResolvedSymbols>(), {}, MessageType::kDetached));
  REQUIRE_THROWS(Message(nullptr, {0, 0, 0}, MessageType::kDetached));
  BytesVector vec = {0x30, 0x82, 0x58, 0x55, 0x06, 0x09, 0x2A, 0x86, 0xF7};
  REQUIRE_THROWS(Message(std::make_shared<ResolvedSymbols>(), vec,
                         MessageType::kDetached));
  REQUIRE_THROWS(Message(std::make_shared<ResolvedSymbols>(), {0, 1, 2, 3},
                         MessageType::kDetached));
}

TEST_CASE("Test CSP create message") {
  SECTION("Empty data") {
    Csp csp;
    REQUIRE(!csp.OpenDetached({}));
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
  REQUIRE_NOTHROW(pdf.FindSignatures());
  // empty msg
  msg = csp.OpenDetached({});
  REQUIRE(!msg);
  // valid message
  REQUIRE_NOTHROW(msg = csp.OpenDetached(pdf.getRawSignature(0)));
  REQUIRE(msg);
}

TEST_CASE("ASN1") {

  SECTION("ASN1 parser") {
    PtrSymbolResolver symbols = std::make_shared<ResolvedSymbols>();

    {
      std::string str1;
      str1.resize(10, 0x00);
      unsigned char *ptr = reinterpret_cast<unsigned char *>(str1.data());
      REQUIRE_THROWS(AsnObj(nullptr, 100));
      REQUIRE_THROWS(AsnObj(nullptr, 100));
      // REQUIRE_THROWS(AsnObj(ptr, 100));
      REQUIRE_THROWS(AsnObj(ptr, 1));
      REQUIRE_THROWS(AsnObj(ptr, 2));

      str1.resize(100, 0x01);
      ptr = reinterpret_cast<unsigned char *>(str1.data());
      REQUIRE_THROWS(AsnObj(ptr, 200));
      REQUIRE_THROWS(AsnObj(ptr, 200));
      str1 = "MIIFajCCBFKgAwIBAgISA6HJW9qjaoJoMn8iU8vTuiQ2MA0GCSqGSIb3DQEBCwUA";
      ptr = reinterpret_cast<unsigned char *>(str1.data());
      REQUIRE_THROWS(AsnObj(ptr, str1.size()));
    }
  }

  // SECTION("Free suite") {
  //   std::string folder = "/home/oleg/dev/eSign/test_suiteASN1/TEST_SUITE/";
  //   PtrSymbolResolver symbols = std::make_shared<ResolvedSymbols>();

  //   std::set<int> good{32, 18, 21, 37, 13, 25, 26, 28, 29, 30, 31};
  //   for (int i = 1; i < 49; ++i) {
  //     std::cout << i << "\n";
  //     auto buff = pdfcsp::csp::FileToVector(folder + "encoded_tc" +
  //                                           std::to_string(i) + ".ber");
  //     REQUIRE(buff.has_value());
  //     if (good.count(i) > 0) {
  //       REQUIRE_NOTHROW(AsnObj(buff->data(), buff->size(), symbols));
  //     } else {
  //       REQUIRE_THROWS(AsnObj(buff->data(), buff->size(), symbols));
  //     }
  //   }
  // }

  SECTION("Parse raw signature") {
    std::string fwin = test_file_dir;
    fwin += file_win;
    pdfcsp::pdf::Pdf pdf;
    pdfcsp::csp::Csp csp;
    PtrMsg msg;
    REQUIRE_NOTHROW(pdf.Open(fwin));
    REQUIRE_NOTHROW(pdf.FindSignatures());
    PtrSymbolResolver symbols = std::make_shared<ResolvedSymbols>();
    auto raw_signature = pdf.getRawSignature(0);
    AsnObj obj(raw_signature.data(), raw_signature.size());
    BytesVector unparsed = obj.Unparse();
    while (unparsed.size() < raw_signature.size()) {
      unparsed.push_back(0x00);
    }
    REQUIRE(raw_signature == unparsed);
  }
}

TEST_CASE("Message properties") {
  std::string fwin = test_file_dir;
  fwin += file_win;
  pdfcsp::pdf::Pdf pdf;
  pdfcsp::csp::Csp csp;
  PtrMsg msg;
  REQUIRE_NOTHROW(pdf.Open(fwin));
  REQUIRE_NOTHROW(pdf.FindSignatures());
  // valid message
  REQUIRE_NOTHROW(msg = csp.OpenDetached(pdf.getRawSignature(0)));
  REQUIRE(msg);

  // TODO(Oleg) enable after solving the problem with memory leaks in libcades
  // SECTION("Message type") {
  //   auto type = msg->GetCadesType();
  //   REQUIRE(type == CadesType::kCadesBes);
  // }
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
    auto numb = msg->GetCertCount(0);
    REQUIRE(numb.has_value());
    REQUIRE(numb.value() == 1);
  }
  SECTION("Get raw certificate") {
    auto numb = msg->GetCertCount(0);
    REQUIRE(numb.has_value());
    for (size_t i = 0; i < numb.value(); ++i) {
      auto raw_cert = msg->GetRawCertificate(i);
      REQUIRE(raw_cert.has_value());
      REQUIRE(!raw_cert.value().empty());
    }
  }

  SECTION("Get crypto attributes") {
    auto res = msg->GetAttributes(0, pdfcsp::csp::AttributesType::kSigned);
    REQUIRE(res.has_value());
    const CryptoAttributesBunch &bunch = res.value();
    uint attr_count = bunch.get_count();
    REQUIRE(attr_count == 4);
    REQUIRE(bunch.get_bunch()[0].get_blobs()[0].size() == 11);
    REQUIRE(bunch.get_bunch()[1].get_blobs()[0].size() == 15);
    REQUIRE(bunch.get_bunch()[2].get_blobs()[0].size() == 34);
    REQUIRE(bunch.get_bunch()[3].get_blobs()[0].size() == 361);
    // for (const auto &attr : bunch.get_bunch()) {
    //   std::cout << "id=" << attr.get_id() << "\n";
    //   std::cout << "blobs count=" << attr.get_blobs_count() << "\n";
    //   for (const auto &blob : attr.get_blobs()) {
    //     std::cout << "blob size=" << blob.size() << "\n";
    //   }
    // }
  }

  SECTION("GetSignerCertId") {
    auto res = msg->GetSignerCertId(0);
    REQUIRE(res.has_value());
    // clang-format off
      constexpr const char *const issuer_expected =
          "ОГРН=1234567890123, ИНН=001234567890, STREET=ул. Сущёвский вал д. 18, " "C=RU, S=г. Москва, L=Москва, O=\"ООО \"\"КРИПТО-ПРО\"\"\","
          " CN=\"Тестовый УЦ ООО \"\"КРИПТО-ПРО\"\"\"";
      constexpr const char *const serial_expected =
          "7c01576777625ad53cb96c4a080157677";
    // clang-format on
    REQUIRE(std::string(issuer_expected).size() == res->issuer.size());
    REQUIRE(res->issuer == issuer_expected);
    REQUIRE(VecBytesStringRepresentation(res->serial) == serial_expected);
    REQUIRE(!res->hashing_algo_oid.empty());
  }
}

TEST_CASE("DataHash") {
  std::string fwin = test_file_dir;
  fwin += file_win;
  pdfcsp::pdf::Pdf pdf;
  pdfcsp::csp::Csp csp;
  PtrMsg msg;
  REQUIRE_NOTHROW(pdf.Open(fwin));
  REQUIRE_NOTHROW(pdf.FindSignatures());
  // valid message
  REQUIRE_NOTHROW(msg = csp.OpenDetached(pdf.getRawSignature(0)));
  REQUIRE(msg);

  SECTION("CheckDataHash") {
    // empty data
    REQUIRE_FALSE(msg->CheckDataHash({}, 0));
    REQUIRE_FALSE(msg->CheckDataHash({0, 0, 0}, 100));
    auto data = pdf.getRawData(0);
    for (int i = 0; i < msg->GetSignersCount(); ++i) {
      REQUIRE(msg->CheckDataHash(data, i));
    }
  }
}

TEST_CASE("ComputedHash") {
  std::string fwin = test_file_dir;
  fwin += file_win;
  pdfcsp::pdf::Pdf pdf;
  pdfcsp::csp::Csp csp;
  PtrMsg msg;
  REQUIRE_NOTHROW(pdf.Open(fwin));
  REQUIRE_NOTHROW(pdf.FindSignatures());
  REQUIRE_NOTHROW(msg = csp.OpenDetached(pdf.getRawSignature(0)));
  SECTION("COMPUTED_HASH") {
    auto calculated_comp_hash = msg->CalculateComputedHash(0);
    REQUIRE(calculated_comp_hash.has_value());
    auto computed_hash_from_sig = msg->GetComputedHash(0);
    REQUIRE(computed_hash_from_sig.has_value());
    REQUIRE(computed_hash_from_sig.value() ==
            calculated_comp_hash.value().GetValue());
  }
}

TEST_CASE("CertHash") {
  std::string fwin = test_file_dir;
  fwin += file_win;
  pdfcsp::pdf::Pdf pdf;
  pdfcsp::csp::Csp csp;
  PtrMsg msg;
  REQUIRE_NOTHROW(pdf.Open(fwin));
  REQUIRE_NOTHROW(pdf.FindSignatures());
  REQUIRE_NOTHROW(msg = csp.OpenDetached(pdf.getRawSignature(0)));
  SECTION("CertHash") {
    auto cert_hash = msg->CalculateCertHash(0);
    REQUIRE(cert_hash.has_value());
    auto cert_id = msg->GetSignerCertId(0);
    REQUIRE(cert_id.has_value());
    REQUIRE(cert_hash->GetValue() == cert_id->hash_cert);
    REQUIRE(msg->CheckCertificateHash(0));
  }
}

TEST_CASE("Global check") {
  std::string fwin = test_file_dir;
  fwin += file_win;
  pdfcsp::pdf::Pdf pdf;
  pdfcsp::csp::Csp csp;
  PtrMsg msg;
  REQUIRE_NOTHROW(pdf.Open(fwin));
  REQUIRE_NOTHROW(pdf.FindSignatures());
  REQUIRE_NOTHROW(msg = csp.OpenDetached(pdf.getRawSignature(0)));
  REQUIRE(msg->Check(pdf.getRawData(0), 0, true));
  REQUIRE_FALSE(msg->Check(pdf.getRawData(0), 100, true));
}
