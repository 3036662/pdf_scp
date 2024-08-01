#include "asn1.hpp"
#include "csp.hpp"
#include "message.hpp"
#include "pdf.hpp"
#include "resolve_symbols.hpp"
#include <cstdint>
#include <fstream>
#include <ios>
#include <memory>
#include <utils.hpp>

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

using namespace pdfcsp::csp;

constexpr const char *const test_file_dir = TEST_FILES_DIR;
const std::string test_dir = std::string(test_file_dir) + "valid_files/";

TEST_CASE("UnparseARM") {
  const std::string file = test_dir + "02_cam_BES.pdf";
  std::cout << "File: " << file << "\n";
  pdfcsp::pdf::Pdf pdf;
  pdfcsp::csp::Csp csp;
  PtrMsg msg;
  REQUIRE_NOTHROW(pdf.Open(file));
  REQUIRE_NOTHROW(pdf.FindSignature());
  AsnObj obj(pdf.getRawSignature().data(), pdf.getRawSignature().size(),
             std::make_shared<ResolvedSymbols>());
  auto unparsed = obj.Unparse();
  std::cout << "Initial size " << pdf.getRawSignature().size() << "\n";
  std::cout << "Unparsed size " << unparsed.size() << "\n";
  if (unparsed.size() < pdf.getRawSignature().size()) {
    unparsed.resize(pdf.getRawSignature().size(), 0x00);
  }
  REQUIRE(unparsed.size() == pdf.getRawSignature().size());
  REQUIRE(unparsed == pdf.getRawSignature());
}

TEST_CASE("BES1") {

  SECTION("01_okular") {
    const std::string file = test_dir + "01_okular_BES.pdf";
    std::cout << "File: " << file << "\n";
    pdfcsp::pdf::Pdf pdf;
    pdfcsp::csp::Csp csp;
    PtrMsg msg;
    REQUIRE_NOTHROW(pdf.Open(file));
    REQUIRE_NOTHROW(pdf.FindSignature());
    REQUIRE_NOTHROW(
        msg = csp.OpenDetached(pdf.getRawSignature(), pdf.getRawData()));
    REQUIRE(msg);
    REQUIRE(msg->GetCadesType() == CadesType::kCadesBes);
    std::cout << "Type:" << InternalCadesTypeToString(msg->GetCadesType())
              << "\n";
    auto signers = msg->GetSignersCount();
    REQUIRE(signers);
    REQUIRE(*signers > 0);
    std::cout << "Signers number " << signers.value_or(0) << "\n";
    auto revoces_count = msg->GetRevokedCertsCount();
    REQUIRE(revoces_count);
    std::cout << "Revoces number " << revoces_count.value() << "\n";
    for (uint signer_index = 0; signer_index < signers.value();
         ++signer_index) {
      REQUIRE(msg->CheckDataHash(pdf.getRawData(), signer_index));
      REQUIRE(msg->Check(pdf.getRawData(), signer_index, true));
    }
  }
}

TEST_CASE("BES2") {
  SECTION("02_cam_BES") {
    const std::string file = test_dir + "02_cam_BES.pdf";
    std::cout << "File: " << file << "\n";
    pdfcsp::pdf::Pdf pdf;
    pdfcsp::csp::Csp csp;
    PtrMsg msg;
    REQUIRE_NOTHROW(pdf.Open(file));
    REQUIRE_NOTHROW(pdf.FindSignature());
    REQUIRE_NOTHROW(
        msg = csp.OpenDetached(pdf.getRawSignature(), pdf.getRawData()));
    std::ofstream outp_file("02_cam_BES.dat", std::ios_base::binary);
    for (const auto ch : pdf.getRawSignature()) {
      outp_file << ch;
    }
    outp_file.close();
    REQUIRE(msg);
    REQUIRE(msg->GetCadesType() == CadesType::kCadesBes);
    std::cout << "Type:" << InternalCadesTypeToString(msg->GetCadesType())
              << "\n";
    auto signers = msg->GetSignersCount();
    REQUIRE(signers);
    REQUIRE(*signers > 0);
    std::cout << "Signers number " << signers.value_or(0) << "\n";
    auto revoces_count = msg->GetRevokedCertsCount();
    REQUIRE(revoces_count);
    std::cout << "Revoces number " << revoces_count.value() << "\n";
    for (uint signer_index = 0; signer_index < signers.value();
         ++signer_index) {
      // REQUIRE(msg->CheckDataHash(pdf.getRawData(), signer_index));
      REQUIRE(msg->Check(pdf.getRawData(), signer_index, true));
    }
  }
}