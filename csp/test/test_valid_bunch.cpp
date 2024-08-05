#include "asn1.hpp"
#include "csp.hpp"
#include "message.hpp"
#include "pdf.hpp"
#include "resolve_symbols.hpp"
#include "typedefs.hpp"
#include <cstdint>
#include <fstream>
#include <ios>
#include <memory>
#include <utils.hpp>

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

using namespace pdfcsp::csp;
using namespace pdfcsp::csp::asn;

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
    REQUIRE_NOTHROW(msg = csp.OpenDetached(pdf.getRawSignature()));
    REQUIRE(msg);
    REQUIRE(msg->GetCadesType() == CadesType::kCadesBes);
    auto signers = msg->GetSignersCount();
    REQUIRE(signers);
    REQUIRE(*signers > 0);
    std::cout << "Signers number " << signers.value_or(0) << "\n";
    auto revoces_count = msg->GetRevokedCertsCount();
    REQUIRE(revoces_count);
    std::cout << "Revoces number " << revoces_count.value() << "\n";
    for (uint signer_index = 0; signer_index < signers.value();
         ++signer_index) {
      REQUIRE(msg->GetCadesTypeEx(signer_index) == CadesType::kCadesBes);
      std::cout << "Type:"
                << InternalCadesTypeToString(msg->GetCadesTypeEx(signer_index))
                << "\n";
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
    REQUIRE_NOTHROW(msg = csp.OpenDetached(pdf.getRawSignature()));
    std::ofstream outp_file("02_cam_BES.dat", std::ios_base::binary);
    for (const auto ch : pdf.getRawSignature()) {
      outp_file << ch;
    }
    outp_file.close();
    REQUIRE(msg);
    REQUIRE(msg->GetCadesType() == CadesType::kCadesBes);
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
      REQUIRE(msg->GetCadesTypeEx(signer_index) == CadesType::kCadesBes);
      std::cout << "Type:"
                << InternalCadesTypeToString(msg->GetCadesTypeEx(signer_index))
                << "\n";
      REQUIRE(msg->Check(pdf.getRawData(), signer_index, true));
    }
  }
}

TEST_CASE("BES3") {
  SECTION("03_cam_BES_signers_free_area") {
    const std::string file = test_dir + "03_cam_BES_signers_free_area.pdf";
    std::cout << "File: " << file << "\n";
    pdfcsp::pdf::Pdf pdf;
    pdfcsp::csp::Csp csp;
    PtrMsg msg;
    REQUIRE_NOTHROW(pdf.Open(file));
    REQUIRE_NOTHROW(pdf.FindSignature());
    REQUIRE_NOTHROW(msg = csp.OpenDetached(pdf.getRawSignature()));
    std::ofstream outp_file("03_cam_BES_signers_free_area.dat",
                            std::ios_base::binary);
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
      REQUIRE(msg->GetCadesTypeEx(signer_index) == CadesType::kCadesBes);
      std::cout << "Type:"
                << InternalCadesTypeToString(msg->GetCadesTypeEx(signer_index))
                << "\n";
      REQUIRE(msg->Check(pdf.getRawData(), signer_index, true));
    }
  }
  SECTION("Bad data") {
    const std::string file = test_dir + "03_cam_BES_signers_free_area.pdf";
    std::cout << "File: " << file << "\n";
    pdfcsp::pdf::Pdf pdf;
    pdfcsp::csp::Csp csp;
    PtrMsg msg;
    REQUIRE_NOTHROW(pdf.Open(file));
    REQUIRE_NOTHROW(pdf.FindSignature());
    BytesVector bad_data = pdf.getRawData();
    bad_data[100] = 0xff;
    REQUIRE_NOTHROW(msg = csp.OpenDetached(pdf.getRawSignature()));
    REQUIRE_FALSE(msg->Check(bad_data, 0, false));
  }
}

TEST_CASE("BES4") {
  SECTION("04_cam_BES_signers_free_area_signed_BES") {
    const std::string file =
        test_dir + "04_cam_BES_signers_free_area_signed_BES.pdf";
    std::cout << "File: " << file << "\n";
    pdfcsp::pdf::Pdf pdf;
    pdfcsp::csp::Csp csp;
    PtrMsg msg;
    REQUIRE_NOTHROW(pdf.Open(file));
    REQUIRE_NOTHROW(pdf.FindSignature());
    REQUIRE_NOTHROW(msg = csp.OpenDetached(pdf.getRawSignature()));
    std::ofstream outp_file("04_cam_BES_signers_free_area_signed_BES.dat",
                            std::ios_base::binary);
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
      REQUIRE(msg->GetCadesTypeEx(signer_index) == CadesType::kCadesBes);
      std::cout << "Type:"
                << InternalCadesTypeToString(msg->GetCadesTypeEx(signer_index))
                << "\n";
      REQUIRE(msg->Check(pdf.getRawData(), signer_index, true));
    }
  }
}

TEST_CASE("BES5") {
  SECTION("05_acrob_BES") {
    const std::string file = test_dir + "05_acrob_BES.pdf";
    std::cout << "File: " << file << "\n";
    pdfcsp::pdf::Pdf pdf;
    pdfcsp::csp::Csp csp;
    PtrMsg msg;
    REQUIRE_NOTHROW(pdf.Open(file));
    REQUIRE_NOTHROW(pdf.FindSignature());
    REQUIRE_NOTHROW(msg = csp.OpenDetached(pdf.getRawSignature()));
    std::ofstream outp_file("05_acrob_BES.dat", std::ios_base::binary);
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
      REQUIRE(msg->GetCadesTypeEx(signer_index) == CadesType::kCadesBes);
      std::cout << "Type:"
                << InternalCadesTypeToString(msg->GetCadesTypeEx(signer_index))
                << "\n";
      REQUIRE(msg->Check(pdf.getRawData(), signer_index, true));
    }
  }
  SECTION("Bad data") {
    const std::string file = test_dir + "05_acrob_BES.pdf";
    std::cout << "File: " << file << "\n";
    pdfcsp::pdf::Pdf pdf;
    pdfcsp::csp::Csp csp;
    PtrMsg msg;
    REQUIRE_NOTHROW(pdf.Open(file));
    REQUIRE_NOTHROW(pdf.FindSignature());
    BytesVector bad_data = pdf.getRawData();
    bad_data[100] = 0xff;
    REQUIRE_NOTHROW(msg = csp.OpenDetached(pdf.getRawSignature()));
    REQUIRE_FALSE(msg->Check(bad_data, 0, false));
  }
  SECTION("Bad signature") {
    const std::string file = test_dir + "05_acrob_BES.pdf";
    std::cout << "File: " << file << "\n";
    pdfcsp::pdf::Pdf pdf;
    pdfcsp::csp::Csp csp;
    PtrMsg msg;
    REQUIRE_NOTHROW(pdf.Open(file));
    REQUIRE_NOTHROW(pdf.FindSignature());
    BytesVector bad_sig = pdf.getRawSignature();
    bad_sig[100] = 0xff;
    REQUIRE_NOTHROW(msg = csp.OpenDetached(bad_sig));
    REQUIRE_FALSE(msg->Check(pdf.getRawData(), 0, false));
  }
}

TEST_CASE("T06") {
  SECTION("06_cam_CADEST_signers_free_area") {
    const std::string file = test_dir + "06_cam_CADEST_signers_free_area.pdf";
    std::cout << "File: " << file << "\n";
    pdfcsp::pdf::Pdf pdf;
    pdfcsp::csp::Csp csp;
    PtrMsg msg;
    REQUIRE_NOTHROW(pdf.Open(file));
    REQUIRE_NOTHROW(pdf.FindSignature());
    REQUIRE_NOTHROW(msg = csp.OpenDetached(pdf.getRawSignature()));
    std::ofstream outp_file("06_cam_CADEST_signers_free_area.dat",
                            std::ios_base::binary);
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
      REQUIRE(msg->GetCadesTypeEx(signer_index) == CadesType::kCadesT);
      std::cout << "Type:"
                << InternalCadesTypeToString(msg->GetCadesTypeEx(signer_index))
                << "\n";
      REQUIRE(msg->Check(pdf.getRawData(), signer_index, true));
    }
  }
}

TEST_CASE("T07") {
  SECTION("07_acrob_CADEST") {
    const std::string file = test_dir + "07_acrob_CADEST.pdf";
    std::cout << "File: " << file << "\n";
    pdfcsp::pdf::Pdf pdf;
    pdfcsp::csp::Csp csp;
    PtrMsg msg;
    REQUIRE_NOTHROW(pdf.Open(file));
    REQUIRE_NOTHROW(pdf.FindSignature());
    REQUIRE_NOTHROW(msg = csp.OpenDetached(pdf.getRawSignature()));
    std::ofstream outp_file("07_acrob_CADEST.dat", std::ios_base::binary);
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
      REQUIRE(msg->GetCadesTypeEx(signer_index) == CadesType::kCadesT);
      std::cout << "Type:"
                << InternalCadesTypeToString(msg->GetCadesTypeEx(signer_index))
                << "\n";
      REQUIRE(msg->Check(pdf.getRawData(), signer_index, true));
    }
  }
}