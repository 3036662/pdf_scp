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
#include <string>
#include <utils.hpp>

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

using namespace pdfcsp::csp;
using namespace pdfcsp::csp::asn;

constexpr const char *const test_file_dir = TEST_FILES_DIR;
const std::string test_dir = std::string(test_file_dir) + "valid_files/";

void Test(const std::string &file, CadesType cad_type) {
  std::cout << "File: " << file << "\n";
  pdfcsp::pdf::Pdf pdf;
  pdfcsp::csp::Csp csp;
  PtrMsg msg;
  REQUIRE_NOTHROW(pdf.Open(file));
  REQUIRE_NOTHROW(pdf.FindSignatures());
  for (uint i = 0; i < pdf.GetSignaturesCount(); ++i) {
    std::cout << "\nTest signature " << i + 1 << " of "
              << pdf.GetSignaturesCount() << "\n";
    REQUIRE_NOTHROW(msg = csp.OpenDetached(pdf.getRawSignature(i)));
    std::ofstream outp_file(
        "08_cam_CADEST_signers_free_area_plus_sign_not_in_signer.dat" +
            std::to_string(i),
        std::ios_base::binary);

    for (const auto ch : pdf.getRawSignature(i)) {
      outp_file << ch;
    }
    outp_file.close();
    REQUIRE(msg);
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
      REQUIRE(msg->GetCadesTypeEx(signer_index) == cad_type);
      std::cout << "Type:"
                << InternalCadesTypeToString(msg->GetCadesTypeEx(signer_index))
                << "\n";
      REQUIRE(msg->Check(pdf.getRawData(i), signer_index, true));
    }
  }
}

TEST_CASE("UnparseARM") {
  const std::string file = test_dir + "02_cam_BES.pdf";
  Test(file, pdfcsp::csp::CadesType::kCadesBes);
}

TEST_CASE("BES1") {

  SECTION("01_okular") {
    const std::string file = test_dir + "01_okular_BES.pdf";
    Test(file, pdfcsp::csp::CadesType::kCadesBes);
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
    REQUIRE_NOTHROW(pdf.FindSignatures());
    for (uint i = 0; i < pdf.GetSignaturesCount(); ++i) {
      std::cout << "\nTest signature " << i + 1 << " of "
                << pdf.GetSignaturesCount() << "\n";
      REQUIRE_NOTHROW(msg = csp.OpenDetached(pdf.getRawSignature(i)));
      std::ofstream outp_file("02_cam_BES.dat" + std::to_string(i),
                              std::ios_base::binary);
      for (const auto ch : pdf.getRawSignature(i)) {
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
                  << InternalCadesTypeToString(
                         msg->GetCadesTypeEx(signer_index))
                  << "\n";
        REQUIRE(msg->Check(pdf.getRawData(i), signer_index, true));
      }
    }
  }
}

TEST_CASE("BES3") {
  SECTION("03_cam_BES_signers_free_area") {
    const std::string file = test_dir + "03_cam_BES_signers_free_area.pdf";
    Test(file, pdfcsp::csp::CadesType::kCadesBes);
  }
  SECTION("Bad data") {
    const std::string file = test_dir + "03_cam_BES_signers_free_area.pdf";
    std::cout << "File: " << file << "\n";
    pdfcsp::pdf::Pdf pdf;
    pdfcsp::csp::Csp csp;
    PtrMsg msg;
    REQUIRE_NOTHROW(pdf.Open(file));
    REQUIRE_NOTHROW(pdf.FindSignatures());
    for (uint i = 0; i < pdf.GetSignaturesCount(); ++i) {
      std::cout << "\nTest signature " << i + 1 << " of "
                << pdf.GetSignaturesCount() << "\n";
      BytesVector bad_data = pdf.getRawData(i);
      bad_data[100] = 0xff;
      REQUIRE_NOTHROW(msg = csp.OpenDetached(pdf.getRawSignature(i)));
      REQUIRE_FALSE(msg->Check(bad_data, 0, false));
    }
  }
}

TEST_CASE("BES4") {
  SECTION("04_cam_BES_signers_free_area_signed_BES") {
    const std::string file =
        test_dir + "04_cam_BES_signers_free_area_signed_BES.pdf";
    Test(file, pdfcsp::csp::CadesType::kCadesBes);
  }
}

TEST_CASE("BES5") {
  SECTION("05_acrob_BES") {
    const std::string file = test_dir + "05_acrob_BES.pdf";
    Test(file, pdfcsp::csp::CadesType::kCadesBes);
  }
  SECTION("Bad data") {
    const std::string file = test_dir + "05_acrob_BES.pdf";
    std::cout << "File: " << file << "\n";
    pdfcsp::pdf::Pdf pdf;
    pdfcsp::csp::Csp csp;
    PtrMsg msg;
    REQUIRE_NOTHROW(pdf.Open(file));
    REQUIRE_NOTHROW(pdf.FindSignatures());
    for (uint i = 0; i < pdf.GetSignaturesCount(); ++i) {
      std::cout << "\nTest signature " << i + 1 << " of "
                << pdf.GetSignaturesCount() << "\n";
      BytesVector bad_data = pdf.getRawData(i);
      bad_data[100] = 0xff;
      REQUIRE_NOTHROW(msg = csp.OpenDetached(pdf.getRawSignature(i)));
      REQUIRE_FALSE(msg->Check(bad_data, 0, false));
    }
  }
  SECTION("Bad signature") {
    const std::string file = test_dir + "05_acrob_BES.pdf";
    std::cout << "File: " << file << "\n";
    pdfcsp::pdf::Pdf pdf;
    pdfcsp::csp::Csp csp;
    PtrMsg msg;
    REQUIRE_NOTHROW(pdf.Open(file));
    REQUIRE_NOTHROW(pdf.FindSignatures());
    for (uint i = 0; i < pdf.GetSignaturesCount(); ++i) {
      std::cout << "\nTest signature " << i + 1 << " of "
                << pdf.GetSignaturesCount() << "\n";
      BytesVector bad_sig = pdf.getRawSignature(i);
      bad_sig[100] = 0xff;
      REQUIRE_NOTHROW(msg = csp.OpenDetached(bad_sig));
      REQUIRE_FALSE(msg->Check(pdf.getRawData(i), 0, false));
    }
  }
}

TEST_CASE("T06") {
  SECTION("06_cam_CADEST_signers_free_area") {
    const std::string file = test_dir + "06_cam_CADEST_signers_free_area.pdf";
    Test(file, pdfcsp::csp::CadesType::kCadesT);
  }
}

TEST_CASE("T07") {
  SECTION("07_acrob_CADEST") {
    const std::string file = test_dir + "07_acrob_CADEST.pdf";
    Test(file, pdfcsp::csp::CadesType::kCadesT);
  }
}

TEST_CASE("T08") {
  SECTION("08_cam_CADEST_signers_free_area_plus_sign_not_in_signer") {
    const std::string file =
        test_dir +
        "08_cam_CADEST_signers_free_area_plus_sign_not_in_signer.pdf";
    Test(file, pdfcsp::csp::CadesType::kCadesT);
  }
}