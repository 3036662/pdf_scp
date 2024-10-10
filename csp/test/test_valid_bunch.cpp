#include "altcsp.hpp"
#include "asn1.hpp"
#include "check_result.hpp"
#include "csppdf.hpp"
#include "message.hpp"
#include "resolve_symbols.hpp"
#include "typedefs.hpp"
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <ios>
#include <memory>
#include <string>
#include <utils.hpp>
#include <utils_msg.hpp>

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

using namespace pdfcsp::csp;
using namespace pdfcsp::csp::asn;
using namespace pdfcsp::csp::utils::message;

constexpr const char *const test_file_dir = TEST_FILES_DIR;
const std::string test_dir = std::string(test_file_dir) + "valid_files/";

void Test(const std::string &file, CadesType cad_type,
          uint signatures_expected) {
  std::cout << "File: " << file << "\n";
  pdfcsp::pdf::Pdf pdf;
  pdfcsp::csp::Csp csp;
  PtrMsg msg;
  REQUIRE_NOTHROW(pdf.Open(file));
  REQUIRE_NOTHROW(pdf.FindSignatures());
  REQUIRE(signatures_expected == pdf.GetSignaturesCount());
  for (uint i = 0; i < pdf.GetSignaturesCount(); ++i) {
    std::cout << "\nTest signature " << i + 1 << " of "
              << pdf.GetSignaturesCount() << "\n";
    REQUIRE_NOTHROW(msg = csp.OpenDetached(pdf.getRawSignature(i)));
    auto path = std::filesystem::path(file).filename().replace_extension();

    std::ofstream outp_file(path.string() + std::to_string(i) + ".sig",
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
      std::cout << "Type:"
                << InternalCadesTypeToString(msg->GetCadesTypeEx(signer_index))
                << "\n";
      REQUIRE(msg->GetCadesTypeEx(signer_index) == cad_type);

      // REQUIRE(msg->Check(pdf.getRawData(i), signer_index, true));
      auto check_result =
          msg->ComprehensiveCheck(pdf.getRawData(i), signer_index, true);
      REQUIRE(check_result.bres.check_summary);
      std::cout << check_result.Str();
      PrintBytes(check_result.cert_serial);
    }
  }
}

void TestRevoced(const std::string &file, CadesType cad_type,
                 uint signatures_expected) {
  std::cout << "File: " << file << "\n";
  pdfcsp::pdf::Pdf pdf;
  pdfcsp::csp::Csp csp;
  PtrMsg msg;
  REQUIRE_NOTHROW(pdf.Open(file));
  REQUIRE_NOTHROW(pdf.FindSignatures());
  REQUIRE(signatures_expected == pdf.GetSignaturesCount());
  for (uint i = 0; i < pdf.GetSignaturesCount(); ++i) {
    std::cout << "\nTest signature " << i + 1 << " of "
              << pdf.GetSignaturesCount() << "\n";
    REQUIRE_NOTHROW(msg = csp.OpenDetached(pdf.getRawSignature(i)));
    auto path = std::filesystem::path(file).filename().replace_extension();

    std::ofstream outp_file(path.string() + std::to_string(i) + ".sig",
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
      std::cout << "Type:"
                << InternalCadesTypeToString(msg->GetCadesTypeEx(signer_index))
                << "\n";
      REQUIRE(msg->GetCadesTypeEx(signer_index) == cad_type);

      // REQUIRE(msg->Check(pdf.getRawData(i), signer_index, true));
      auto check_result =
          msg->ComprehensiveCheck(pdf.getRawData(i), signer_index, true);
      std::cout << check_result.Str();
      REQUIRE_FALSE(check_result.bres.certificate_chain_ok);
      REQUIRE_FALSE(check_result.bres.certificate_ocsp_ok);
      REQUIRE_FALSE(check_result.bres.certificate_ocsp_check_failed);
      REQUIRE_FALSE(check_result.bres.certificate_ok);
      REQUIRE_FALSE(check_result.bres.bes_all_ok);
      REQUIRE_FALSE(check_result.bres.check_summary);
    }
  }
}

void TestExpiredCert(const std::string &file, CadesType cad_type,
                     uint signatures_expected) {
  std::cout << "File: " << file << "\n";
  pdfcsp::pdf::Pdf pdf;
  pdfcsp::csp::Csp csp;
  PtrMsg msg;
  REQUIRE_NOTHROW(pdf.Open(file));
  REQUIRE_NOTHROW(pdf.FindSignatures());
  REQUIRE(signatures_expected == pdf.GetSignaturesCount());
  for (uint i = 0; i < pdf.GetSignaturesCount(); ++i) {
    std::cout << "\nTest signature " << i + 1 << " of "
              << pdf.GetSignaturesCount() << "\n";
    REQUIRE_NOTHROW(msg = csp.OpenDetached(pdf.getRawSignature(i)));
    auto path = std::filesystem::path(file).filename().replace_extension();

    std::ofstream outp_file(path.string() + std::to_string(i) + ".sig",
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
      std::cout << "Type:"
                << InternalCadesTypeToString(msg->GetCadesTypeEx(signer_index))
                << "\n";
      REQUIRE(msg->GetCadesTypeEx(signer_index) == cad_type);

      // REQUIRE(msg->Check(pdf.getRawData(i), signer_index, true));
      auto check_result =
          msg->ComprehensiveCheck(pdf.getRawData(i), signer_index, true);
      std::cout << check_result.Str() << "\n";
      REQUIRE_FALSE(check_result.bres.certificate_chain_ok);
      REQUIRE_FALSE(check_result.bres.certificate_ocsp_ok);
      REQUIRE_FALSE(check_result.bres.certificate_ocsp_check_failed);
      REQUIRE_FALSE(check_result.bres.certificate_ok);
      REQUIRE_FALSE(check_result.bres.bes_all_ok);
      REQUIRE_FALSE(check_result.bres.check_summary);
      std::cout << "now = "
                << std::chrono::system_clock::to_time_t(
                       std::chrono::system_clock::now())
                << "\n";
      std::cout << "the certificate expired at " << check_result.cert_not_after
                << "\n";
    }
  }
}

TEST_CASE("UnparseARM") {
  const std::string file = test_dir + "02_cam_BES.pdf";
  pdfcsp::pdf::Pdf pdf;
  pdfcsp::csp::Csp csp;
  PtrMsg msg;
  REQUIRE_NOTHROW(pdf.Open(file));
  REQUIRE_NOTHROW(pdf.FindSignatures());
  REQUIRE(1 == pdf.GetSignaturesCount());
  auto raw_signature = pdf.getRawSignature(0);
  AsnObj obj(raw_signature.data(), raw_signature.size());
  auto unparsed = obj.Unparse();
  if (std::all_of(raw_signature.cbegin() + unparsed.size(),
                  raw_signature.cend(),
                  [](const unsigned char c) { return c == 0x00; })) {
    raw_signature.resize(unparsed.size());
  }

  REQUIRE(raw_signature.size() == obj.Unparse().size());
}

TEST_CASE("BES1") {

  SECTION("01_okular") {
    const std::string file = test_dir + "01_okular_BES.pdf";
    TestExpiredCert(file, pdfcsp::csp::CadesType::kCadesBes, 1);
  }
}

TEST_CASE("BES2") {
  SECTION("02_cam_BES") {
    const std::string file = test_dir + "02_cam_BES.pdf";
    TestExpiredCert(file, pdfcsp::csp::CadesType::kCadesBes, 1);
  }
}

TEST_CASE("BES3") {
  SECTION("03_cam_BES_signers_free_area") {
    const std::string file = test_dir + "03_cam_BES_signers_free_area.pdf";
    TestExpiredCert(file, pdfcsp::csp::CadesType::kCadesBes, 1);
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
    TestExpiredCert(file, pdfcsp::csp::CadesType::kCadesBes, 2);
  }
}

TEST_CASE("BES5") {
  SECTION("05_acrob_BES") {
    const std::string file = test_dir + "05_acrob_BES.pdf";
    TestExpiredCert(file, pdfcsp::csp::CadesType::kCadesBes, 1);
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

TEST_CASE("T6") {
  SECTION("06_cam_CADEST_signers_free_area") {
    const std::string file = test_dir + "06_cam_CADEST_signers_free_area.pdf";
    TestExpiredCert(file, pdfcsp::csp::CadesType::kCadesT, 1);
  }
}

TEST_CASE("T7") {
  SECTION("07_acrob_CADEST") {
    const std::string file = test_dir + "07_acrob_CADEST.pdf";
    TestExpiredCert(file, pdfcsp::csp::CadesType::kCadesT, 1);
  }
}

TEST_CASE("T8") {
  SECTION("08_cam_CADEST_signers_free_area_plus_sign_not_in_signer") {
    const std::string file =
        test_dir +
        "08_cam_CADEST_signers_free_area_plus_sign_not_in_signer.pdf";
    TestExpiredCert(file, pdfcsp::csp::CadesType::kCadesT, 3);
  }
}

TEST_CASE("T9") {
  SECTION("09_cam_CADEST") {
    const std::string file = test_dir + "09_cam_CADEST.pdf";
    TestExpiredCert(file, pdfcsp::csp::CadesType::kCadesT, 1);
  }
}

TEST_CASE("T10") {
  SECTION("10_cam_CADEST_signers_free_area_signedCadesT_plus_cadesT") {
    const std::string file =
        test_dir +
        "10_cam_CADEST_signers_free_area_signedCadesT_plus_cadesT.pdf";
    TestExpiredCert(file, pdfcsp::csp::CadesType::kCadesT, 3);
  }
}

TEST_CASE("T11") {
  SECTION("11_cam_CADEST_singers_free_area_plus_signedCADEST") {
    const std::string file =
        test_dir + "11_cam_CADEST_singers_free_area_plus_signedCADEST.pdf";
    TestExpiredCert(file, pdfcsp::csp::CadesType::kCadesT, 2);
  }
}

TEST_CASE("T12") {
  SECTION("12_cam_NULL") {
    const std::string file = test_dir + "12_cam_NULL.pdf";
    Test(file, pdfcsp::csp::CadesType::kUnknown, 0);
  }
}

TEST_CASE("X13") {
  SECTION("13_cam_CADES-XLT1_1sig") {
    const std::string file = test_dir + "13_cam_CADES-XLT1_1sig.pdf";
    Test(file, pdfcsp::csp::CadesType::kCadesXLong1, 1);
  }
}

TEST_CASE("X14") {
  SECTION("14_cam_CADES-XLT1_1sig") {
    const std::string file = test_dir + "14_acrob_CADES-XLT1.pdf";
    Test(file, pdfcsp::csp::CadesType::kCadesXLong1, 1);
  }
}

TEST_CASE("15") {
  SECTION("15_fns_1.pdf") {
    const std::string file = test_dir + "15_fns_1.pdf";
    Test(file, pdfcsp::csp::CadesType::kPkcs7, 1);
  }
}

TEST_CASE("REV16") {
  SECTION("16_Document_АРМ_BES_revoced.pdf") {
    const std::string file = test_dir + "16_Document_АРМ_BES_revoced.pdf";
    TestRevoced(file, pdfcsp::csp::CadesType::kCadesBes, 1);
  }
}

TEST_CASE("REV17") {
  SECTION("17_acr_XLT1_revoced.pdf") {
    const std::string file = test_dir + "17_acr_XLT1_revoced.pdf";
    Test(file, pdfcsp::csp::CadesType::kCadesXLong1, 1);
  }
}

TEST_CASE("REV18") {
  SECTION("18_carm_T_revoced.pdf") {
    const std::string file = test_dir + "18_carm_T_revoced.pdf";
    TestRevoced(file, pdfcsp::csp::CadesType::kCadesT, 1);
  }
}

TEST_CASE("REV19") {
  SECTION("19_carm_xlt_revoced.pdf") {
    const std::string file = test_dir + "19_carm_xlt_revoced.pdf";
    Test(file, pdfcsp::csp::CadesType::kCadesXLong1, 1);
  }
}

TEST_CASE("REV20") {
  SECTION("20_acrob_T_revoced.pdf") {
    const std::string file = test_dir + "20_acrob_T_revoced.pdf";
    TestRevoced(file, pdfcsp::csp::CadesType::kCadesT, 1);
  }
}

TEST_CASE("X21") {
  SECTION("21_cam_CADES-XLT1_5signs.pdf") {
    const std::string file = test_dir + "21_cam_CADES-XLT1_5signs.pdf";
    Test(file, pdfcsp::csp::CadesType::kCadesXLong1, 5);
  }
}

TEST_CASE("X22") {
  SECTION("22_carm-XLT1_plusT_free_area.pdf") {
    const std::string file = test_dir + "22_carm-XLT1_plusT_free_area.pdf";
    Test(file, pdfcsp::csp::CadesType::kCadesXLong1, 3);
  }
}

TEST_CASE("X23") {
  SECTION("23_cam-XLT1_4signs.pdf") {
    const std::string file = test_dir + "23_cam-XLT1_4signs.pdf";
    Test(file, pdfcsp::csp::CadesType::kCadesXLong1, 4);
  }
}

TEST_CASE("X24") {
  SECTION("24_cam_XLT1_free_space.pdf") {
    const std::string file = test_dir + "24_cam_XLT1_free_space.pdf";
    Test(file, pdfcsp::csp::CadesType::kCadesXLong1, 1);
  }
}

TEST_CASE("A25") {
  SECTION("25_cam_CADES-A.pdf") {
    const std::string file = test_dir + "25_cam_CADES-A.pdf";
    Test(file, pdfcsp::csp::CadesType::kCadesXLong1, 1);
  }
}

TEST_CASE("X26") {
  SECTION("26_cades-xlt1-sign_task146042.pdf") {
    const std::string file = test_dir + "26_cades-xlt1-sign_task146042.pdf";
    Test(file, pdfcsp::csp::CadesType::kCadesXLong1, 1);
  }
}

TEST_CASE("BES27") {
  SECTION("27_cades-bes-sign_task146042.pdf") {
    const std::string file = test_dir + "27_cades-bes-sign_task146042.pdf";
    Test(file, pdfcsp::csp::CadesType::kCadesBes, 1);
  }
}

TEST_CASE("T28") {
  SECTION("28_cades-t-sign_task146042.pdf") {
    const std::string file = test_dir + "28_cades-t-sign_task146042.pdf";
    Test(file, pdfcsp::csp::CadesType::kCadesT, 1);
  }
}

TEST_CASE("X29") {
  SECTION("29_cades-xlt1-sign_tax-gov_task146042.pdf") {
    const std::string file =
        test_dir + "29_cades-xlt1-sign_tax-gov_task146042.pdf";
    Test(file, pdfcsp::csp::CadesType::kCadesXLong1, 1);
  }
}

TEST_CASE("T30") {
  SECTION("30_cades-t-sign_tax-gov_task146042.pdf") {
    const std::string file =
        test_dir + "30_cades-t-sign_tax-gov_task146042.pdf";
    Test(file, pdfcsp::csp::CadesType::kCadesT, 1);
  }
}

TEST_CASE("T31") {
  SECTION("31_cades-t-sign_iecp_task146042.pdf") {
    const std::string file = test_dir + "31_cades-t-sign_iecp_task146042.pdf";
    Test(file, pdfcsp::csp::CadesType::kCadesT, 1);
  }
}

TEST_CASE("X32") {
  SECTION("32_cades-xlt1-sign_iecp_task146042.pdf") {
    const std::string file =
        test_dir + "32_cades-xlt1-sign_iecp_task146042.pdf";
    Test(file, pdfcsp::csp::CadesType::kCadesXLong1, 1);
  }
}

TEST_CASE("X33") {
  SECTION("33_cades-xlt1-sign_iecp_2_task146042.pdf") {
    const std::string file =
        test_dir + "33_cades-xlt1-sign_iecp_2_task146042.pdf";
    Test(file, pdfcsp::csp::CadesType::kCadesXLong1, 1);
  }
}

TEST_CASE("T34") {
  SECTION("34_cades-t-sign_iecp_2_task146042.pdf") {
    const std::string file = test_dir + "34_cades-t-sign_iecp_2_task146042.pdf";
    Test(file, pdfcsp::csp::CadesType::kCadesT, 1);
  }
}