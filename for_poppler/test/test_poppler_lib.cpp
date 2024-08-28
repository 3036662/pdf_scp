#include "structs.hpp"
#define CATCH_CONFIG_MAIN
#include "c_interface.hpp"
#include "pdf.hpp"
#include <catch2/catch.hpp>

constexpr const char *const test_file_dir = TEST_FILES_DIR;
const std::string test_dir = std::string(test_file_dir) + "valid_files/";

using namespace pdfcsp::poppler;

void PrintBytes(const BytesVector &val) noexcept {
  for (const auto &symbol : val) {
    std::cout << std::hex << std::setw(2) << static_cast<int>(symbol) << " ";
  }
  std::cout << "\n";
}

TEST_CASE("1") {

  pdfcsp::pdf::Pdf pdf;
  std::string file(test_dir);
  file += "13_cam_CADES-XLT1_1sig.pdf";
  REQUIRE_NOTHROW(pdf.Open(file));
  REQUIRE_NOTHROW(pdf.FindSignatures());
  REQUIRE(pdf.GetSignaturesCount() > 0);
  auto branges = pdf.getSigByteRanges(0);
  REQUIRE_FALSE(branges.empty());
  auto raw_signature = pdf.getRawSignature(0);

  // call popplerlib
  REQUIRE_FALSE(raw_signature.empty());
  pdfcsp::poppler::ESInfo es_info =
      pdfcsp::poppler::CheckES(branges, raw_signature, file);

  REQUIRE(es_info.signature_val_status == SigStatus::Valid);
  REQUIRE(es_info.certificate_val_status == CertStatus::Trusted);
  REQUIRE(es_info.cert_info.cert_validity.notAfter == 1725433177);
  REQUIRE(es_info.cert_info.cert_validity.notBefore == 1720612763);
  REQUIRE(es_info.cert_info.cert_serial ==
          "7c00158a3ff6a9424bf01936ef000800158a3f");
  REQUIRE(es_info.cert_info.cert_version == 0);
  REQUIRE(es_info.cert_info.keyLocation == KeyLocation::Unknown);
  REQUIRE(es_info.signer_name == "Test Certificate");
  REQUIRE(es_info.signer_subject_dn == "CN=Test Certificate");
  REQUIRE(es_info.hash_algorithm == HashAlgorithm::GOST_R3411_12_256);
  REQUIRE(es_info.signing_time == 1721136306);
  REQUIRE(es_info.signature.size() == 64);
}