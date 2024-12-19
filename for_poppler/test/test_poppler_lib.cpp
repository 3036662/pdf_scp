/* File: test_poppler_lib.cpp  
Copyright (C) Basealt LLC,  2024
Author: Oleg Proskurin, <proskurinov@basealt.ru>

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with this program; if not, write to the Free Software Foundation,
Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/


#include "csppdf.hpp"
#include "structs.hpp"
#define CATCH_CONFIG_MAIN
#include "csp_for_poppl.hpp"
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
  file += "31_cades-t-sign_iecp_task146042.pdf";
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
  REQUIRE(es_info.cert_info.cert_validity.notAfter == 1755164698);
  REQUIRE(es_info.cert_info.cert_validity.notBefore == 1723628040);
  REQUIRE(es_info.cert_info.cert_serial == "01daee2d30b79e900007f449381d0002");
  REQUIRE(es_info.cert_info.keyLocation == KeyLocation::Unknown);
  REQUIRE(es_info.signer_name == "Обухов Никита Сергеевич");
  REQUIRE(es_info.signer_subject_dn ==
          "ИНН=400905413358, CN=Обухов Никита Сергеевич, SNILS=17204947363");
  REQUIRE(es_info.hash_algorithm == HashAlgorithm::GOST_R3411_12_256);
  REQUIRE(es_info.signing_time == 1727854052);
  REQUIRE(es_info.signature.size() == 64);
  REQUIRE(es_info.cert_info.subject_info.email == "nickfang15@gmail.com");
  REQUIRE(es_info.cert_info.subject_info.organization == "");
  REQUIRE(es_info.cert_info.subject_info.distinguishedName ==
          "ИНН=400905413358, CN=Обухов Никита Сергеевич, SNILS=17204947363");
  std::cout << es_info.cert_info.issuer_info.distinguishedName << "\n";
  REQUIRE(
      es_info.cert_info.issuer_info.distinguishedName ==
      "ОРГН=1105260001175, ИНН=5260270696, STREET=улица Нижняя Красносельская, "
      "дом 40/12, корпус 20, C=RU, S=77 г. Москва, L=г. Москва, O=Акционерное "
      "общество \"Аналитический Центр\", CN=АО \"Аналитический Центр\"");
  REQUIRE(es_info.cert_info.cert_version == 2);
  REQUIRE(es_info.cert_info.ku_extensions == 240);
  REQUIRE(es_info.cert_info.cert_der.size() == 2053);
}