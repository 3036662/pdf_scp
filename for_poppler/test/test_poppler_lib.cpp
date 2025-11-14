/* File: test_poppler_lib.cpp
Copyright (C) Basealt LLC,  2025
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
#include <catch2/catch.hpp>

#include "csp_for_poppl.hpp"

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
  file += "41_pades-xlt1-itcom.pdf";
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
  REQUIRE(es_info.cert_info.cert_validity.notAfter == 1768049441);
  REQUIRE(es_info.cert_info.cert_validity.notBefore == 1728564041);
  REQUIRE(es_info.cert_info.cert_serial == "4cd509880002000832b2");
  REQUIRE(es_info.cert_info.keyLocation == KeyLocation::Unknown);
  REQUIRE(es_info.signer_name == "Обухов Никита Сергеевич");
  REQUIRE(
    es_info.signer_subject_dn ==
    "ИНН ФЛ=400905413358, C=RU, CN=Обухов Никита Сергеевич, SNILS=17204947363");
  REQUIRE(es_info.hash_algorithm == HashAlgorithm::GOST_R3411_12_256);
  REQUIRE(es_info.signing_time == 1729260622);
  REQUIRE(es_info.signature.size() == 64);
  REQUIRE(es_info.cert_info.subject_info.email == "nickf@basealt.ru");
  REQUIRE(es_info.cert_info.subject_info.organization == "");
  REQUIRE(
    es_info.cert_info.subject_info.distinguishedName ==
    "ИНН ФЛ=400905413358, C=RU, CN=Обухов Никита Сергеевич, SNILS=17204947363");
  std::cout << es_info.cert_info.issuer_info.distinguishedName << "\n";
  REQUIRE(
    es_info.cert_info.issuer_info.distinguishedName ==
    "ОРГН=1167746840843, ИНН ЮЛ=7714407563, STREET=ВН.ТЕР.Г. МУНИЦИПАЛЬНЫЙ "
    "ОКРУГ АЛЕКСЕЕВСКИЙ, УЛ ЯРОСЛАВСКАЯ, Д. 13А, СТР. 1, ПОМЕЩ. 6, C=RU, S=77 "
    "г. Москва, L=Москва, O=ООО \"АйтиКом\", CN=ООО \"АйтиКом\"");
  REQUIRE(es_info.cert_info.cert_version == 2);
  REQUIRE(es_info.cert_info.ku_extensions == 240);
  REQUIRE(es_info.cert_info.cert_der.size() == 2098);
}