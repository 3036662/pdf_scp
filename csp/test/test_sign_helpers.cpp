/* File: test_sign_helpers.cpp  
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



#include "hash_handler.hpp"
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Winvalid-utf8"
#include "resolve_symbols.hpp"
#pragma GCC diagnostic pop
#include "typedefs.hpp"
#include "utils_cert.hpp"
#include <array>
#include <boost/json/serialize.hpp>
#include <cstddef>
#include <fstream>
#include <iterator>
#include <memory>
#include <string>
#include <vector>
#define CATCH_CONFIG_MAIN
#include "altcsp.hpp"
#include <catch2/catch.hpp>
#include <utils.hpp>
#include <utils_msg.hpp>

using namespace pdfcsp::csp;
using namespace pdfcsp::csp::asn;
using namespace pdfcsp::csp::utils::message;

constexpr const char *const test_file_dir = TEST_FILES_DIR;
const std::string test_dir = std::string(test_file_dir) + "valid_files/";

TEST_CASE("CetList") {
  Csp csp;
  REQUIRE_NOTHROW(csp.GetCertList());
  auto cert_list = csp.GetCertList();
  REQUIRE_FALSE(cert_list.empty());
  auto js_array = utils::cert::CertListToJSONArray(cert_list);
  REQUIRE(js_array);
  REQUIRE_FALSE(js_array->empty());
  std::cout << boost::json::serialize(*js_array);
};

TEST_CASE("FindCertBySerial") {

  Csp csp;
  // find cert and private key
  auto cert = pdfcsp::csp::utils::cert::FindCertInUserStoreBySerial(
      "Test Certificate", "7c001710d43a522a13006a8c39000a001710d4",
      std::make_shared<ResolvedSymbols>());
  REQUIRE(cert);
  auto cert2 = pdfcsp::csp::utils::cert::FindCertInUserStoreBySerial(
      "Test Certificate", "7c0016b744e7a68ddba55a265f00090016b7445",
      std::make_shared<ResolvedSymbols>());
  REQUIRE_FALSE(cert2);
}

TEST_CASE("SignBes") {
  Csp csp;
  auto symbols = std::make_shared<ResolvedSymbols>();
  auto cert = pdfcsp::csp::utils::cert::FindCertInUserStoreBySerial(
      "Test Certificate", "7c001710d43a522a13006a8c39000a001710d4", symbols);
  REQUIRE(cert);
  HashHandler hash(szOID_CP_GOST_R3411_12_256, symbols);
  BytesVector data_for_hashing{0, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2};
  hash.SetData(data_for_hashing);
  BytesVector hashing_result = hash.GetValue();
  REQUIRE(hashing_result.size() == 32);
  // find cert and private key
  HCRYPTPROV_OR_NCRYPT_KEY_HANDLE h_csp{};
  DWORD key_additional_info = 0;
  BOOL caller_must_free = 0;
  BOOL res = symbols->dl_CryptAcquireCertificatePrivateKey(
      cert->GetContext(), 0, nullptr, &h_csp, &key_additional_info,
      &caller_must_free);

  std::cout << "get private key ..." << (res == TRUE ? "OK" : "FAILED") << "\n";
  REQUIRE(res == TRUE);

  // sign hash
  //  CRYPT sign params
  CRYPT_SIGN_MESSAGE_PARA crypt_sign_params{};
  std::memset(&crypt_sign_params, 0x00, sizeof(CRYPT_SIGN_MESSAGE_PARA));
  crypt_sign_params.cbSize = sizeof(CRYPT_SIGN_MESSAGE_PARA);
  crypt_sign_params.dwMsgEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
  crypt_sign_params.pSigningCert = cert->GetContext(); // signer's certificate
  crypt_sign_params.HashAlgorithm.pszObjId =
      const_cast<char *>(szOID_CP_GOST_R3411_12_256); // NOLINT
  // save signer's cert to message
  crypt_sign_params.cMsgCert = 1;
  std::array<PCCERT_CONTEXT, 1> certs{cert->GetContext()};
  crypt_sign_params.rgpMsgCert = certs.data(); //
  // CADES sign params
  CADES_SIGN_PARA cades_sign_params{};
  std::memset(&cades_sign_params, 0x00, sizeof(CADES_SIGN_PARA));
  cades_sign_params.dwSize = sizeof(CADES_SIGN_PARA);
  cades_sign_params.dwCadesType = CADES_BES; // TODO(Oleg) test the rest
  cades_sign_params.pSignerCert =
      cert->GetContext();                         // TODO(Oleg) do we need this?
  cades_sign_params.pTspConnectionPara = nullptr; // TODO(Oleg) test with csp
  // CADES msg params
  CADES_SIGN_MESSAGE_PARA cades_sign_msg_params{};
  cades_sign_msg_params.dwSize = sizeof(CADES_SIGN_MESSAGE_PARA);
  cades_sign_msg_params.pSignMessagePara = &crypt_sign_params;
  cades_sign_msg_params.pCadesSignPara = &cades_sign_params;
  // create a signature
  PCRYPT_DATA_BLOB pSignedMessage = nullptr;
  PCRYPT_DATA_BLOB pSignedMessage2 = nullptr;
  auto hash_val = hash.GetValue();
  res = symbols->dl_CadesSignHash(&cades_sign_msg_params, hash_val.data(),
                                  hash_val.size(), szOID_RSA_data,
                                  &pSignedMessage);
  hash_val[0] = 0xFF;
  res = symbols->dl_CadesSignHash(&cades_sign_msg_params, hash_val.data(),
                                  hash_val.size(), szOID_RSA_data,
                                  &pSignedMessage2);
  ResCheck(res, "SecondSign", symbols);
  REQUIRE(res == TRUE);
  REQUIRE(pSignedMessage != nullptr);
  REQUIRE(pSignedMessage->cbData != 0);
  REQUIRE(pSignedMessage->pbData != nullptr);
  std::ofstream ofile("test_bes_res.sig");
  REQUIRE(ofile.is_open());
  for (size_t i = 0; i < pSignedMessage->cbData; ++i) {
    ofile << pSignedMessage->pbData[i];
  }
  ofile.close();
  // TODO(oleg) Close message
  if (caller_must_free == TRUE) {
    res = symbols->dl_CryptReleaseContext(h_csp, 0);
    std::cout << "release crypto context ..." << (res == TRUE ? "OK" : "FAILED")
              << "\n";
  }
  // verify
  BytesVector raw_msg;
  std::copy(pSignedMessage->pbData,
            pSignedMessage->pbData + pSignedMessage->cbData,
            std::back_inserter(raw_msg));
  auto msg = csp.OpenDetached(raw_msg);
  auto check_res = msg->ComprehensiveCheck(data_for_hashing, 0, true);
  std::cout << check_res.Str() << "\n";
  REQUIRE(check_res.bres.check_summary);
  // verify invalid
  BytesVector raw_msg2;
  std::copy(pSignedMessage2->pbData,
            pSignedMessage2->pbData + pSignedMessage2->cbData,
            std::back_inserter(raw_msg2));
  auto msg_invalid = csp.OpenDetached(raw_msg2);
  auto check_res2 = msg_invalid->ComprehensiveCheck(data_for_hashing, 0, true);
  std::cout << check_res2.Str() << "\n";
  REQUIRE_FALSE(check_res2.bres.check_summary);
}

TEST_CASE("SignBes_high_level") {
  Csp csp;
  BytesVector data_for_hashing{0, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2};
  auto raw_signature =
      csp.SignData("7c001710d43a522a13006a8c39000a001710d4", "Test Certificate",
                   pdfcsp::csp::CadesType::kCadesBes, data_for_hashing);
  auto msg = csp.OpenDetached(raw_signature);
  auto check_res = msg->ComprehensiveCheck(data_for_hashing, 0, true);
  REQUIRE(check_res.bres.check_summary);
}

TEST_CASE("SignT") {
  Csp csp;
  BytesVector data_for_hashing{0, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2};
  const std::wstring tsp_url(L"http://pki.tax.gov.ru/tsp/tsp.srf");
  auto raw_signature =
      csp.SignData("7c001710d43a522a13006a8c39000a001710d4", "Test Certificate",
                   pdfcsp::csp::CadesType::kCadesT, data_for_hashing, tsp_url);
  auto msg = csp.OpenDetached(raw_signature);
  auto check_res = msg->ComprehensiveCheck(data_for_hashing, 0, true);
  std::cout << check_res.Str();
  REQUIRE(check_res.bres.check_summary);
  {
    std::ofstream ofile("test_T_res.sig");
    REQUIRE(ofile.is_open());
    for (size_t i = 0; i < raw_signature.size(); ++i) {
      ofile << raw_signature[i];
    }
    ofile.close();
  }
  {
    std::ofstream ofile("data_signed.dat");
    REQUIRE(ofile.is_open());
    for (size_t i = 0; i < data_for_hashing.size(); ++i) {
      ofile << data_for_hashing[i];
    }
    ofile.close();
  }
}

TEST_CASE("SignXLT") {
  Csp csp;
  BytesVector data_for_hashing{0, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2};
  const std::wstring tsp_url(L"http://pki.tax.gov.ru/tsp/tsp.srf");
  auto raw_signature = csp.SignData(
      "7c001710d43a522a13006a8c39000a001710d4", "Test Certificate",
      pdfcsp::csp::CadesType::kCadesXLong1, data_for_hashing, tsp_url);
  auto msg = csp.OpenDetached(raw_signature);
  auto check_res = msg->ComprehensiveCheck(data_for_hashing, 0, true);
  std::cout << check_res.Str();
  REQUIRE(check_res.bres.check_summary);
  std::ofstream ofile("test_X_res.sig");
  REQUIRE(ofile.is_open());
  for (size_t i = 0; i < raw_signature.size(); ++i) {
    ofile << raw_signature[i];
  }
  ofile.close();
}