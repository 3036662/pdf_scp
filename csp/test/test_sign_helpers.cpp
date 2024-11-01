#include "CSP_WinDef.h"
#include "cert_common_info.hpp"
#include "hash_handler.hpp"
#include "resolve_symbols.hpp"
#include "store_hanler.hpp"
#include "typedefs.hpp"
#include "utils_cert.hpp"
#include <array>
#include <boost/json/serialize.hpp>
#include <cstddef>
#include <fstream>
#include <iterator>
#include <memory>
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
      "Test Certificate", "7c0016b744e7a68ddba55a265f00090016b744",
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
      "Test Certificate", "7c0016b744e7a68ddba55a265f00090016b744", symbols);
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
  crypt_sign_params.cMsgCert = 1;                     // no certs n
  std::array<PCCERT_CONTEXT, 1> certs{cert->GetContext()};
  crypt_sign_params.rgpMsgCert = certs.data(); // TODO(Oleg) do we need this?
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
  auto hash_val = hash.GetValue();
  res = symbols->dl_CadesSignHash(&cades_sign_msg_params, hash_val.data(),
                                  hash_val.size(), szOID_RSA_data,
                                  &pSignedMessage);
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
}