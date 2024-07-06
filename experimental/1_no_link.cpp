#include "CSP_WinCrypt.h"
#include "CSP_WinDef.h"
#include "resolve_symbols.hpp"
#include <filesystem>
#include <fstream>
#include <ios>
#include <iostream>
#include <iterator>
#include <string>
#include <sys/types.h>
#include <vector>

#define UNIX
#define SIZEOF_VOID_P 8
#define IGNORE_LEGACY_FORMAT_MESSAGE_MSG

#include "cades.h"

constexpr const char *const delimiter =
    "--------------------------------------------\n";

BOOL CertEnumSystemStoreCallback(const void *pvSystemStore, DWORD dwFlags,
                                 PCERT_SYSTEM_STORE_INFO pStoreInfo,
                                 void *pvReserved, void *pvArg) {
  std::cout << static_cast<const char *>(pvSystemStore) << "\n";
  std::cout << "dwFlags = " << std::hex << dwFlags << "\n";
  switch (dwFlags) {
  case CERT_SYSTEM_STORE_LOCATION_MASK:
    std::cout << "CERT_SYSTEM_STORE_LOCATION_MASK\n";
    break;
  case CERT_SYSTEM_STORE_RELOCATE_FLAG:
    std::cout << "CERT_SYSTEM_STORE_RELOCATE_FLAG\n";
    break;
  case (CERT_SYSTEM_STORE_RELOCATE_FLAG | CERT_SYSTEM_STORE_LOCATION_MASK):
    std::cout << "CERT_SYSTEM_STORE_RELOCATE_FLAG | "
                 "CERT_SYSTEM_STORE_LOCATION_MASK\n";
    break;
  }
  std::cout << "pStoreInfo = " << pStoreInfo << "\n";
  return TRUE;
}

std::string GetHashOid(const std::string &public_key_algo) {
  if (public_key_algo == szOID_CP_GOST_R3410EL) {
    return szOID_CP_GOST_R3411;
  } else if (public_key_algo == szOID_CP_GOST_R3410_12_256) {
    return szOID_CP_GOST_R3411_12_256;
  } else if (public_key_algo == szOID_CP_GOST_R3410_12_512) {
    return szOID_CP_GOST_R3411_12_512;
  }
  return "";
}

std::vector<unsigned char> FileToVec(const std::string &path) {
  std::vector<unsigned char> res;
  namespace fs = std::filesystem;
  if (!fs::exists(path)) {
    std::cerr << "file " << path << " doesn't  exist\n";
    return res;
  }
  auto size = fs::file_size(path);
  if (size <= 0) {
    std::cerr << "file " << path << " is empty\n";
    return res;
  }
  std::cout << std::dec << "filesize = " << size << "\n";
  std::vector<char> buff;
  buff.reserve(size);
  res.reserve(size);
  std::ifstream file(path, std::ios_base::binary);
  if (!file.is_open()) {
    std::cerr << "can't open file " << path << "\n";
    return res;
  }
  file.read(buff.data(), size);
  std::copy(buff.data(), buff.data() + size, std::back_inserter(res));
  file.close();
  std::cout << "Bytes read = " << res.size() << "\n";
  return res;
}

int main() {
  ResolvedSymbols dl;

  // enum stores
  //  void* ptr=nullptr;
  //  int
  //  res=CertEnumSystemStore(CERT_SYSTEM_STORE_CURRENT_USER,0,ptr,CertEnumSystemStoreCallback);
  //  std::cout << "res = "<< res <<"\n";
  //  if (res==FALSE){
  //      std::cout << std::hex<<GetLastError() <<"\n";
  //  }

  // ------------------------------------------------------------------
  // open store
  // Only current user certificates are accessible using this method, not the
  // local machine store.
  HCERTSTORE h_store = dl.dl_CertOpenSystemStoreA(0, "MY");
  if (h_store == nullptr) {
    std::cout << "error opening store\n";
  } else {
    std::cout << "Open store ... OK\n";
  }

  // ------------------------------------------------------------------
  // enum certificates
  std::cout << "List of certificates:\n";
  PCCERT_CONTEXT p_cert_context = nullptr;
  while ((p_cert_context =
              dl.dl_CertEnumCertificatesInStore(h_store, p_cert_context))) {
    std::cout << delimiter;
    // encoding
    switch (p_cert_context->dwCertEncodingType) {
    case X509_ASN_ENCODING:
      std::cout << "X509_ASN_ENCODING\n";
      break;
    case PKCS_7_ASN_ENCODING:
      std::cout << "PKCS_7_ASN_ENCODING\n";
    case X509_ASN_ENCODING | PKCS_7_ASN_ENCODING:
      std::cout << "PKCS_7_ASN_ENCODING | X509_ASN_ENCODING\n";
      break;
    default:
      std::cout << "Unclear " << std::hex << p_cert_context->dwCertEncodingType;
    }
    // certificate info
    if (p_cert_context->pCertInfo == nullptr) {
      std::cout << "No certificate info\n";
      continue;
    }
    std::cout << "version = " << p_cert_context->pCertInfo->dwVersion << "\n";
    DWORD index_last = p_cert_context->pCertInfo->SerialNumber.cbData - 1;
    std::cout << "serial = ";
    for (int i = index_last; i >= 0; --i) {
      std::cout << std::hex
                << static_cast<int>(
                       p_cert_context->pCertInfo->SerialNumber.pbData[i]);
    }
    std::cout << "\n";
    std::cout << "signature algorithm = ";
    std::string alg(p_cert_context->pCertInfo->SignatureAlgorithm.pszObjId);
    if (alg == std::string(szOID_CP_GOST_R3411_12_256_R3410)) {
      std::cout << "Алгоритм цифровой подписи ГОСТ Р 34.10-2012 для ключей "
                   "длины 256 бит \n";
    } else {
      std::cout << p_cert_context->pCertInfo->SignatureAlgorithm.pszObjId;
    }
    // issuer
    {
      CERT_NAME_BLOB &issuerNameBlob = p_cert_context->pCertInfo->Issuer;
      DWORD dwSize = dl.dl_CertNameToStrA(X509_ASN_ENCODING, &issuerNameBlob,
                                          CERT_X500_NAME_STR, nullptr, 0);
      std::string issuerString(dwSize, '\0');
      dl.dl_CertNameToStrA(X509_ASN_ENCODING, &issuerNameBlob,
                           CERT_X500_NAME_STR, &issuerString[0], dwSize);
      std::cout << issuerString << "\n";
    }
    // name
    {
      CERT_NAME_BLOB &subject_blob = p_cert_context->pCertInfo->Subject;
      DWORD dwSize = dl.dl_CertNameToStrA(X509_ASN_ENCODING, &subject_blob,
                                          CERT_X500_NAME_STR, nullptr, 0);
      std::cout << "Name = ";
      std::string cert_name(dwSize, '\0');
      dl.dl_CertNameToStrA(X509_ASN_ENCODING, &subject_blob, CERT_X500_NAME_STR,
                           &cert_name[0], dwSize);
      std::cout << cert_name << "\n";
    }
  }

  // ------------------------------------------------------------------
  // now test CertFindCertificateInStore
  // [in] hCertStore - A handle of the certificate store
  // [in] dwCertEncodingType X509_ASN_ENCODING | PKCS_7_ASN_ENCODING
  // [in] dwFindFlags Used with some dwFindType values to modify the search
  // criteria. For most dwFindType values, dwFindFlags is not used and should be
  // set to zero. For detailed information, see Remarks. [in] dwFindType
  // CERT_FIND_SUBJECT_STR = CERT_FIND_SUBJECT_STR_W = 0x80007 Data type of
  // pvFindPara: Null-terminated Unicode string. Searches for a certificate that
  // contains the specified subject name [in] pvFindPara Points to a data item
  // or structure used with dwFindType. [in] pPrevCertContext A pointer to the
  // last CERT_CONTEXT structure returned by this function. This parameter must
  // be NULL on the first call of the function.
  //      CERT_FIND_ANY No search criteria used. Returns the next certificate in
  //      the store.
  // return If the function succeeds, the function returns a pointer to a
  // read-only CERT_CONTEXT structure.
  //  must be freed by CertFreeCertificateContext or by being passed as the
  //  pPrevCertContext parameter on a subsequent call to
  //  CertFindCertificateInStore.

  /*
   A CERT_CONTEXT structure that contains a handle to a certificate store,
   a pointer to the original encoded certificate BLOB, a pointer to a CERT_INFO
   structure, and an encoding type member. It is the CERT_INFO structure that
   contains most of the certificate information.
  */

  PCCERT_CONTEXT p_cert_ctx = dl.dl_CertFindCertificateInStore(
      h_store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, CERT_FIND_ANY,
      nullptr, nullptr);
  if (p_cert_ctx == nullptr) {
    std::cout << "can't get any sertificates\n";
  } else {
    std::cout << "Get certificate context ... OK\n";
  }

  std::cout << delimiter;
  if (p_cert_ctx == nullptr) {
    dl.dl_CertCloseStore(h_store, 0);
    return 0;
  }

  // ------------------------------------------------------------------
  // now try to get a private key for certificate
  /*
  BOOL CryptAcquireCertificatePrivateKey(
  [in]           PCCERT_CONTEXT                  pCert, The address of a
  CERT_CONTEXT structure [in]           DWORD                           dwFlags,
  [in, optional] void                            *pvParameters,
  [out]          HCRYPTPROV_OR_NCRYPT_KEY_HANDLE *phCryptProvOrNCryptKey, The
  address of an HCRYPTPROV_OR_NCRYPT_KEY_HANDLE variable that receives the
  handle of either the CryptoAPI provider or the CNG key. [out]          DWORD
  *pdwKeySpec, [out]          BOOL *pfCallerFreeProvOrNCryptKey
  );
  */

  HCRYPTPROV_OR_NCRYPT_KEY_HANDLE csp_provider = 0;
  DWORD key_additional_info = 0;
  /*
  If this variable receives TRUE, the caller is responsible for releasing the
  handle returned in the phCryptProvOrNCryptKey variable. If the pdwKeySpec
  variable receives the CERT_NCRYPT_KEY_SPEC value, the handle must be released
  by passing it to the NCryptFreeObject function; otherwise, the handle is
  released by passing it to the CryptReleaseContext function.
  */
  BOOL caller_must_free = 0;
  // function obtains the private key for a certificate
  BOOL res = dl.dl_CryptAcquireCertificatePrivateKey(
      p_cert_ctx, 0, 0, &csp_provider, &key_additional_info, &caller_must_free);
  if (res == FALSE) {
    std::cout << "error getting private key\n";
  } else {
    std::cout << "get private key ...OK\n";
  }
  // additional info about the key
  if (res != FALSE) {
    switch (key_additional_info) {
    case AT_KEYEXCHANGE:
      std::cout << "The key is AT_KEYEXCHANGE\n";
      break;
    case AT_SIGNATURE:
      std::cout << "The key is AT_SIGNATURE\n";
      break;
    default:
      std::cout << "Additional key info flag is not recognized\n";
      break;
    }
  }
  // must free
  std::cout << (caller_must_free == TRUE ? "caller must free the handle"
                                         : "caller must NOT free the handle")
            << "\n";
  // ------------------------------------------------------------------
  // retrieve the information contained in an extended property of certiface
  // context

  /*
  retrieves the information contained in an extended property of a certificate
  context. BOOL CertGetCertificateContextProperty( [in]      PCCERT_CONTEXT
  pCertContext, A pointer to the CERT_CONTEXT [in]      DWORD          dwPropId,
  The property to be retrieved. [out]     void           *pvData, [in, out]
  DWORD          *pcbData
      );
  */

  /*
    CERT_KEY_PROV_INFO_PROP_ID
    it stores the key provider information within the certificate context.
    The key provider information includes details such as the cryptographic
    provider type, provider name, key container name, and other relevant
    parameters needed to access the private key associated with the certificate.
  */

  DWORD buff_size = 0;
  res = dl.dl_CertGetCertificateContextProperty(
      p_cert_ctx, CERT_KEY_PROV_INFO_PROP_ID, 0, &buff_size);
  if (res == FALSE) {
    std::cout << "Get certificate property ... FAILED\n";
  }
  std::vector<BYTE> buff(buff_size, 0);
  res = dl.dl_CertGetCertificateContextProperty(
      p_cert_ctx, CERT_KEY_PROV_INFO_PROP_ID, buff.data(), &buff_size);
  std::cout << "Get certificate property ..." << (res == TRUE ? "OK" : "FAILED")
            << "\n";
  // debug print prop
  // std::string prop;
  // prop.assign(reinterpret_cast<const char*>(buff.data()),buff_size);
  // std::cout << prop<<"\n";

  // ------------------------------------------------------------------
  // create a sign
  /*
      CadesMsgOpenToEncode = MS CryptMsgOpenToEncode
      The CryptMsgOpenToEncode function opens a cryptographic message for
     encoding and returns a handle of the opened message. The message remains
     open until CryptMsgClose is called. HCRYPTMSG CadesMsgOpenToEncode (
          __in DWORD dwMsgEncodingType, Specifies the encoding type used.
          __in DWORD dwFlags,
          __in PCADES_ENCODE_INFO pvMsgEncodeInfo, pointer to CADES_ENCODE_INFO
          __in_opt LPSTR pszInnerContentObjID,
          __in PCMSG_STREAM_INFO pStreamInfo
          );

      CMSG_SIGNER_ENCODE_INFO -  structure contains signer information.
      CMSG_SIGNED_ENCODE_INFO - structure contains information to be passed to
     CryptMsgOpenToEncode if dwMsgType is CMSG_SIGNED.
  */

  // find hash algo (public key algo = szOID_CP_GOST_R3411_12_256_R3410)
  std::string hash_algo(GetHashOid(
      p_cert_ctx->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId));
  std::cout << "Hashing algo " << (hash_algo.empty() ? hash_algo : "empty")
            << "\n";
  // signer info
  CMSG_SIGNER_ENCODE_INFO signer_info{};
  signer_info.cbSize = sizeof(CMSG_SIGNER_ENCODE_INFO);
  signer_info.pCertInfo = p_cert_ctx->pCertInfo;
  signer_info.hCryptProv = csp_provider;
  signer_info.dwKeySpec =
      key_additional_info; // Specifies the private key to be used.
                           //  TODO figure out what to do if it is empty and wy
                           //  passing 0
  signer_info.HashAlgorithm.pszObjId =
      const_cast<char *>(hash_algo.empty() ? nullptr : hash_algo.c_str());
  // encode info
  CMSG_SIGNED_ENCODE_INFO signed_info{};
  signed_info.cbSize = sizeof(CMSG_SIGNED_ENCODE_INFO);
  signed_info.cSigners = 1;
  signed_info.rgSigners = &signer_info;
  // cades info
  CADES_ENCODE_INFO cades_info{};
  cades_info.dwSize = sizeof(cades_info);
  cades_info.pSignedEncodeInfo = &signed_info;
  // open crypto message
  HCRYPTMSG handler_message = dl.dl_CadesMsgOpenToEncode(
      X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, &cades_info, 0, 0);
  if (handler_message == 0) {
    std::cout << "Open message to encode ... FAILED\n";
  }

  // read data
  std::vector<unsigned char> data = FileToVec(
      "/home/oleg/dev/eSign/pdf_tool/test_files/text_file_to_sign.txt");
  // Create message
  dl.dl_CryptMsgUpdate(handler_message, data.data(), data.size(), TRUE);
  if (res == FALSE) {
    std::cerr << "Can't create message with CryptMsgUpdate\n";
  }
  // get sing size
  DWORD sign_size = 0;
  res = dl.dl_CryptMsgGetParam(handler_message, CMSG_CONTENT_PARAM, 0, 0,
                               &sign_size);

  std::cout << "Sign size = " << sign_size << "\n";
  // get the sign
  std::vector<unsigned char> message_data(sign_size);
  res = dl.dl_CryptMsgGetParam(handler_message, CMSG_CONTENT_PARAM, 0,
                               message_data.data(), &sign_size);
  std::cout << "Get sign message ..." << (res == TRUE ? "OK" : "FAILED")
            << "\n";
  std::cout << "Message size in memory = " << message_data.size() << "\n";
  // close message
  dl.dl_CryptMsgClose(handler_message);
  // open again for decode
  handler_message = dl.dl_CryptMsgOpenToDecode(
      X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, 0, 0, 0, 0);
  if (handler_message == 0) {
    std::cout << "Open to decode ... FAIL\n";
  }
  res = dl.dl_CryptMsgUpdate(handler_message, message_data.data(),
                             message_data.size(), TRUE);
  std::cout << "Message update ... " << (res == TRUE ? "OK" : "FAIL") << "\n";
  // enchance the signature
  // https://cpdn.cryptopro.ru/content/cades/struct___c_a_d_e_s___s_e_r_v_i_c_e___c_o_n_n_e_c_t_i_o_n___p_a_r_a.html
  CADES_SERVICE_CONNECTION_PARA connection_params{};
  connection_params.dwSize = sizeof(CADES_SERVICE_CONNECTION_PARA);
  connection_params.wszUri =
      L"http://testca2012.cryptopro.ru/tsp/tsp.srf"; // test server
  connection_params.pAuthPara = NULL;
  // https://cpdn.cryptopro.ru/content/cades/struct___c_a_d_e_s___s_i_g_n___p_a_r_a.html
  CADES_SIGN_PARA enchanced_params{};
  enchanced_params.dwSize = sizeof(CADES_SIGN_PARA);
  enchanced_params.dwCadesType = CADES_X_LONG_TYPE_1;
  enchanced_params.pTspConnectionPara = &connection_params;
  // process enchancement
  res = dl.dl_CadesMsgEnhanceSignature(handler_message, 0, &enchanced_params);
  std::cout << "Enchance signature ..." << (res == TRUE ? "OK" : "FAIL")
            << "\n";

  sign_size = 0;
  dl.dl_CryptMsgGetParam(handler_message, CMSG_ENCODED_MESSAGE, 0, 0,
                         &sign_size);
  message_data.clear();
  message_data.resize(sign_size, 0);
  res = dl.dl_CryptMsgGetParam(handler_message, CMSG_ENCODED_MESSAGE, 0,
                               message_data.data(), &sign_size);
  std::cout << "Message read enchanced ..." << (res == TRUE ? "OK" : "FAIL")
            << "\n";
  std::cout << "Enchanced message size = " << sign_size << "\n";

  // // ------------------------------------------------------------------
  // close message
  dl.dl_CryptMsgClose(handler_message);
  // free csp context
  if (caller_must_free == TRUE) {
    int res = dl.dl_CryptReleaseContext(csp_provider, 0);
    std::cout << "release crypto context ..." << (res == TRUE ? "OK" : "FAILED")
              << "\n";
  }
  // free cert context
  if (p_cert_ctx != nullptr) {
    dl.dl_CertFreeCertificateContext(p_cert_ctx);
  }
  // close the store
  res = dl.dl_CertCloseStore(h_store, 0);
}