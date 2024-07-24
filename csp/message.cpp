#include "message.hpp"
#include "asn1.hpp"
#include "certificate_id.hpp"
#include "crypto_attribute.hpp"
#include "message_handler.hpp"
#include "typedefs.hpp"
#include "utils.hpp"
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <limits>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <sys/types.h>
#include <vector>

namespace pdfcsp::csp {

// check resolver and data and call DecodeDetachedMessage
Message::Message(std::shared_ptr<ResolvedSymbols> dlsymbols,
                 const BytesVector &raw_signature, const BytesVector &data)
    : symbols_(std::move(dlsymbols)), raw_signature_(raw_signature) {
  if (!symbols_) {
    throw std::runtime_error("Symbol resolver is null");
  }
  if (raw_signature.empty() || data.empty()) {
    throw std::logic_error("Empty data");
  }
  DecodeDetachedMessage(raw_signature, data);
}

CadesType Message::GetCadesType() const noexcept {
  CadesType res = CadesType::kUnknown;
  if (!symbols_ || !msg_handler_) {
    return res;
  }
  try {
    BOOL check_result = FALSE;
    symbols_->dl_CadesMsgIsType(*msg_handler_, 0, CADES_BES, &check_result);
    if (check_result == TRUE) {
      res = CadesType::kCadesBes;
      return res;
    }
    symbols_->dl_CadesMsgIsType(*msg_handler_, 0, CADES_T, &check_result);
    if (check_result == TRUE) {
      res = CadesType::kCadesT;
      return res;
    }
    symbols_->dl_CadesMsgIsType(*msg_handler_, 0, CADES_X_LONG_TYPE_1,
                                &check_result);
    if (check_result == TRUE) {
      res = CadesType::kCadesXLong1;
      return res;
    }
    symbols_->dl_CadesMsgIsType(*msg_handler_, 0, PKCS7_TYPE, &check_result);
    if (check_result == TRUE) {
      res = CadesType::kPkcs7;
      return res;
    }
  } catch (const std::exception &ex) {
    return res;
  }

  return res;
}

std::optional<uint> Message::GetSignersCount() const noexcept {
  if (!symbols_ || !msg_handler_) {
    return std::nullopt;
  }
  DWORD buff_size = sizeof(DWORD);
  DWORD number_of_singners = 0;
  try {
    ResCheck(symbols_->dl_CryptMsgGetParam(*msg_handler_,
                                           CMSG_SIGNER_COUNT_PARAM, 0,
                                           &number_of_singners, &buff_size),
             "GetSignersCount");

  } catch ([[maybe_unused]] const std::exception &ex) {
    return std::nullopt;
  }
  return number_of_singners;
}

std::optional<uint> Message::GetRevokedCertsCount() const noexcept {
  if (!symbols_ || !msg_handler_) {
    return std::nullopt;
  }
  DWORD buff_size = sizeof(DWORD);
  DWORD number_of_revoces = 0;
  try {
    ResCheck(symbols_->dl_CryptMsgGetParam(*msg_handler_, CMSG_CRL_COUNT_PARAM,
                                           0, &number_of_revoces, &buff_size),
             "Get revoked certs count");
  } catch ([[maybe_unused]] const std::exception &ex) {
    return std::nullopt;
  }
  return number_of_revoces;
}

[[nodiscard]] std::optional<CertificateID>
Message::GetSignerCertId(uint signer_index) const noexcept {
  // get data from CMSG_SIGNER_CERT_INFO_PARAM
  DWORD buff_size = 0;
  CertificateID id_from_cert_info;
  try {
    ResCheck(symbols_->dl_CryptMsgGetParam(*msg_handler_,
                                           CMSG_SIGNER_CERT_INFO_PARAM,
                                           signer_index, nullptr, &buff_size),
             "Get signer info -> cert_id size");
    BytesVector buff = CreateBuffer(buff_size);
    ResCheck(symbols_->dl_CryptMsgGetParam(
                 *msg_handler_, CMSG_SIGNER_CERT_INFO_PARAM, signer_index,
                 buff.data(), &buff_size),
             "Get signer info cert_id");
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    auto *p_cert_info = reinterpret_cast<_CERT_INFO *>(buff.data());
    const CRYPT_INTEGER_BLOB *p_serial_blob = &p_cert_info->SerialNumber;
    auto res = IntBlobToVec(p_serial_blob);
    if (!res || res->empty()) {
      return std::nullopt;
    }
    id_from_cert_info.serial = std::move(res.value());
    CERT_NAME_BLOB *p_issuer_blob = &p_cert_info->Issuer;
    auto res_issuer = NameBlobToString(p_issuer_blob, symbols_);
    if (!res_issuer) {
      return std::nullopt;
    }
    id_from_cert_info.issuer = std::move(res_issuer.value());
  } catch ([[maybe_unused]] const std::exception &ex) {
    return std::nullopt;
  }
  // get data from CMSG_SIGNER_AUTH_ATTR_PARAM
  CertificateID id_from_auth_attributes;
  {
    auto signed_attrs = GetSignedAttributes(signer_index);
    if (!signed_attrs.has_value()) {
      std::cerr << "No signed attributes\n";
      return std::nullopt;
    }
    for (const auto &attr : signed_attrs.value().get_bunch()) {
      // find certificate
      if (attr.get_id() == szCPOID_RSA_SMIMEaaSigningCertificateV2) {
        if (attr.get_blobs_count() == 0) {
          std::cerr << "No blobs in signed sertificate";
          return std::nullopt;
        }
        try {
          // ASN decode
          for (size_t i = 0; i < attr.get_blobs_count(); ++i) {
            const AsnObj asn(attr.get_blobs()[i].data(),
                             attr.get_blobs()[i].size(), symbols_);
            id_from_auth_attributes = CertificateID(asn);
          }
        } catch (const std::exception &ex) {
          std::cerr << ex.what();
          return std::nullopt;
        }
        break;
      }
    }
  }
  // get data form CadesMsgGetSigningCertId
  CertificateID id_from_cades;
  try {
    CRYPT_DATA_BLOB *p_cert_id_blob = nullptr;
    ResCheck(symbols_->dl_CadesMsgGetSigningCertId(*msg_handler_, signer_index,
                                                   &p_cert_id_blob),
             "CadesMsgGetSigningCertId");
    if (p_cert_id_blob == nullptr || p_cert_id_blob->cbData == 0) {
      throw std::runtime_error("CadesMsgGetSigningCertId returned nullptr");
    }
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    auto *p_cert_id = reinterpret_cast<CERT_ID *>(p_cert_id_blob->pbData);
    if (p_cert_id->dwIdChoice != CERT_ID_ISSUER_SERIAL_NUMBER) {
      throw std::runtime_error(
          "[CadesMsgGetSigningCertId] no serial number in CERT_ID was found");
    }
    // NOLINTBEGIN(cppcoreguidelines-pro-type-union-access)
    auto issuer = NameBlobToString(&p_cert_id->f_name.IssuerSerialNumber.Issuer,
                                   symbols_);
    auto serial =
        IntBlobToVec(&p_cert_id->f_name.IssuerSerialNumber.SerialNumber);
    // NOLINTEND(cppcoreguidelines-pro-type-union-access)
    if (!issuer || !serial || issuer->empty() || serial->empty()) {
      throw std::runtime_error("[CadesMsgGetSigningCertId] empty cert_id");
    }
    id_from_cades.serial = std::move(serial.value());
    id_from_cades.issuer = std::move(issuer.value());
  } catch (const std::exception &ex) {
    std::cerr << ex.what();
    return std::nullopt;
  }
  // compare everything
  if (id_from_cert_info == id_from_cades &&
      id_from_cert_info == id_from_auth_attributes) {
    return id_from_auth_attributes;
  }
  return std::nullopt;
}

// ------------------------- private ----------------------------------

[[nodiscard]] std::optional<CryptoAttributesBunch>
Message::GetSignedAttributes(uint signer_index) const noexcept {
  try {
    unsigned int buff_size = 0;
    ResCheck(symbols_->dl_CryptMsgGetParam(*msg_handler_,
                                           CMSG_SIGNER_AUTH_ATTR_PARAM,
                                           signer_index, nullptr, &buff_size),
             "Get signed attr size");
    if (buff_size == 0 ||
        buff_size > std::numeric_limits<unsigned int>::max()) {
      return std::nullopt;
    }
    auto buff = CreateBuffer(buff_size);
    ResCheck(symbols_->dl_CryptMsgGetParam(
                 *msg_handler_, CMSG_SIGNER_AUTH_ATTR_PARAM, signer_index,
                 buff.data(), &buff_size),
             "Get signed attributes");
    if (buff_size == 0) {
      return std::nullopt;
    }
    // NOLINTBEGIN(cppcoreguidelines-pro-type-reinterpret-cast)
    const auto *ptr_crypt_attr =
        reinterpret_cast<CRYPT_ATTRIBUTES *>(buff.data());
    // NOLINTEND(cppcoreguidelines-pro-type-reinterpret-cast)
    if (ptr_crypt_attr->cAttr == 0 ||
        ptr_crypt_attr->cAttr > std::numeric_limits<unsigned int>::max()) {
      return std::nullopt;
    }
    if (ptr_crypt_attr->rgAttr == nullptr) {
      return std::nullopt;
    }
    return CryptoAttributesBunch(ptr_crypt_attr);

  } catch ([[maybe_unused]] const std::exception &ex) {
    std::cerr << ex.what() << "\n";
    return std::nullopt;
  }
  return std::nullopt;
}

std::optional<uint> Message::GetCertCount() const noexcept {
  if (!symbols_ || !msg_handler_) {
    return std::nullopt;
  }
  DWORD buff_size = sizeof(DWORD);
  DWORD number_of_certs = 0;
  try {
    ResCheck(symbols_->dl_CryptMsgGetParam(*msg_handler_, CMSG_CERT_COUNT_PARAM,
                                           0, &number_of_certs, &buff_size),
             "Get revoked certs count");
  } catch ([[maybe_unused]] const std::exception &ex) {
    return std::nullopt;
  }
  return number_of_certs;
}

std::optional<BytesVector>
Message::GetRawCertificate(uint index) const noexcept {
  DWORD buff_size = 0;
  try {
    ResCheck(symbols_->dl_CryptMsgGetParam(*msg_handler_, CMSG_CERT_PARAM,
                                           index, nullptr, &buff_size),
             "Get the raw certificate size");
    if (buff_size == 0) {
      return std::nullopt;
    }
    BytesVector buff = CreateBuffer(buff_size);
    buff.resize(buff_size, 0x00);
    ResCheck(symbols_->dl_CryptMsgGetParam(*msg_handler_, CMSG_CERT_PARAM,
                                           index, buff.data(), &buff_size),
             "Get raw certificate");
    return buff;
  } catch (const std::exception &) {
    return std::nullopt;
  }
  return std::nullopt;
}

// throw exception if FALSE
void Message::ResCheck(BOOL res, const std::string &msg) const {
  ::pdfcsp::csp::ResCheck(res, msg, symbols_);
}

// decode a message
void Message::DecodeDetachedMessage(const BytesVector &sig,
                                    const BytesVector &data) {
  // create new message
  msg_handler_ =
      MsgDescriptorWrapper(symbols_->dl_CryptMsgOpenToDecode(
                               X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                               CMSG_DETACHED_FLAG, 0, 0, nullptr, nullptr),
                           symbols_);
  if (!msg_handler_) {
    throw std::runtime_error("CryptMsgOpenToDecode failed");
  }
  // load data to message
  ResCheck(
      symbols_->dl_CryptMsgUpdate(*msg_handler_, sig.data(), sig.size(), TRUE),
      "Msg update with data");
  // load data to the Msg
  ResCheck(symbols_->dl_CryptMsgUpdate(*msg_handler_, data.data(), data.size(),
                                       TRUE),
           "Load data to msg");
}

[[nodiscard]] std::optional<std::string>
Message::GetDataHashingAlgo(uint signer_index) const noexcept {
  auto cert_id = GetSignerCertId(signer_index);
  if (!cert_id) {
    std::cerr << "no certificate id was found\n";
    return std::nullopt;
  }
  std::string algo_oid_from_signed_attrs = cert_id->hashing_algo_oid;
  // CMSG_SIGNER_HASH_ALGORITHM_PARAM
  std::string algo_oid_from_signer_info;
  try {
    constexpr const char *const operation_name =
        "CMSG_SIGNER_HASH_ALGORITHM_PARAM";
    constexpr const char *const expl =
        "Get hash from CMSG_SIGNER_HASH_ALGORITHM_PARAM failed";
    DWORD buff_size = 0;
    ResCheck(symbols_->dl_CryptMsgGetParam(*msg_handler_,
                                           CMSG_SIGNER_HASH_ALGORITHM_PARAM,
                                           signer_index, nullptr, &buff_size),
             operation_name);
    if (buff_size == 0) {
      throw std::runtime_error(expl);
    }
    auto buf = CreateBuffer(buff_size);
    ResCheck(symbols_->dl_CryptMsgGetParam(
                 *msg_handler_, CMSG_SIGNER_HASH_ALGORITHM_PARAM, signer_index,
                 buf.data(), &buff_size),
             operation_name);
    // NOLINTBEGIN(cppcoreguidelines-pro-type-reinterpret-cast)
    auto *ptr_ctypt_id =
        reinterpret_cast<CRYPT_ALGORITHM_IDENTIFIER *>(buf.data());
    // NOLINTEND(cppcoreguidelines-pro-type-reinterpret-cast)
    algo_oid_from_signer_info = ptr_ctypt_id->pszObjId;
    if (algo_oid_from_signer_info.empty()) {
      throw std::runtime_error(expl);
    }
  } catch (const std::exception &ex) {
    std::cerr << ex.what() << "\n";
    return std::nullopt;
  }
  if (algo_oid_from_signed_attrs != algo_oid_from_signer_info) {
    std::cerr << "The hashing algo oid from signed attributes does not match "
                 "CMSG_SIGNER_HASH\n";
    return std::nullopt;
  }
  return algo_oid_from_signed_attrs;
}

std::optional<BytesVector>
Message::GetSignedDataHash(uint signer_index) const noexcept {
  constexpr const char *const func_name = "[GetSignedDataHash] ";
  auto signed_attr = GetSignedAttributes(signer_index);
  if (!signed_attr) {
    std::cerr << func_name << "No signed attibutes were found.\n";
    return std::nullopt;
  }
  for (const auto &attr : signed_attr->get_bunch()) {
    if (attr.get_id() == szOID_PKCS_9_MESSAGE_DIGEST) {
      if (attr.get_blobs_count() == 0 || attr.get_blobs_count() > 1) {
        std::cerr << func_name
                  << " Wrong number of blobs in szOID_PKCS_9_MESSAGE_DIGEST "
                     "attribute\n";
        return std::nullopt;
      }
      auto blobs = attr.get_blobs();
      if (blobs[0].empty()) {
        std::cerr << func_name << "empty blob in szOID_PKCS_9_MESSAGE_DIGEST";
        return std::nullopt;
      }
      try {
        const AsnObj obj(blobs[0].data(), blobs[0].size(), symbols_);
        auto str = obj.GetStringData();
        if (!str || str->empty()) {
          std::cerr << func_name << "no MESSAGE_DIGEST found\n";
          return std::nullopt;
        }
        return BytesVector(str->cbegin(), str->cend());
      } catch (const std::exception &ex) {
        std::cerr << func_name << ex.what() << "\n";
        return std::nullopt;
      }
      break;
    }
  }
  return std::nullopt;
}
// NOLINTBEGIN
//  NOLINTNEXTLINE(readability-function-cognitive-complexity)
bool Message::VeriyHash(const BytesVector &hash_to_compare,
                        const std::string &hashing_algo,
                        const BytesVector &data,
                        uint signer_index) const noexcept {
  constexpr const char *const expl_algo_unknown = "Unknown hashing algorithm";
  constexpr const char *const func_name = "[CalculateDataHash] ";
  HCRYPTPROV csp_handler = 0;
  HCRYPTHASH hash_handler = 0;
  HCRYPTKEY handler_pub_key = 0;
  BytesVector data_hash_calculated;
  try {
    unsigned int provider_type = 0;
    if (hashing_algo == szOID_CP_GOST_R3411_12_256) {
      provider_type = PROV_GOST_2012_256;
    } else {
      throw std::runtime_error(expl_algo_unknown);
    }

    // get CSP context
    ResCheck(symbols_->dl_CryptAcquireContextA(&csp_handler, nullptr, nullptr,
                                               provider_type, 0),
             "CryptAcquireContextA");
    if (csp_handler == 0) {
      throw std::runtime_error("CSP handler == 0");
    }
    // create hash
    unsigned int hash_calc_type = 0;
    if (hashing_algo == szOID_CP_GOST_R3411_12_256) {
      hash_calc_type = CALG_GR3411_2012_256;
    } else {
      throw std::runtime_error(expl_algo_unknown);
    }
    ResCheck(symbols_->dl_CryptCreateHash(csp_handler, hash_calc_type, 0, 0,
                                          &hash_handler),
             "CryptCreateHash");
    ResCheck(
        symbols_->dl_CryptHashData(hash_handler, data.data(), data.size(), 0),
        "CryptHashData");
    DWORD hash_size = 0;
    DWORD hash_size_size = sizeof(DWORD);
    // NOLINTBEGIN(cppcoreguidelines-pro-type-reinterpret-cast)
    ResCheck(symbols_->dl_CryptGetHashParam(
                 hash_handler, HP_HASHSIZE,
                 reinterpret_cast<BYTE *>(&hash_size), &hash_size_size, 0),
             "Get Hash size");
    if (hash_size == 0) {
      throw std::runtime_error("hash size == 0");
    }
    {
      auto buff = CreateBuffer(hash_size);
      buff.resize(hash_size, 0x00);
      ResCheck(symbols_->dl_CryptGetHashParam(hash_handler, HP_HASHVAL,
                                              buff.data(), &hash_size, 0),
               "CryptGetHashParam hash value");
      data_hash_calculated = std::move(buff);
    }
    // compare
    if (data_hash_calculated != hash_to_compare) {
      throw std::runtime_error("The hash does not match the signed hash");
    }

    //===============================================
    // get certificate
    auto raw_cert = GetRawCertificate(signer_index);
    if (!raw_cert) {
      throw std::runtime_error("Get a raw certificate failed");
    }
    PCCERT_CONTEXT p_cert_ctx = symbols_->dl_CertCreateCertificateContext(
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, raw_cert->data(),
        raw_cert->size());
    if (p_cert_ctx == nullptr) {
      throw std::runtime_error("CertCreateCertificateContext failed");
    }
    if (p_cert_ctx->pCertInfo->SubjectPublicKeyInfo.PublicKey.cbData == 0) {
      throw std::runtime_error("no public key data in the certificate");
    }
    // get the public key

    ResCheck(symbols_->dl_CryptImportPublicKeyInfo(
                 csp_handler, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                 &(p_cert_ctx->pCertInfo->SubjectPublicKeyInfo),
                 &handler_pub_key),
             "CryptImportPublicKeyInfo");
    if (handler_pub_key == 0) {
      throw std::runtime_error("CryptImportPublicKeyInfo failed");
    }

    // get  hash COMPUTED_HASH
    std::vector<BYTE> computed_hash;
    {
      std::cout << "---\n";
      DWORD buff_size = 0;
      ResCheck(symbols_->dl_CryptMsgGetParam(
                   *msg_handler_, CMSG_COMPUTED_HASH_PARAM, 0, 0, &buff_size),
               "get CMSG_COMPUTED_HASH_PARAM");
      std::cout << " hash size = " << buff_size << "\n";
      std::vector<BYTE> buff(buff_size, 0);
      ResCheck(symbols_->dl_CryptMsgGetParam(*msg_handler_,
                                             CMSG_COMPUTED_HASH_PARAM, 0,
                                             buff.data(), &buff_size),
               "get CMSG_COMPUTED_HASH_PARAM");
      std::cout << "COMPUTED HASH =";
      for (uint i = 0; i < buff.size(); ++i) {
        int ch = static_cast<int>(buff[i]);
        std::cout << std::hex << ch << " ";
      }
      std::cout << "\n";
      computed_hash = std::move(buff);
    }

    // create hash
    HCRYPTHASH hash_handler2 = 0;
    ResCheck(symbols_->dl_CryptCreateHash(csp_handler, hash_calc_type, 0, 0,
                                          &hash_handler2),
             "CryptCreateHash");
    // ResCheck(symbols_->dl_CryptSetHashParam(
    //              hash_handler, HP_OID,
    //              (BYTE *)szOID_tc26_gost_3410_12_256_paramSetA, 0),
    //          "SET HP_OID");
    ResCheck(symbols_->dl_CryptSetHashParam(hash_handler2, HP_HASHVAL,
                                            computed_hash.data(), 0),
             "set hash val");

    // digest enctypted
    std::vector<BYTE> digest_encrypted;
    {
      std::cout << "---\n";
      DWORD buff_size = 0;
      ResCheck(symbols_->dl_CryptMsgGetParam(
                   *msg_handler_, CMSG_ENCRYPTED_DIGEST, 0, 0, &buff_size),
               "get sign size");
      std::cout << " CMSG_ENCRYPTED_DIGEST size = " << buff_size << "\n";
      std::vector<BYTE> buff(buff_size, 0);
      ResCheck(symbols_->dl_CryptMsgGetParam(*msg_handler_,
                                             CMSG_ENCRYPTED_DIGEST, 0,
                                             buff.data(), &buff_size),
               "get sign");
      // std::cout << "CMSG_ENCRYPTED_DIGEST = " << VecToStr(buff) << std::endl;
      digest_encrypted = std::move(buff);
    }
    for (uint i = 0; i < digest_encrypted.size(); ++i) {
      int ch = static_cast<int>(digest_encrypted[i]);
      std::cout << std::hex << ch << " ";
    }

    std::reverse(digest_encrypted.begin(), digest_encrypted.end());
    std::cout << "sig size" << digest_encrypted.size() << "\n";

    ResCheck(symbols_->dl_CryptVerifySignatureA(
                 hash_handler2, digest_encrypted.data(),
                 digest_encrypted.size(), handler_pub_key, nullptr, 0),
             "CryptVerifySignatureA");
    if (hash_handler2 != 0) {
      symbols_->dl_CryptDestroyHash(hash_handler);
    }
    std::cout << "Verify signature ...OK" << "\n";

    // ResCheck(symbols_->dl_CryptImportKey(csp_handler,public_key_raw.data()
    // , public_key_raw.size(), 0, 0, &handler_pub_key);

    // HCRYPTKEY handler_pub_key = 0;
    //  ResCheck(symbols_->dl_CryptImportPublicKeyInfo(
    //   csp_handler, PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
    //   &(p_cert_ctx->pCertInfo->SubjectPublicKeyInfo), &handler_pub_key);

    //===============================================

    // NOLINTEND(cppcoreguidelines-pro-type-reinterpret-cast)
  } catch (const std::exception &ex) {
    if (handler_pub_key != 0) {
      symbols_->dl_CryptDestroyKey(handler_pub_key);
    }
    if (hash_handler != 0) {
      symbols_->dl_CryptDestroyHash(hash_handler);
    }
    if (csp_handler != 0) {
      symbols_->dl_CryptReleaseContext(csp_handler, 0);
    }
    std::cerr << func_name << ex.what() << "\n";
    return false;
  }
  // free

  if (handler_pub_key != 0) {
    symbols_->dl_CryptDestroyKey(handler_pub_key);
  }
  if (hash_handler != 0) {
    symbols_->dl_CryptDestroyHash(hash_handler);
  }
  if (csp_handler != 0) {
    symbols_->dl_CryptReleaseContext(csp_handler, 0);
  }
  return true;
}

[[nodiscard]] bool Message::CheckDataHash(const BytesVector &data,
                                          uint signer_index) const noexcept {
  constexpr const char *const func_name = "[CheckDataHash] ";
  // TODO(Oleg)
  //  get hash algorithm
  //  from signed attributes
  if (data.empty()) {
    std::cerr << func_name << "Can't check hash for an empty data\n";
    return false;
  }
  if (GetSignersCount() < signer_index + 1) {
    std::cerr << func_name << "Wrong signer index\n";
    return false;
  }
  // get OID of hashing algo
  auto hashing_algo = GetDataHashingAlgo(signer_index);
  if (!hashing_algo) {
    std::cerr << func_name << "Data hashing algo OID was not found\n";
    return false;
  }
  // get hash value from signed_attibutes
  auto hash_signed = GetSignedDataHash(signer_index);
  if (!hash_signed || hash_signed->empty()) {
    std::cerr << func_name << " Find signed data hash failed\n";
    return false;
  }
  // create data hash
  // compare
  // verify with crypto api
  return VeriyHash(hash_signed.value(), hashing_algo.value(), data,
                   signer_index);
}
// NOLINTEND

// NOLINTBEGIN(readability-function-cognitive-complexity)
std::optional<BytesVector>
Message::CalculateComputedHash(uint signer_index) const noexcept {
  {
    try {
      // parse the whole signature
      const AsnObj asn(raw_signature_.data(), raw_signature_.size(), symbols_);
      if (asn.IsFlat() || asn.ChildsCount() == 0) {
        return std::nullopt;
      }
      // look for content node
      u_int64_t index_content = 0;
      bool content_found = false;
      for (auto i = 0UL; i < asn.ChildsCount(); ++i) {
        const AsnObj &tmp = asn.GetChilds()[i];
        if (!tmp.IsFlat() && tmp.get_asn_header().asn_tag == AsnTag::kUnknown &&
            tmp.get_asn_header().constructed) {
          index_content = i;
          content_found = true;
          break;
        }
      }
      if (!content_found) {
        throw std::runtime_error("Content node was node found in signature");
      }
      const AsnObj &content = asn.GetChilds()[index_content];
      if (content.IsFlat() || content.ChildsCount() == 0) {
        throw std::runtime_error("Content node is empty");
      }
      // signed data node
      const AsnObj &signed_data = content.GetChilds()[0];
      if (signed_data.get_asn_header().asn_tag != AsnTag::kSequence ||
          signed_data.ChildsCount() == 0) {
        throw std::runtime_error("Signed data element is empty");
      }
      // signer infos - second set
      u_int64_t index_signers_infos = 0;
      bool signer_infos_found = false;
      u_int64_t set_num = 0;
      for (u_int64_t i = 0; i < signed_data.ChildsCount(); ++i) {
        if (signed_data.GetChilds()[i].get_asn_header().asn_tag ==
            AsnTag::kSet) {
          ++set_num;
          if (set_num == 2) {
            index_signers_infos = i;
            signer_infos_found = true;
            break;
          }
        }
      }
      if (!signer_infos_found) {
        throw std::runtime_error("signerInfos node was note found");
      }
      const AsnObj &signer_infos = signed_data.GetChilds()[index_signers_infos];
      if (signer_infos.IsFlat() || signer_infos.ChildsCount() == 0) {
        throw std::runtime_error("signerInfos node is empty");
      }
      if (signer_infos.ChildsCount() < signer_index) {
        throw std::runtime_error("no signer with such index in signers_info");
      }
      const AsnObj &signer_info = signer_infos.GetChilds()[signer_index];
      if (signer_info.IsFlat() || signer_info.ChildsCount() == 0) {
        throw std::runtime_error("Empty signerInfo node");
      }
      u_int64_t signed_attributes_index = 0;
      bool signed_attributes_found = false;
      for (u_int64_t i = 0; i < signer_info.ChildsCount(); ++i) {
        if (signer_info.GetChilds()[i].get_asn_header().asn_tag ==
            AsnTag::kUnknown) {
          signed_attributes_found = true;
          signed_attributes_index = i;
        }
      }
      if (!signed_attributes_found) {
        throw std::runtime_error("Signed attributes not found");
      }
      const AsnObj &signed_attributes =
          signer_info.GetChilds()[signed_attributes_index];

      std::cout << "childs =" << signed_attributes.ChildsCount() << "\n";

      // unparse
      auto unparsed = signed_attributes.Unparse();
      for (auto symbol : unparsed) {
        std::cout << std::hex                  //<< std::setw(2)
                  << static_cast<int>(symbol); //<< " ";
      }
      std::cout << "\n";
      unparsed[0] = 0x31;
      // calculate hash
      HCRYPTPROV csp_handler = 0;
      HCRYPTHASH hash_handler = 0;
      BytesVector data_hash_calculated;
      auto hashing_algo = GetDataHashingAlgo(signer_index);
      unsigned int provider_type = 0;
      if (hashing_algo == szOID_CP_GOST_R3411_12_256) {
        provider_type = PROV_GOST_2012_256;
      } else {
        throw std::runtime_error("unknown hashing algo");
      }
      // get CSP context
      ResCheck(symbols_->dl_CryptAcquireContextA(&csp_handler, nullptr, nullptr,
                                                 provider_type, 0),
               "CryptAcquireContextA");
      unsigned int hash_calc_type = 0;
      if (hashing_algo == szOID_CP_GOST_R3411_12_256) {
        hash_calc_type = CALG_GR3411_2012_256;
      } else {
        throw std::runtime_error("unknown hashing algo");
      }
      if (csp_handler == 0) {
        throw std::runtime_error("CSP handler == 0");
      }
      ResCheck(symbols_->dl_CryptCreateHash(csp_handler, hash_calc_type, 0, 0,
                                            &hash_handler),
               "CryptCreateHash");
      ResCheck(symbols_->dl_CryptHashData(hash_handler, unparsed.data(),
                                          unparsed.size(), 0),
               "CryptHashData");
      DWORD hash_size = 0;
      DWORD hash_size_size = sizeof(DWORD);
      // NOLINTBEGIN(cppcoreguidelines-pro-type-reinterpret-cast)
      ResCheck(symbols_->dl_CryptGetHashParam(
                   hash_handler, HP_HASHSIZE,
                   reinterpret_cast<BYTE *>(&hash_size), &hash_size_size, 0),
               "Get Hash size");
      if (hash_size == 0) {
        throw std::runtime_error("hash size == 0");
      }
      {
        auto buff = CreateBuffer(hash_size);
        buff.resize(hash_size, 0x00);
        ResCheck(symbols_->dl_CryptGetHashParam(hash_handler, HP_HASHVAL,
                                                buff.data(), &hash_size, 0),
                 "CryptGetHashParam hash value");
        data_hash_calculated = std::move(buff);
      }
      for (auto symbol : data_hash_calculated) {
        std::cout << std::hex << std::setw(2) << static_cast<int>(symbol)
                  << " ";
      }
      std::cout << "\n";
      if (hash_handler != 0) {
        symbols_->dl_CryptDestroyHash(hash_handler);
      }
      if (csp_handler != 0) {
        symbols_->dl_CryptReleaseContext(csp_handler, 0);
      }
      // NOLINTEND(cppcoreguidelines-pro-type-reinterpret-cast)
    } catch (const std::exception &ex) {
      std::cerr << "[CalculateComputedHash] " << ex.what() << "\n";
      return std::nullopt;
    }
    return std::nullopt;
  }
}
// NOLINTEND(readability-function-cognitive-complexity)

} // namespace pdfcsp::csp