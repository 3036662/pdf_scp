#include "message.hpp"
#include "asn1.hpp"
#include "cades.h"
#include "certificate_id.hpp"
#include "crypto_attribute.hpp"
#include "message_handler.hpp"
#include "typedefs.hpp"
#include "utils.hpp"
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
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

/**
 * @details
 * extracts the certificate ID from three sources:
 * 1. CMSG_SIGNER_CERT_INFO_PARAM
 * 2. CMSG_SIGNER_AUTH_ATTR_PARAM
 * 3. CadesMsgGetSigningCertId
 * 4. compares them and returns a CertifiaceID structure if they match.
 */

[[nodiscard]] std::optional<CertificateID>
Message::GetSignerCertId(uint signer_index) const noexcept {
  // get data from CMSG_SIGNER_CERT_INFO_PARAM
  DWORD buff_size = 0;
  CertificateID id_from_cert_info;
  constexpr const char *const func_name = "[GetSignerCertId] ";
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
      throw std::runtime_error("empty data from _CERT_INFO");
    }
    id_from_cert_info.serial = std::move(res.value());
    CERT_NAME_BLOB *p_issuer_blob = &p_cert_info->Issuer;
    auto res_issuer = NameBlobToString(p_issuer_blob, symbols_);
    if (!res_issuer) {
      throw std::runtime_error("Empty issuer from _CERT_INFO");
    }
    id_from_cert_info.issuer = std::move(res_issuer.value());
  } catch ([[maybe_unused]] const std::exception &ex) {
    std::cerr << func_name << ex.what() << "\n";
    return std::nullopt;
  }
  // get data from CMSG_SIGNER_AUTH_ATTR_PARAM
  CertificateID id_from_auth_attributes;
  {
    auto signed_attrs = GetSignedAttributes(signer_index);
    if (!signed_attrs.has_value()) {
      std::cerr << func_name << "No signed attributes\n";
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
          std::cerr << func_name << ex.what();
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
    std::cerr << func_name << ex.what();
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

/**
 * @details copies CMSG_SIGNER_AUTH_ATTR_PARAM to array of
 * CryptoAttribute objects
 */
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

/**
 * @details gets number of Certificates from CMSG_CERT_COUNT_PARAM
 * @return std::optional<uint>
 */
std::optional<uint>
Message::GetCertCount(uint64_t signer_index) const noexcept {
  if (!symbols_ || !msg_handler_) {
    return std::nullopt;
  }
  DWORD buff_size = sizeof(DWORD);
  DWORD number_of_certs = 0;
  try {
    ResCheck(symbols_->dl_CryptMsgGetParam(*msg_handler_, CMSG_CERT_COUNT_PARAM,
                                           signer_index, &number_of_certs,
                                           &buff_size),
             "Get revoked certs count");
  } catch ([[maybe_unused]] const std::exception &ex) {
    return std::nullopt;
  }
  return number_of_certs;
}

/**
 * @brief Returns a raw signer's certificate.
 * @param index
 * @return std::optional<BytesVector>
 */
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

/**
 * @brief Decode raw message
 * @param sig a raw signature data
 * @param data a raw signed data
 * @throws std::runtime exception on fail
 * @details wraps a message handler to RAII object and puts it in a private
 * field
 */
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

/**
 * @brief Extracts the ID of an algorithm that is used for data hashing
 * @param signer_index
 * @return std::optional<std::string>
 * @details extracts the id from two sources:
 * 1.signed attributes certificate info.
 * 2.CMSG_SIGNER_HASH_ALGORITHM_PARAM.
 * Compares these two values and returns first if they match.
 */
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
    const auto *ptr_ctypt_id =
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

/**
 * @brief Gets the data hash from signed attributes -
 * szOID_PKCS_9_MESSAGE_DIGEST
 * @param signer_index
 * @return std::optional<BytesVector>
 */
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

std::optional<BytesVector>
Message::CalculateDataHash(const std::string &hashing_algo,
                           const BytesVector &data) const noexcept {
  constexpr const char *const func_name = "[CalculateDataHash] ";
  HCRYPTPROV csp_handler = 0;
  HCRYPTHASH hash_handler = 0;
  try {
    // get a CSP context
    const uint64_t provider_type = GetProviderType(hashing_algo);
    ResCheck(symbols_->dl_CryptAcquireContextA(&csp_handler, nullptr, nullptr,
                                               provider_type, 0),
             "CryptAcquireContextA");
    if (csp_handler == 0) {
      throw std::runtime_error("CSP handler == 0");
    }
    // get a hash valuse
    const unsigned int hash_calc_type = GetHashCalcType(hashing_algo);
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
    // NOLINTEND(cppcoreguidelines-pro-type-reinterpret-cast)
    if (hash_size == 0) {
      throw std::runtime_error("hash size == 0");
    }
    BytesVector data_hash_calculated;
    data_hash_calculated.resize(hash_size, 0x00);
    ResCheck(symbols_->dl_CryptGetHashParam(hash_handler, HP_HASHVAL,
                                            data_hash_calculated.data(),
                                            &hash_size, 0),
             "CryptGetHashParam hash value");
    // free resources
    if (hash_handler != 0) {
      symbols_->dl_CryptDestroyHash(hash_handler);
    }
    if (csp_handler != 0) {
      symbols_->dl_CryptReleaseContext(csp_handler, 0);
    }
    return data_hash_calculated;
  } catch (const std::exception &ex) {
    if (hash_handler != 0) {
      symbols_->dl_CryptDestroyHash(hash_handler);
    }
    if (csp_handler != 0) {
      symbols_->dl_CryptReleaseContext(csp_handler, 0);
    }
    std::cerr << func_name << ex.what() << "\n";
  }
  return std::nullopt;
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
  auto calculated_data_hash = CalculateDataHash(hashing_algo.value(), data);
  if (!calculated_data_hash || calculated_data_hash->empty()) {
    std::cerr << func_name << "Calculate data hash failed\n";
    return false;
  }
  // compare
  if (calculated_data_hash != hash_signed) {
    return false;
  }

  // verify with crypto api
  return VeriyDataHashCades(hash_signed.value(), hashing_algo.value());
}

/**
 * @brief Verify hash with CadesVerifyHash
 * @param hash
 * @param hashing_algo
 */
bool Message::VeriyDataHashCades(
    const BytesVector &hash, const std::string &hashing_algo) const noexcept {
  try {
    PCADES_VERIFICATION_INFO p_verify_info = nullptr;
    CRYPT_VERIFY_MESSAGE_PARA crypt_verify_params{};
    std::memset(&crypt_verify_params, 0x00, sizeof(CRYPT_VERIFY_MESSAGE_PARA));
    crypt_verify_params.cbSize = sizeof(CRYPT_VERIFY_MESSAGE_PARA);
    CADES_VERIFICATION_PARA cades_verify_params{};
    std::memset(&cades_verify_params, 0x00, sizeof(CADES_VERIFICATION_PARA));
    cades_verify_params.dwSize = sizeof(CADES_VERIFICATION_PARA);
    cades_verify_params.dwCadesType =
        InternalCadesTypeToCspType(GetCadesType());
    crypt_verify_params.dwMsgAndCertEncodingType =
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
    CADES_VERIFY_MESSAGE_PARA verify_params{};
    std::memset(&verify_params, 0x00, sizeof(CADES_VERIFY_MESSAGE_PARA));
    verify_params.dwSize = sizeof(CADES_VERIFY_MESSAGE_PARA);
    verify_params.pVerifyMessagePara = &crypt_verify_params;
    verify_params.pCadesVerifyPara = &cades_verify_params;
    CRYPT_ALGORITHM_IDENTIFIER alg;
    memset(&alg, 0x00, sizeof(CRYPT_ALGORITHM_IDENTIFIER));
    std::vector<char> tmp_buff;
    std::copy(hashing_algo.cbegin(), hashing_algo.cend(),
              std::back_inserter(tmp_buff));
    tmp_buff.push_back(0x00);
    alg.pszObjId = tmp_buff.data();
    ResCheck(symbols_->dl_CadesVerifyHash(&verify_params, 0,
                                          raw_signature_.data(),
                                          raw_signature_.size(), hash.data(),
                                          hash.size(), &alg, &p_verify_info),
             "CadesVerifyHash");
    return p_verify_info->dwStatus == CADES_VERIFY_SUCCESS;
  } catch (const std::exception &ex) {
    std::cerr << "[VerifyDataHashCades] CadesVerifyHash failed\n";
    return false;
  }
  return false;
}

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