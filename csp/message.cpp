#include "message.hpp"
#include "asn1.hpp"
#include "asn_tsp.hpp"
#include "cades.h"
#include "certificate.hpp"
#include "certificate_id.hpp"
#include "crypto_attribute.hpp"
#include "hash_handler.hpp"
#include "message_handler.hpp"
#include "oids.hpp"
#include "typedefs.hpp"
#include "utils.hpp"
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <exception>
#include <iostream>
#include <iterator>
#include <limits>
#include <optional>
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

[[nodiscard]] bool Message::Check(const BytesVector &data, uint signer_index,
                                  bool ocsp_check) const noexcept {
  auto signers_count = GetSignersCount();
  if (!signers_count || signers_count.value_or(0) < signer_index + 1) {
    std::cerr << "No signer with " << signer_index << " index found\n";
    return false;
  }
  // data hash
  if (!CheckDataHash(data, signer_index)) {
    std::cerr << "Data hash check failed for signer " << signer_index << "\n";
    return false;
  }
  std::cout << "Data hash...OK\n";
  // computed hash
  auto calculated_computed_hash = CalculateComputedHash(signer_index);
  if (!calculated_computed_hash) {
    std::cerr << "Error calculating computed hash value\n";
    return false;
  }
  std::cout << "Calculate COMPUTED_HASH...OK\n";
  if (calculated_computed_hash->GetValue() != GetComputedHash(signer_index)) {
    std::cerr << "The computed hash does not match for signer " << signer_index
              << "\n";
    return false;
  }
  std::cout << "Check COMPUTED_HASH...OK\n";
  // certificate hash
  if (!CheckCertificateHash(signer_index)) {
    std::cerr << "The sertificate hash does not match, signer " << signer_index
              << "\n";
    return false;
  }
  std::cout << "Check Certificate Hash...OK\n";
  // revocation status
  try {
    auto raw_certificate = GetRawCertificate(signer_index);
    if (!raw_certificate) {
      throw std::runtime_error("GetRawCertificate failed");
    }
    const Certificate cert(raw_certificate.value(), symbols_);
    if (!cert.IsTimeValid()) {
      std::cerr << "Invaid certificate time for signer " << signer_index
                << "\n";
      return false;
    }
    if (!cert.IsChainOK()) {
      std::cerr << "The certificate chain status is not ok\n";
      return false;
    }
    std::cout << "Check Certificate chain...OK\n";

    if (ocsp_check && !cert.IsOcspStatusOK()) {
      std::cerr << "OCSP status is not ok\n";
      return false;
    }
    std::cout << "Check Certificate with OSCP...OK\n";
    // get the encrypted digest
    BytesVector encrypted_digest;
    {
      auto digest = GetEncryptedDigest(signer_index);
      if (!digest) {
        throw std::runtime_error("Extract the encrypted digest failed");
      }
      std::reverse_copy(digest->cbegin(), digest->cend(),
                        std::back_inserter(encrypted_digest));
    }
    // import the public key
    HCRYPTKEY handler_pub_key = 0;
    ResCheck(symbols_->dl_CryptImportPublicKeyInfo(
                 calculated_computed_hash->get_csp_hanler(),
                 PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
                 &cert.GetContext()->pCertInfo->SubjectPublicKeyInfo,
                 &handler_pub_key),
             "CryptImportPublicKeyInfo");
    if (handler_pub_key == 0) {
      throw std::runtime_error("Import public key failed");
    }
    // verify the signature
    ResCheck(symbols_->dl_CryptVerifySignatureA(
                 calculated_computed_hash->get_hash_handler(),
                 encrypted_digest.data(), encrypted_digest.size(),
                 handler_pub_key, nullptr, 0),
             "CryptVerifySignatureA");
    std::cout << "VerifySignature ... OK\n";
    // verify TSP
    const CadesType msg_type = GetCadesTypeEx(signer_index);
    if (msg_type == CadesType::kCadesT) {
      const bool cades_t_res = CheckCadesT(signer_index);
      if (cades_t_res) {
        std::cout << "CADES_T check ...OK\n";
      } else {
        return false;
      }
    }

  } catch (const std::exception &ex) {
    std::cerr << "[Message::Check] " << ex.what() << "\n";
    return false;
  }

  // TODO(Oleg)
  //   Key usage extensions and extended key usage
  //   Subject and Issuer Information
  //  Public Key Length and Algorithm
  //  Certificate Policies
  //  check signing time
  return true;
}

bool Message::CheckCadesT(uint signer_index) const {
  auto unsigned_attributes =
      GetAttributes(signer_index, AttributesType::kUnsigned);
  if (!unsigned_attributes) {
    throw std::runtime_error("no unsigned attributes where found");
  }
  auto tsp_attribute = std::find_if(
      unsigned_attributes->get_bunch().cbegin(),
      unsigned_attributes->get_bunch().cend(), [](const CryptoAttribute &attr) {
        return attr.get_id() == asn::OID_id_aa_signatureTimeStampToken;
      });
  if (tsp_attribute == unsigned_attributes->get_bunch().cend()) {
    throw std::runtime_error("TSP attribute is not found");
  }
  if (tsp_attribute->get_blobs_count() != 1) {
    throw std::runtime_error("invalid blobs count in tsp attibute");
  }
  const asn::AsnObj tsp_asn_attr(tsp_attribute->get_blobs()[0].data(),
                                 tsp_attribute->get_blobs()[0].size(),
                                 symbols_);
  const asn::TspAttribute tsp(tsp_asn_attr);
  // TODO(Oleg) return a value
  return true;
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

/**
 * @brief Replace function for GetCadesType
 * @details Does not use CadesMsgIsType
 * @param signer_index
 * @return CadesType
 */
CadesType Message::GetCadesTypeEx(uint signer_index) const noexcept {
  CadesType res = CadesType::kUnknown;
  if (!symbols_ || !msg_handler_) {
    return res;
  }
  // check if CADES_BES
  auto signed_attributes = GetAttributes(signer_index, AttributesType::kSigned);
  if (!signed_attributes || signed_attributes->get_count() < 4) {
    return res;
  }
  const bool content_type = std::any_of(
      signed_attributes->get_bunch().cbegin(),
      signed_attributes->get_bunch().cend(), [](const CryptoAttribute &attr) {
        // RFC 3852 [11.1] Content Type
        return attr.get_id() == "1.2.840.113549.1.9.3";
      });
  const bool message_digest = std::any_of(
      signed_attributes->get_bunch().cbegin(),
      signed_attributes->get_bunch().cend(), [](const CryptoAttribute &attr) {
        // RFC 3852 [11.2] Message digest
        return attr.get_id() == "1.2.840.113549.1.9.4";
      });
  const bool signed_certificate_v2 = std::any_of(
      signed_attributes->get_bunch().cbegin(),
      signed_attributes->get_bunch().cend(), [](const CryptoAttribute &attr) {
        // RFC 5126 [5.7.3.2] Message digest
        return attr.get_id() == "1.2.840.113549.1.9.16.2.47";
      });
  // TODO(Oleg) Maybe check for signing time attribute
  if (content_type && message_digest && signed_certificate_v2) {
    res = CadesType::kCadesBes;
  } else {
    return res;
  }
  // check if CADES_T
  auto unsigned_attributes =
      GetAttributes(signer_index, AttributesType::kUnsigned);
  if (!unsigned_attributes) {
    return res;
  }
  const bool time_stamp = std::any_of(
      unsigned_attributes->get_bunch().cbegin(),
      unsigned_attributes->get_bunch().cend(), [](const CryptoAttribute &attr) {
        return attr.get_id() == "1.2.840.113549.1.9.16.2.14";
      });
  if (time_stamp) {
    res = CadesType::kCadesT;
  }
  // TODO(Oleg) check for other types
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
 * @brief Get the Signer Cert Id struct
 * @details
 * extracts the certificate ID from three sources:
 * 1. CMSG_SIGNER_CERT_INFO_PARAM
 * 2. CMSG_SIGNER_AUTH_ATTR_PARAM
 * 3. CadesMsgGetSigningCertId (temporary disabled due to memory leaks)
 * 4. compares them and returns a CertifiaceID structure if they match.
 */
[[nodiscard]] std::optional<CertificateID>
Message::GetSignerCertId(uint signer_index) const noexcept {
  //  get data from CMSG_SIGNER_CERT_INFO_PARAM
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
    auto signed_attrs = GetAttributes(signer_index, AttributesType::kSigned);
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
            const asn::AsnObj asn(attr.get_blobs()[i].data(),
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
  // using dl_CadesMsgGetSigningCertId yields a 37000-byte memory leak
  // TODO(Oleg) ask message to CSP helpdesk
  /*
  CertificateID id_from_cades;
  CRYPT_DATA_BLOB *p_cert_id_blob = nullptr;
  try {
    // using dl_CadesMsgGetSigningCertId yields a 37000-byte memory leak
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
    symbols_->dl_CadesFreeBlob(p_cert_id_blob);
  } catch (const std::exception &ex) {
    if (p_cert_id_blob != nullptr) {
      symbols_->dl_CadesFreeBlob(p_cert_id_blob);
    }
    std::cerr << func_name << ex.what();
    return std::nullopt;
  }
  // compare everything
  if (id_from_cert_info == id_from_cades &&
      id_from_cert_info == id_from_auth_attributes) {
    return id_from_auth_attributes;
  }
  */
  // compare everything
  if (id_from_cert_info == id_from_auth_attributes) {
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
Message::GetAttributes(uint signer_index, AttributesType type) const noexcept {
  try {
    unsigned int buff_size = 0;
    int attributes_type_param = 0;
    switch (type) {
    case pdfcsp::csp::AttributesType::kSigned:
      attributes_type_param = CMSG_SIGNER_AUTH_ATTR_PARAM;
      break;
    case pdfcsp::csp::AttributesType::kUnsigned:
      attributes_type_param = CMSG_SIGNER_UNAUTH_ATTR_PARAM;
      break;
    }
    ResCheck(symbols_->dl_CryptMsgGetParam(*msg_handler_, attributes_type_param,
                                           signer_index, nullptr, &buff_size),
             "Get signed attr size");
    if (buff_size == 0 ||
        buff_size > std::numeric_limits<unsigned int>::max()) {
      return std::nullopt;
    }
    auto buff = CreateBuffer(buff_size);
    ResCheck(symbols_->dl_CryptMsgGetParam(*msg_handler_, attributes_type_param,
                                           signer_index, buff.data(),
                                           &buff_size),
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
                                    [[maybe_unused]] const BytesVector &data) {
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
  // ResCheck(symbols_->dl_CryptMsgUpdate(*msg_handler_, data.data(),
  // data.size(),
  //                                      TRUE),
  //          "Load data to msg");
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
  auto signed_attr = GetAttributes(signer_index, AttributesType::kSigned);
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
        const asn::AsnObj obj(blobs[0].data(), blobs[0].size(), symbols_);
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
  try {
    HashHandler hash(hashing_algo, symbols_);
    hash.SetData(data);
    BytesVector data_hash_calculated = hash.GetValue();
    return data_hash_calculated;
  } catch (const std::exception &ex) {
    std::cerr << func_name << ex.what() << "\n";
  }
  return std::nullopt;
}

[[nodiscard]] bool Message::CheckDataHash(const BytesVector &data,
                                          uint signer_index) const noexcept {
  constexpr const char *const func_name = "[CheckDataHash] ";
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

  return calculated_data_hash == hash_signed;
  // TODO(Oleg) figure out the problem with  CSP help-desk
  // call to VeriyDataHashCades is temporaty disabled because of memory leaks
  // inCadesVerifyHash compare if (calculated_data_hash != hash_signed) {
  //   return false;
  // }
  // // verify with crypto api
  // return VeriyDataHashCades(hash_signed.value(), hashing_algo.value());
}

/**
 * @brief Verify hash with CadesVerifyHash
 * @param hash
 * @param hashing_algo
 */
bool Message::VeriyDataHashCades(
    const BytesVector &hash, const std::string &hashing_algo) const noexcept {
  PCADES_VERIFICATION_INFO p_verify_info = nullptr;
  try {
    // crypt_verify
    CRYPT_VERIFY_MESSAGE_PARA crypt_verify_params{};
    std::memset(&crypt_verify_params, 0x00, sizeof(CRYPT_VERIFY_MESSAGE_PARA));
    crypt_verify_params.cbSize = sizeof(CRYPT_VERIFY_MESSAGE_PARA);
    crypt_verify_params.dwMsgAndCertEncodingType =
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
    // cades_verify
    CADES_VERIFICATION_PARA cades_verify_params{};
    std::memset(&cades_verify_params, 0x00, sizeof(CADES_VERIFICATION_PARA));
    cades_verify_params.dwSize = sizeof(CADES_VERIFICATION_PARA);
    cades_verify_params.dwCadesType =
        InternalCadesTypeToCspType(GetCadesType());
    // verify message para
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
    const bool result = p_verify_info->dwStatus == CADES_VERIFY_SUCCESS;
    ResCheck(symbols_->dl_CadesFreeVerificationInfo(p_verify_info),
             "CadesFreeVerificationInfo");
    return result;
  } catch (const std::exception &ex) {
    if (p_verify_info != nullptr) {
      symbols_->dl_CadesFreeVerificationInfo(p_verify_info);
    }
    std::cerr << "[VerifyDataHashCades] CadesVerifyHash failed\n";
    return false;
  }
  return false;
}

BytesVector Message::ExtractRawSignedAttributes(uint signer_index) const {
  // parse the whole signature
  const asn::AsnObj asn(raw_signature_.data(), raw_signature_.size(), symbols_);
  if (asn.IsFlat() || asn.ChildsCount() == 0) {
    throw std::runtime_error(
        "Extract signed attributes failed.ASN1 obj is flat");
  }
  // look for content node
  const uint64_t index_content = FindSigContentIndex(asn);
  const asn::AsnObj &content = asn.GetChilds()[index_content];
  if (content.IsFlat() || content.ChildsCount() == 0) {
    throw std::runtime_error("Content node is empty");
  }
  // signed data node
  const asn::AsnObj &signed_data = content.GetChilds()[0];
  if (signed_data.get_asn_header().asn_tag != asn::AsnTag::kSequence ||
      signed_data.ChildsCount() == 0) {
    throw std::runtime_error("Signed data element is empty");
  }
  // signer infos - second set
  const uint64_t index_signers_infos = FindSignerInfosIndex(signed_data);
  const asn::AsnObj &signer_infos =
      signed_data.GetChilds()[index_signers_infos];
  if (signer_infos.IsFlat() || signer_infos.ChildsCount() == 0) {
    throw std::runtime_error("signerInfos node is empty");
  }
  if (signer_infos.ChildsCount() < signer_index) {
    throw std::runtime_error("no signer with such index in signers_info");
  }
  const asn::AsnObj &signer_info = signer_infos.GetChilds()[signer_index];
  if (signer_info.IsFlat() || signer_info.ChildsCount() == 0) {
    throw std::runtime_error("Empty signerInfo node");
  }
  u_int64_t signed_attributes_index = 0;
  bool signed_attributes_found = false;
  for (u_int64_t i = 0; i < signer_info.ChildsCount(); ++i) {
    if (signer_info.GetChilds()[i].get_asn_header().asn_tag ==
        asn::AsnTag::kUnknown) {
      const asn::AsnObj &tmp = signer_info.GetChilds()[i];
      // to make sure that proper node is found check if it has contentType OID
      // as first element
      if (tmp.ChildsCount() > 0 && tmp.at(0).ChildsCount() > 0 &&
          tmp.at(0).at(0).get_asn_header().asn_tag == asn::AsnTag::kOid &&
          tmp.at(0).at(0).GetStringData() == "1.2.840.113549.1.9.3") {
        signed_attributes_found = true;
        signed_attributes_index = i;
        break;
      }
    }
  }

  if (!signed_attributes_found) {
    throw std::runtime_error("Signed attributes not found");
  }
  const asn::AsnObj &signed_attributes =
      signer_info.GetChilds()[signed_attributes_index];

  // unparse
  auto unparsed = signed_attributes.Unparse();
  // change object type from Content-specific to SET
  unparsed[0] = 0x31;
  return unparsed;
}

std::optional<HashHandler>
Message::CalculateComputedHash(uint signer_index) const noexcept {
  {
    try {
      auto unparsed = ExtractRawSignedAttributes(signer_index);
      auto hashing_algo = GetDataHashingAlgo(signer_index);
      if (!hashing_algo) {
        throw std::runtime_error("Hashing algorithm was no found");
      }
      HashHandler hash(hashing_algo.value(), symbols_);
      hash.SetData(unparsed);
      return hash;
    } catch (const std::exception &ex) {
      std::cerr << "[CalculateComputedHash] " << ex.what() << "\n";
      return std::nullopt;
    }
    return std::nullopt;
  }
}

/**
 * @brief Calculate a Certificate hash from raw certificate
 * @param signer_index
 * @return std::optional<BytesVector>
 */
[[nodiscard]] std::optional<HashHandler>
Message::CalculateCertHash(uint signer_index) const noexcept {
  try {
    auto raw_cert = GetRawCertificate(signer_index);
    if (!raw_cert) {
      throw std::runtime_error("Error extracting the raw cerificate");
    }
    auto hashing_algo = GetDataHashingAlgo(signer_index);
    if (!hashing_algo) {
      throw std::runtime_error("Hashing algorithm was no found");
    }
    HashHandler hash(hashing_algo.value(), symbols_);
    hash.SetData(raw_cert.value());
    return hash;

  } catch (const std::exception &ex) {
    std::cerr << "[CalculateCertHash] " << ex.what() << "\n";
    return std::nullopt;
  }
  return std::nullopt;
}

/**
 * @brief Calculate signer's cerificate hash and compare it with hash from
 * signed attributes
 * @param signer_index
 */
[[nodiscard]] bool
Message::CheckCertificateHash(uint signer_index) const noexcept {
  constexpr const char *const func_name = "CheckCertificateHash";
  auto cert_id = GetSignerCertId(signer_index);
  if (!cert_id) {
    std::cerr << func_name << "Certificate id was not found\n";
    return false;
  }
  auto cert_hash = CalculateCertHash(signer_index);
  if (!cert_hash) {
    std::cerr << "Calculate hash for signer's ceritifiacte failed\n";
    return false;
  }
  return cert_hash->GetValue() == cert_id->hash_cert;
}

std::optional<BytesVector>
Message::GetComputedHash(uint signer_index) const noexcept {
  try {
    DWORD buff_size = 0;
    ResCheck(symbols_->dl_CryptMsgGetParam(*msg_handler_,
                                           CMSG_COMPUTED_HASH_PARAM,
                                           signer_index, nullptr, &buff_size),
             "Get COMPUTED_HASH");
    if (buff_size == 0) {
      throw std::runtime_error("Get COMPUTED_HASH size failed");
    }
    BytesVector buff = CreateBuffer(buff_size);
    buff.resize(buff_size, 0x00);
    ResCheck(
        symbols_->dl_CryptMsgGetParam(*msg_handler_, CMSG_COMPUTED_HASH_PARAM,
                                      signer_index, buff.data(), &buff_size),
        "Get COMPUTED_HASH failed");
    return buff;
  } catch (const std::exception &ex) {
    std::cerr << "[GetComputedHash] " << ex.what() << "\n";
  }
  return std::nullopt;
}

std::optional<BytesVector>
Message::GetEncryptedDigest(uint signer_index) const noexcept {
  try {
    DWORD buff_size = 0;
    ResCheck(symbols_->dl_CryptMsgGetParam(*msg_handler_, CMSG_ENCRYPTED_DIGEST,
                                           signer_index, nullptr, &buff_size),
             "Get COMPUTED_HASH");
    if (buff_size == 0) {
      throw std::runtime_error("Get CMSG_ENCRYPTED_DIGEST size failed");
    }
    BytesVector buff = CreateBuffer(buff_size);
    buff.resize(buff_size, 0x00);
    ResCheck(symbols_->dl_CryptMsgGetParam(*msg_handler_, CMSG_ENCRYPTED_DIGEST,
                                           signer_index, buff.data(),
                                           &buff_size),
             "Get COMPUTED_HASH failed");
    return buff;
  } catch (const std::exception &ex) {
    std::cerr << "[GetEncryptedDigest] " << ex.what() << "\n";
  }
  return std::nullopt;
}

} // namespace pdfcsp::csp