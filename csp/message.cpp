#include "message.hpp"
#include "asn1.hpp"
#include "cades.h"
#include "certificate.hpp"
#include "certificate_id.hpp"
#include "crypto_attribute.hpp"
#include "hash_handler.hpp"
#include "i_check_stategy.hpp"
#include "message_handler.hpp"
#include "oids.hpp"
#include "pks_checks.hpp"
#include "resolve_symbols.hpp"
#include "typedefs.hpp"
#include "utils.hpp"
#include "utils_cert.hpp"
#include "utils_msg.hpp"
#include "x_checks.hpp"
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <exception>
#include <iostream>
#include <limits>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <sys/types.h>
#include <vector>

namespace pdfcsp::csp {

// check resolver and data and call DecodeDetachedMessage
Message::Message(std::shared_ptr<ResolvedSymbols> dlsymbols,
                 const BytesVector &raw_signature, MessageType msg_type)
    : symbols_(std::move(dlsymbols)), raw_signature_(raw_signature),
      msg_type_(msg_type) {
  if (!symbols_) {
    throw std::runtime_error("Symbol resolver is null");
  }
  if (raw_signature.empty()) {
    throw std::runtime_error("The signature is empty");
  }
  DecodeMessage(raw_signature);
}

/**
 * @brief Check an attached message
 * @details Create a data hash, than performs chech with Check()
 * @param signer_index
 * @param ocsp_check enable/disable ocsp check
 * @throws runtime_error
 */
bool Message::CheckAttached(uint signer_index, bool ocsp_check) const {
  const BytesVector conent_data = GetContentFromAttached();
  return Check(conent_data, signer_index, ocsp_check);
}

/// @brief Extracts the eContent of the message
BytesVector Message::GetContentFromAttached() const {
  // retrieve a data
  DWORD data_size = 0;
  ResCheck(symbols_->dl_CryptMsgGetParam(*msg_handler_, CMSG_CONTENT_PARAM, 0,
                                         nullptr, &data_size),
           "Get CMSG_CONTENT_PARAM size");
  if (data_size == 0) {
    throw std::runtime_error("Get content failed");
  }
  BytesVector buff_data = CreateBuffer(data_size);
  buff_data.resize(data_size, 0x00);
  ResCheck(symbols_->dl_CryptMsgGetParam(*msg_handler_, CMSG_CONTENT_PARAM, 0,
                                         buff_data.data(), &data_size),
           "Get CMSG_CONTENT_PARAM size");
  return buff_data;
}

/**
 * @brief Returns the summary of the Comprehensive message check
 * @param data a raw data
 * @param signer_index
 * @param ocsp_check enable/disable an ocsp check
 * @throws runtime error
 */
[[nodiscard]] bool Message::Check(const BytesVector &data, uint signer_index,
                                  bool ocsp_check) const noexcept {

  auto check_result = ComprehensiveCheck(data, signer_index, ocsp_check);
  return check_result.check_summary;
}

/**
 * @brief Comprehensive message check
 * @param data a raw data
 * @param signer_index
 * @param ocsp_check enable/disable an ocsp check
 */
checks::CheckResult
Message::ComprehensiveCheck(const BytesVector &data, uint signer_index,
                            bool ocsp_check) const noexcept {
  try {
    // choose strategy
    auto msg_type = GetCadesTypeEx(signer_index);

    std::unique_ptr<checks::ICheckStrategy> check_strategy;
    switch (msg_type) {
    case CadesType::kCadesBes:
      check_strategy = std::make_unique<checks::BesChecks>(
          this, signer_index, ocsp_check, symbols_);
      break;
    case CadesType::kCadesT:
      check_strategy = std::make_unique<checks::TChecks>(this, signer_index,
                                                         ocsp_check, symbols_);
      break;
    case CadesType::kCadesXLong1:
      check_strategy = std::make_unique<checks::XChecks>(this, signer_index,
                                                         ocsp_check, symbols_);
      break;
    case CadesType::kPkcs7:
      check_strategy = std::make_unique<checks::PksChecks>(
          this, signer_index, ocsp_check, symbols_);
      break;
    default:
      std::cerr << "Message type "
                << utils::message::InternalCadesTypeToString(msg_type) << "\n";
      throw std::runtime_error("No check strategy for this type of message ");
      break;
    }
    return check_strategy->All(data);
  } catch (const std::exception &ex) {
    std::cerr << "[Message::Check] " << ex.what() << "\n";
    return {};
  }
}

/**
 * @brief Set the Explicit Certificate for signer with index
 * @param signer_index
 * @param raw_cert an encoded certificate
 */
void Message::SetExplicitCertForSigner(uint signer_index,
                                       BytesVector raw_cert) noexcept {
  if (raw_cert.empty()) {
    std::cerr << "[SetExplicitCertForSigner] Can't set empty data as "
                 "signer's cert\n";
    return;
  }
  raw_certs_.erase(signer_index);
  raw_certs_.emplace(signer_index, std::move(raw_cert));
}

[[deprecated("Gives non reliable unswers,replaced with "
             "Message::GetCadesTypeEx")]] CadesType
Message::GetCadesType() const noexcept {
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
  auto unsigned_attributes =
      GetAttributes(signer_index, AttributesType::kUnsigned);
  if (!signed_attributes && !unsigned_attributes) {
    return CadesType::kPkcs7;
  }
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
  if (!unsigned_attributes) {
    return res;
  }
  const uint tsp_attr_count = utils::message::CountAttributesWithOid(
      unsigned_attributes.value(), asn::kOID_id_aa_signatureTimeStampToken);
  const uint cert_refs_count = utils::message::CountAttributesWithOid(
      unsigned_attributes.value(), asn::kOID_id_aa_ets_certificateRefs);
  const uint revoc_ref_count = utils::message::CountAttributesWithOid(
      unsigned_attributes.value(), asn::kOID_id_aa_ets_revocationRefs);
  const uint cert_val_attr_count = utils::message::CountAttributesWithOid(
      unsigned_attributes.value(), asn::kOID_id_aa_ets_certValues);
  const uint revoc_val_attr_count = utils::message::CountAttributesWithOid(
      unsigned_attributes.value(), asn::kOID_id_aa_ets_revocationValues);
  const uint esc_tsp_attr_count = utils::message::CountAttributesWithOid(
      unsigned_attributes.value(), asn::kOid_id_aa_ets_escTimeStamp);
  // check if CADES_T
  if (tsp_attr_count > 0) {
    res = CadesType::kCadesT;
  }
  // check if CADES_X_LONG_TYPE1
  // For each of these attributes, only one instance is expected
  if (cert_refs_count > 1 || revoc_ref_count > 1 || cert_val_attr_count > 1 ||
      revoc_val_attr_count > 1) {
    res = CadesType::kUnknown;
    return res;
  }
  if ((tsp_attr_count > 0 || is_tsp_message_) && cert_refs_count == 1 &&
      revoc_ref_count == 1 && cert_val_attr_count == 1 &&
      revoc_val_attr_count == 1 &&
      (esc_tsp_attr_count > 0 || is_tsp_message_)) {
    res = CadesType::kCadesXLong1;
  }
  return res;
}

/// @brief get number of signers
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

/// @brief get number of revoced certificates
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
[[nodiscard]] std::optional<asn::CertificateID>
Message::GetSignerCertId(uint signer_index) const noexcept {
  //  get data from CMSG_SIGNER_CERT_INFO_PARAM
  DWORD buff_size = 0;
  asn::CertificateID id_from_cert_info;
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

    auto res_issuer =
        NameBlobToStringEx(p_issuer_blob->pbData, p_issuer_blob->cbData);
    // gives valgring errors
    // auto res_issuer = NameBlobToString(p_issuer_blob, symbols_);
    if (!res_issuer) {
      throw std::runtime_error("Empty issuer from _CERT_INFO");
    }
    id_from_cert_info.issuer = std::move(res_issuer.value());
  } catch ([[maybe_unused]] const std::exception &ex) {
    std::cerr << func_name << ex.what() << "\n";
    return std::nullopt;
  }
  // false by default, true for pksc7
  if (is_primitive_pks_) {
    return id_from_cert_info;
  }
  // get data from CMSG_SIGNER_AUTH_ATTR_PARAM
  asn::CertificateID id_from_auth_attributes;
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
                                  attr.get_blobs()[i].size());
            id_from_auth_attributes = asn::CertificateID(asn);
          }
        } catch (const std::exception &ex) {
          std::cerr << func_name << ex.what();
          return std::nullopt;
        }
        break;
      }
    }
  }
  // compare everything
  if (id_from_cert_info == id_from_auth_attributes) {
    return id_from_auth_attributes;
  }
  return std::nullopt;
}

/**
 * @brief Get the Signers signing time
 * @return std::optional<time_t>
 */
[[nodiscard]] std::optional<time_t>
Message::GetSignersTime(uint signer_index) const noexcept {
  auto signed_attrs = GetAttributes(signer_index, AttributesType::kSigned);
  if (!signed_attrs.has_value()) {
    return std::nullopt;
  }
  auto it_signed_time = std::find_if(
      signed_attrs->get_bunch().cbegin(), signed_attrs->get_bunch().cend(),
      [](const CryptoAttribute &attr) {
        return attr.get_id() == asn::kOid_id_signingTime;
      });
  try {
    if (it_signed_time != signed_attrs->get_bunch().cend() &&
        it_signed_time->get_blobs_count() == 1) {
      auto time_blob = it_signed_time->get_blobs().at(0);
      const asn::AsnObj time_asn(time_blob.data(), time_blob.size());
      if (time_asn.AsnTag() == asn::AsnTag::kUTCTime &&
          time_asn.StringData().has_value()) {
        const std::string time_str = time_asn.StringData().value_or("");
        auto parsed_time = UTCTimeToTimeT(time_str);
        return parsed_time.time + parsed_time.gmt_offset;
      }
    }
  } catch (const std::exception &ex) {
    std::cerr << "[Message::GetSignersTime] error extracting signing time"
              << ex.what() << "\n";
    return std::nullopt;
  }
  return std::nullopt;
}

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
  // look for cert within the message
  try {
    ResCheck(symbols_->dl_CryptMsgGetParam(*msg_handler_, CMSG_CERT_PARAM,
                                           index, nullptr, &buff_size),
             "Get the raw certificate size");
    if (buff_size == 0) {
      throw std::runtime_error("empty cert");
    }
    BytesVector buff = CreateBuffer(buff_size);
    buff.resize(buff_size, 0x00);
    ResCheck(symbols_->dl_CryptMsgGetParam(*msg_handler_, CMSG_CERT_PARAM,
                                           index, buff.data(), &buff_size),
             "Get raw certificate");
    return buff;
  } catch (const std::exception &) {
    // if no cert within the message look in explicitly set certs
    // std::cout << "raw_certs count =" << raw_certs_.size() << "\n";
    if (raw_certs_.count(index) != 0) {
      return raw_certs_.at(index);
    }
    std::cerr << "[GetRawCertificate] No certificate for signer " << index
              << " was found in message" << "\n";
    return std::nullopt;
  }
  return std::nullopt;
}

/**
 * @brief Look for the signer's certificate in the x_long embedded certificates
 * and system store.
 * @param tsp_message
 * @param tsp_signer_index
 * @return std::optional<Certificate>
 */
[[nodiscard]] std::optional<Certificate>
Message::FindTspCert(const Message &tsp_message,
                     uint tsp_signer_index) const noexcept {
  auto signers_raw_cert = tsp_message.GetRawCertificate(tsp_signer_index);
  if (!signers_raw_cert) {
    // get the serial
    auto cert_id = tsp_message.GetSignerCertId(tsp_signer_index);
    if (!cert_id) {
      std::cerr << "Can't find signer's certificate ID\n";
      return std::nullopt;
    }
    std::cout << "[FindTspCert] Looking for cert:\n";
    // find cert in embedded to tsp_message certVals
    {
      std::cout << "[FindTspCert] looking for cert in tsp embedded certs:\n";
      auto unsigned_attributes = tsp_message.GetAttributes(
          tsp_signer_index, AttributesType::kUnsigned);
      if (unsigned_attributes) {
        auto tsp_cert_vals = utils::message::ExtractCertVals(
            unsigned_attributes.value(), symbols_);
        auto it_cert =
            std::find_if(tsp_cert_vals.cbegin(), tsp_cert_vals.cend(),
                         [&cert_id](const Certificate &cert) {
                           return cert.Serial() == cert_id->serial;
                         });
        if (it_cert != tsp_cert_vals.cend()) {
          std::cout << "[FindTspCert] Found in tsp message certVals\n";
          signers_raw_cert = it_cert->GetRawCopy();
          return Certificate(signers_raw_cert.value(), symbols_);
        }
      }
    }
    // find cert in store
    auto cert = utils::cert::FindCertInStoreByID(cert_id.value(),
                                                 L"addressbook", symbols_);
    if (!cert) {
      std::cerr << "Error getting signers certificate\n";
      return std::nullopt;
    }
    return cert;
  }

  try {
    return Certificate(signers_raw_cert.value(), symbols_);
  } catch (const std::exception &ex) {
    std::cerr << ex.what() << "\n";
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
void Message::DecodeMessage(const BytesVector &sig) {
  // create new message
  const DWORD detached_flag =
      msg_type_ == MessageType::kDetached ? CMSG_DETACHED_FLAG : 0;
  msg_handler_ = MsgDescriptorWrapper(
      symbols_->dl_CryptMsgOpenToDecode(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                        detached_flag, 0, 0, nullptr, nullptr),
      symbols_);
  if (!msg_handler_) {
    throw std::runtime_error("CryptMsgOpenToDecode failed");
  }
  // load data to message

  ResCheck(
      symbols_->dl_CryptMsgUpdate(*msg_handler_, sig.data(), sig.size(), TRUE),
      "Msg update with data");

  // check if not CADES
  const uint64_t signers_count = GetSignersCount().value_or(0);
  uint64_t pks_count = 0;
  for (uint64_t sign_index = 0; sign_index < signers_count; ++sign_index) {
    if (GetCadesTypeEx(sign_index) == CadesType::kPkcs7) {
      ++pks_count;
    }
  }
  is_primitive_pks_ = signers_count > 0 && signers_count == pks_count;
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
    if (is_primitive_pks_) {
      return algo_oid_from_signer_info;
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
        const asn::AsnObj obj(blobs[0].data(), blobs[0].size());
        const auto &digest = obj.Data();
        if (digest.empty()) {
          std::cerr << func_name << "no MESSAGE_DIGEST found\n";
          return std::nullopt;
        }
        return digest;
      } catch (const std::exception &ex) {
        std::cerr << func_name << ex.what() << "\n";
        return std::nullopt;
      }
      break;
    }
  }
  return std::nullopt;
}

/**
 * @brief Calculate a hash value for data
 * @param hashing_algo
 * @param data
 * @return std::optional<BytesVector>
 */
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

/**
 * @brief extracts signed attributes from a raw signature
 * @param signer_index
 * @return BytesVector
 * @throws runtime_error
 */
BytesVector Message::ExtractRawSignedAttributes(uint signer_index) const {
  // parse the whole signature
  // PrintBytes(raw_signature_);
  const asn::AsnObj signer_info =
      utils::message::ExtractAsnSignersInfo(signer_index, raw_signature_);
  u_int64_t signed_attributes_index = 0;
  bool signed_attributes_found = false;
  for (u_int64_t i = 0; i < signer_info.Size(); ++i) {
    if (signer_info.Childs()[i].Header().asn_tag == asn::AsnTag::kUnknown &&
        signer_info.Childs()[i].ParseChoiceNumber() == 0) {
      const asn::AsnObj &tmp = signer_info.Childs()[i];
      // to make sure that proper node is found check if it has contentType
      // OID as first element
      if (tmp.Size() > 0 && tmp.at(0).Size() > 0 &&
          tmp.at(0).at(0).Header().asn_tag == asn::AsnTag::kOid &&
          tmp.at(0).at(0).StringData() == "1.2.840.113549.1.9.3") {
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
      signer_info.Childs()[signed_attributes_index];
  // unparse
  auto unparsed = signed_attributes.Unparse();
  // change object type from Content-specific to SET
  unparsed[0] = 0x31;
  return unparsed;
}

/**
 * @brief Calculate a COMPUTED_HASH VALUE from raw data of signed attributes
 * @param signer_index
 * @return std::optional<HashHandler>
 */
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
 * @brief Get the Computed Hash value from CryptoApi
 * @param signer_index
 * @return std::optional<BytesVector>
 */
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

/// @brief returns CMSG_ENCRYPTED_DIGEST (signature)
std::optional<BytesVector>
Message::GetEncryptedDigest(uint signer_index) const noexcept {
  try {
    DWORD buff_size = 0;
    ResCheck(symbols_->dl_CryptMsgGetParam(*msg_handler_, CMSG_ENCRYPTED_DIGEST,
                                           signer_index, nullptr, &buff_size),
             "Get CMSG_ENCRYPTED_DIGEST");
    if (buff_size == 0) {
      throw std::runtime_error("Get CMSG_ENCRYPTED_DIGEST size failed");
    }
    BytesVector buff = CreateBuffer(buff_size);
    buff.resize(buff_size, 0x00);
    ResCheck(symbols_->dl_CryptMsgGetParam(*msg_handler_, CMSG_ENCRYPTED_DIGEST,
                                           signer_index, buff.data(),
                                           &buff_size),
             "Get CMSG_ENCRYPTED_DIGEST failed");
    return buff;
  } catch (const std::exception &ex) {
    std::cerr << "[GetEncryptedDigest] " << ex.what() << "\n";
  }
  return std::nullopt;
}

/**
 * @brief extracts unsigned attributes from a raw signature
 * @param signer_index
 * @return AsnObj containig unsigned attributes
 * @throws runtime_error
 */
asn::AsnObj Message::ExtractUnsignedAttributes(uint signer_index) const {
  const asn::AsnObj signer_info =
      utils::message::ExtractAsnSignersInfo(signer_index, raw_signature_);
  u_int64_t unsigned_attributes_index = 0;
  bool unsigned_attributes_found = false;
  for (u_int64_t i = 0; i < signer_info.Size(); ++i) {
    if (signer_info.Childs()[i].Header().asn_tag == asn::AsnTag::kUnknown) {
      const asn::AsnObj &tmp = signer_info.Childs()[i];
      // skip signed
      if (tmp.Size() > 0 && tmp.at(0).Size() > 0 &&
          tmp.at(0).at(0).Header().asn_tag == asn::AsnTag::kOid &&
          tmp.at(0).at(0).StringData() == "1.2.840.113549.1.9.3") {
        continue;
      }
      unsigned_attributes_found = true;
      unsigned_attributes_index = i;
    }
  }
  if (!unsigned_attributes_found) {
    throw std::runtime_error("Unsigned attributes not found");
  }
  return signer_info.Childs()[unsigned_attributes_index];
}

} // namespace pdfcsp::csp