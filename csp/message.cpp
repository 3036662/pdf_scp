#include "message.hpp"
#include "asn1.hpp"
#include "certificate_id.hpp"
#include "crypto_attribute.hpp"
#include "message_handler.hpp"
#include "typedefs.hpp"
#include "utils.hpp"
#include <cstddef>
#include <exception>
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
    : symbols_(std::move(dlsymbols)) {
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
    return id_from_cert_info;
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

} // namespace pdfcsp::csp