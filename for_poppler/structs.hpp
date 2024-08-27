#pragma once
#include "obj_storage.hpp"
#include <cstdint>
#include <ctime>
#include <ios>
#include <sstream>
#include <string>
#include <vector>

namespace pdfcsp::poppler {

using BytesVector = std::vector<unsigned char>;

// ENUMS

enum class SigStatus : uint8_t {
  Valid = 0,          ///< The signature is cryptographically valid.
  Invalid = 1,        ///< The signature is cryptographically invalid.
  DigestMismatch = 2, ///< The document content was changed after the signature
                      ///< was applied.
  DecodingError = 3,  ///< The signature CMS/PKCS7 structure is malformed.
  GenericError = 4,   ///< The signature could not be verified.
  NotFound = 5,   ///< The requested signature is not present in the document.
  NotVerified = 6 ///< The signature is not yet verified.
};

enum class CertStatus : uint8_t {
  Trusted = 0,         ///< The certificate is considered trusted.
  UntrustedIssuer = 1, ///< The issuer of this certificate has been marked as
                       ///< untrusted by the user.
  UnknownIssuer = 2,   ///< The certificate trust chain has not finished in a
                       ///< trusted root certificate.
  Revoked = 3,      ///< The certificate was revoked by the issuing certificate
                    ///< authority.
  Expired = 4,      ///< The signing time is outside the validity bounds of this
                    ///< certificate.
  GenericError = 5, ///< The certificate could not be verified.
  NotVerified = 6   ///< The certificate is not yet verified.
};

enum class HashAlgorithm : uint8_t {
  Unknown = 0,
  Md2 = 1,
  Md5 = 2,
  Sha1 = 3,
  Sha256 = 4,
  Sha384 = 5,
  Sha512 = 6,
  Sha224 = 7,
  GOST_R3411_12_256 = 8
};

enum class KeyLocation : uint8_t {
  Unknown = 0, /** We don't know the location */
  Other =
      1, /** We know the location, but it is somehow not covered by this enum */
  Computer = 2, /** The key is on this computer */
  HardwareToken =
      3 /** The key is on a dedicated hardware token, either a smartcard
         or a dedicated usb token (e.g. gnuk, nitrokey or yubikey) */
};

enum class PublicKeyType : uint8_t {
  RSAKEY = 0,
  DSAKEY = 1,
  ECKEY = 2,
  OTHERKEY = 3
};

// POD Structs

struct PodParam {
  uint64_t *byte_range_arr = nullptr;
  uint64_t byte_ranges_size = 0;
  const unsigned char *raw_signature_data = nullptr;
  uint64_t raw_signature_size = 0;
  const char *file_path = nullptr;
  uint64_t file_path_size = 0;
};

struct PodResult {
  SigStatus signature_val_status = SigStatus::NotVerified;
  CertStatus certificate_val_status = CertStatus::NotVerified;
  // cert_info - issuer
  const char *issuer_common_name = nullptr;
  const char *issuer_distinguished_name = nullptr;
  const char *issuer_email = nullptr;
  const char *issuer_organization = nullptr;
  // cert_info - subject
  const char *subj_common_name = nullptr;
  const char *subj_distinguished_name = nullptr;
  const char *subj_email = nullptr;
  const char *subj_organization = nullptr;
  // cert_info - PublicKeyInfo
  const unsigned char *public_key = nullptr;
  uint64_t public_key_size = 0;
  PublicKeyType public_key_type = PublicKeyType::OTHERKEY;
  uint32_t public_key_stength = 0;
  // cert_info - validity
  time_t not_before = 0;
  time_t not_after = 0;
  // cert_info serial
  const unsigned char *cert_serial = nullptr;
  uint64_t cert_serial_size = 0;
  // cert_info cert_der encoded
  const unsigned char *cert_der = nullptr;
  uint64_t cert_der_size = 0;
  // cert_ingo cert_nick
  const char *cert_nick = nullptr;
  // key usage extensions
  uint32_t ku_extensions = 0;
  // key location
  KeyLocation key_location = KeyLocation::Unknown;
  // ESInfo
  const char *signers_name = nullptr;
  const char *signer_subject_dn = nullptr;
  HashAlgorithm hash_algorithm = HashAlgorithm::Unknown;
  time_t signing_time = 0;
  // signature
  const unsigned char *signature = nullptr;
  uint64_t signature_size = 0;
  ObjStorage *p_stor = nullptr;
};

// Srtucts

struct EntityInfo {
  std::string commonName;
  std::string distinguishedName;
  std::string email;
  std::string organization;
};

struct PublicKeyInfo {
  BytesVector publicKey;
  PublicKeyType publicKeyType = PublicKeyType::OTHERKEY;
  unsigned int publicKeyStrength = 0; // in bits
};

struct Validity {
  time_t notBefore = 0;
  time_t notAfter = 0;
};

struct CertInfo {
  EntityInfo issuer_info;
  EntityInfo subject_info;
  PublicKeyInfo public_key_info;
  Validity cert_validity;
  std::string cert_serial;
  BytesVector cert_der;
  std::string cert_nick;
  uint32_t ku_extensions = 0;
  int cert_version = 0;
  bool is_self_signed = false;
  KeyLocation keyLocation = KeyLocation::Unknown;
};

inline std::string
VecBytesStringRepresentation(const std::vector<unsigned char> &vec) noexcept {
  std::stringstream builder;
  for (const auto symbol : vec) {
    builder << std::hex << static_cast<int>(symbol);
  }
  return builder.str();
}

struct ESInfo {
  SigStatus signature_val_status = SigStatus::NotVerified;
  CertStatus certificate_val_status = CertStatus::NotVerified;
  CertInfo cert_info;
  std::string signer_name;
  std::string signer_subject_dn;
  HashAlgorithm hash_algorithm = HashAlgorithm::Unknown;
  time_t signing_time = 0;
  BytesVector signature;
  ESInfo() = default;

  /**
   * @brief Construct a new ESInfo object
   * @param pod_res a pointer to PodResult
   */
  explicit ESInfo(PodResult *pod_res) {
    if (pod_res == nullptr) {
      return;
    }
    // enums
    signature_val_status = pod_res->signature_val_status;
    certificate_val_status = pod_res->certificate_val_status;
    // cert_info
    if (pod_res->issuer_common_name != nullptr) {
      cert_info.issuer_info.commonName = pod_res->issuer_common_name;
    }
    if (pod_res->issuer_distinguished_name != nullptr) {
      cert_info.issuer_info.distinguishedName =
          pod_res->issuer_distinguished_name;
    }
    if (pod_res->issuer_email != nullptr) {
      cert_info.issuer_info.email = pod_res->issuer_email;
    }
    if (pod_res->issuer_organization != nullptr) {
      cert_info.issuer_info.organization = pod_res->issuer_organization;
    }
    if (pod_res->subj_common_name != nullptr) {
      cert_info.subject_info.commonName = pod_res->subj_common_name;
    }
    if (pod_res->subj_distinguished_name != nullptr) {
      cert_info.subject_info.distinguishedName =
          pod_res->subj_distinguished_name;
    }
    if (pod_res->subj_email != nullptr) {
      cert_info.subject_info.email = pod_res->subj_email;
    }
    if (pod_res->subj_organization != nullptr) {
      cert_info.subject_info.organization = pod_res->subj_organization;
    }
    if (pod_res->public_key != nullptr && pod_res->public_key_size > 0) {
      cert_info.public_key_info.publicKey = BytesVector(
          pod_res->public_key, pod_res->public_key + pod_res->public_key_size);
    }
    cert_info.public_key_info.publicKeyType = pod_res->public_key_type;
    cert_info.public_key_info.publicKeyStrength = pod_res->public_key_stength;
    cert_info.cert_validity.notBefore = pod_res->not_before;
    cert_info.cert_validity.notAfter = pod_res->not_after;
    if (pod_res->cert_serial != nullptr && pod_res->cert_serial_size > 0) {
      cert_info.cert_serial = VecBytesStringRepresentation(
          BytesVector(pod_res->cert_serial,
                      pod_res->cert_serial + pod_res->cert_serial_size));
    }
    if (pod_res->cert_der != nullptr && pod_res->cert_der_size > 0) {
      cert_info.cert_der = BytesVector(
          pod_res->cert_der, pod_res->cert_der + pod_res->cert_der_size);
    }
    if (pod_res->cert_nick != nullptr) {
      cert_info.cert_nick = pod_res->cert_nick;
    }
    cert_info.ku_extensions = pod_res->ku_extensions;
    cert_info.keyLocation = pod_res->key_location;
    // ESInfo
    if (pod_res->signers_name != nullptr) {
      signer_name = pod_res->signers_name;
    }
    if (pod_res->signer_subject_dn != nullptr) {
      signer_subject_dn = pod_res->signer_subject_dn;
    }
    hash_algorithm = pod_res->hash_algorithm;
    signing_time = pod_res->signing_time;
    if (pod_res->signature != nullptr && pod_res->signature_size > 0) {
      signature = BytesVector(pod_res->signature,
                              pod_res->signature + pod_res->signature_size);
    }
  }
};

} // namespace pdfcsp::poppler