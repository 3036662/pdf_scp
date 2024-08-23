#pragma once
#include <cstdint>
#include <ctime>
#include <string>
#include <vector>

namespace pfdcsp::poppler {

// USING

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
  const unsigned char *cert_nick = nullptr;
  uint64_t cert_nick_size = 0;
  // key usage extensions
  uint32_t ku_extensions = 0;
  // key location
  KeyLocation keyLocation = KeyLocation::Unknown;
  // ESInfo
  const char *signers_name = nullptr;
  const char *signer_subject_dn = nullptr;
  HashAlgorithm hash_algorithm = HashAlgorithm::Unknown;
  time_t signing_time = 0;
  // signature
  const unsigned char *signature = nullptr;
  const unsigned char *signature_size = nullptr;
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
  BytesVector cert_serial;
  BytesVector cert_der;
  BytesVector cert_nick;
  uint32_t ku_extensions = 0;
  int cert_version = 0;
  bool is_self_signed = false;
  KeyLocation keyLocation = KeyLocation::Unknown;
};

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

  explicit ESInfo(PodResult *pod_res) {}
};

} // namespace pfdcsp::poppler