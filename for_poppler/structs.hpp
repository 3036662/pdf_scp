#pragma once
#include "pod_structs.hpp"
#include <algorithm>
#include <cstdint>
#include <ctime>
#include <iomanip>
#include <ios>
#include <iostream>
#include <limits>
#include <sstream>
#include <string>
#include <sys/types.h>
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
    builder << std::setw(2) << std::setfill('0') << std::hex
            << static_cast<int>(symbol);
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

  // NOLINTBEGIN(readability-function-cognitive-complexity)

  /**
   * @brief Construct a new ESInfo object
   * @param pod_res a pointer to PodResult
   */
  explicit ESInfo(c_bridge::CPodResult *pod_res) {
    if (pod_res == nullptr) {
      return;
    }
    const c_bridge::CPodResult &check_res = *pod_res;
    // enums
    // signatures
    if (check_res.bres.check_summary) {
      signature_val_status = SigStatus::Valid;
    } else if (!check_res.bres.data_hash_ok) {
      signature_val_status = SigStatus::DigestMismatch;
    } else {
      signature_val_status = SigStatus::Invalid;
    }
    // certificate_val_status = pod_res->certificate_val_status;
    //  cert status
    if (check_res.bres.certificate_ok) {
      certificate_val_status = CertStatus::Trusted;
    } else if (!check_res.bres.certificate_time_ok) {
      certificate_val_status = CertStatus::Expired;
    } else if (!check_res.bres.certificate_chain_ok) {
      certificate_val_status = CertStatus::UntrustedIssuer;
    } else if (!check_res.bres.certificate_ocsp_ok &&
               !check_res.bres.certificate_ocsp_check_failed &&
               check_res.bres.ocsp_online_used) {
      certificate_val_status = CertStatus::Revoked;
    } else {
      certificate_val_status = CertStatus::GenericError;
    }
    // cert_info
    if (pod_res->cert_issuer_dname != nullptr) {
      cert_info.issuer_info.commonName = pod_res->issuer_common_name;
    }
    if (pod_res->cert_subject_dname != nullptr) {
      cert_info.issuer_info.distinguishedName = pod_res->cert_issuer_dname;
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
    if (pod_res->cert_subject_dname != nullptr) {
      cert_info.subject_info.distinguishedName = pod_res->cert_subject_dname;
    }
    if (pod_res->subj_email != nullptr) {
      cert_info.subject_info.email = pod_res->subj_email;
    }
    if (pod_res->subj_organization != nullptr) {
      cert_info.subject_info.organization = pod_res->subj_organization;
    }
    if (pod_res->cert_public_key != nullptr &&
        pod_res->cert_public_key_size > 0) {
      cert_info.public_key_info.publicKey =
          BytesVector(pod_res->cert_public_key,
                      pod_res->cert_public_key + pod_res->cert_public_key_size);
    }
    cert_info.public_key_info.publicKeyType = PublicKeyType::OTHERKEY;
    cert_info.public_key_info.publicKeyStrength = pod_res->cert_public_key_size;
    cert_info.cert_validity.notBefore = pod_res->cert_not_before;
    cert_info.cert_validity.notAfter = pod_res->cert_not_after;
    if (pod_res->cert_serial != nullptr && pod_res->cert_serial_size > 0) {
      cert_info.cert_serial = VecBytesStringRepresentation(
          BytesVector(pod_res->cert_serial,
                      pod_res->cert_serial + pod_res->cert_serial_size));
    }
    if (pod_res->signers_cert_version > std::numeric_limits<int>::max()) {
      std::cerr << "[WARNING] certificate version is wider than integer\n";
    }
    cert_info.cert_version = static_cast<int>(pod_res->signers_cert_version);
    if (pod_res->cert_der_encoded != nullptr &&
        pod_res->cert_der_encoded_size > 0) {
      cert_info.cert_der = BytesVector(pod_res->cert_der_encoded,
                                       pod_res->cert_der_encoded +
                                           pod_res->cert_der_encoded_size);
    }
    // TODO(Oleg) skipped, find out if he is needed or not
    // if (pod_res->cert_nick != nullptr) {
    //   cert_info.cert_nick = pod_res->cert_nick;
    // }
    // TODO(Oleg) skipped, find out if he is needed or not
    if (pod_res->signers_cert_key_usage >
        std::numeric_limits<uint32_t>::max()) {
      std::cerr << "[WARNING] key usage is wider then uint32_t\n";
    }
    cert_info.ku_extensions =
        static_cast<uint32_t>(pod_res->signers_cert_key_usage);
    cert_info.keyLocation = KeyLocation::Unknown;
    // ESInfo
    if (pod_res->subj_common_name != nullptr) {
      signer_name = pod_res->subj_common_name;
    }
    if (pod_res->cert_subject_dname != nullptr) {
      signer_subject_dn = pod_res->cert_subject_dname;
    }
    hash_algorithm = std::string(pod_res->hashing_oid) == "1.2.643.7.1.1.2.2"
                         ? HashAlgorithm::GOST_R3411_12_256
                         : HashAlgorithm::Unknown;
    //  signing time
    {
      std::vector<time_t> tmp;
      std::copy(pod_res->times_collection,
                pod_res->times_collection + pod_res->times_collection_size,
                std::back_inserter(tmp));
      std::copy(pod_res->x_times_collection,
                pod_res->x_times_collection + pod_res->x_times_collection_size,
                std::back_inserter(tmp));
      auto max_el = std::max_element(tmp.cbegin(), tmp.cend());
      if (max_el != tmp.cend()) {
        signing_time = *max_el;
      } else {
        signing_time = check_res.signers_time;
      }
    }

    if (pod_res->encrypted_digest != nullptr &&
        pod_res->encrypted_digest_size > 0) {
      signature = BytesVector(pod_res->encrypted_digest,
                              pod_res->encrypted_digest +
                                  pod_res->encrypted_digest_size);
    }
  }
};

// NOLINTEND(readability-function-cognitive-complexity)

} // namespace pdfcsp::poppler