#include "bes_checks.hpp"
#include "certificate.hpp"
#include "message.hpp"
#include "typedefs.hpp"
#include "utils_cert.hpp"
#include "utils_msg.hpp"
#include <algorithm>
#include <exception>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>

namespace pdfcsp::csp::checks {

BesChecks::BesChecks(const Message *pmsg, unsigned int signer_index,
                     bool ocsp_online, PtrSymbolResolver symbols)
    : msg_(pmsg), signer_index_(signer_index), ocsp_online_(ocsp_online),
      res_{}, symbols_(std::move(symbols)) {
  if (msg_ == nullptr) {
    throw std::runtime_error("[BesChecks] nullptr pointer to message");
  }
  if (!symbols_) {
    throw std::runtime_error("[BesCheck] nullptr to symbols resolver recieved");
  }
}

/// @brief Performs all checks
/// @param data - a raw pdf data (extacted with a byterange)
const CheckResult &BesChecks::All(const BytesVector &data) noexcept {
  SignerIndex();
  CadesTypeFind();
  DataHash(data);
  ComputedHash();
  CertificateHash();
  CertificateStatus(ocsp_online_);
  Signature();
  FinalDecision();
  computed_hash_.reset();
  signers_cert_.reset();
  return res_;
}

/// @brief Check if a signer with this index exists.
bool BesChecks::SignerIndex() noexcept {
  auto signers_count = msg_->GetSignersCount();
  if (!res_.bes_fatal && signers_count &&
      signers_count.value_or(0) > signer_index_) {
    res_.signer_index_ok = true;
    ResetFatal();
    return true;
  }
  res_.signer_index_ok = false;
  SetFatal();
  return false;
}

/// @brief find a cades_type
void BesChecks::CadesTypeFind() noexcept {
  const CadesType msg_type = msg_->GetCadesTypeEx(signer_index_);
  res_.cades_type = msg_type;
  res_.cades_t_str = InternalCadesTypeToString(msg_type);
  if (Fatal() || msg_type < CadesType::kCadesBes) {
    std::cerr << "[CadesTypeFind] Unsupported cades type\n";
    SetFatal();
    res_.cades_type_ok = false;
    return;
  }
  ResetFatal();
  res_.cades_type_ok = true;
}

/// @brief Check the data hash.
void BesChecks::DataHash(const BytesVector &data) noexcept {
  constexpr const char *const func_name = "[BesChecks::DataHash] ";
  res_.data_hash_ok = false;
  // basic checks
  if (Fatal() || data.empty() || !SignerIndex()) {
    std::cerr << func_name << "Can't check hash for an empty data\n";
    SetFatal();
    return;
  }
  // get a hashing algo OID
  auto hashing_algo = msg_->GetDataHashingAlgo(signer_index_);
  if (!hashing_algo) {
    std::cerr << func_name << "Data hashing algo OID was not found\n";
    SetFatal();
    return;
  }
  res_.hashing_oid = std::move(hashing_algo.value());
  // get hash value from signed_attibutes
  auto hash_signed = msg_->GetSignedDataHash(signer_index_);
  if (!hash_signed || hash_signed->empty()) {
    std::cerr << func_name << " Find signed data hash failed\n";
    SetFatal();
    return;
  }
  // create data hash
  auto calculated_data_hash = msg_->CalculateDataHash(res_.hashing_oid, data);
  if (!calculated_data_hash || calculated_data_hash->empty()) {
    std::cerr << func_name << "Calculate data hash failed\n";
    SetFatal();
    return;
  }
  res_.data_hash_ok = calculated_data_hash == hash_signed;
  if (res_.data_hash_ok) {
    ResetFatal();
  }
}

/// @brief Check a COMPUTED_HASH, a hash of signed attributes.
void BesChecks::ComputedHash() noexcept {
  if (Fatal()) {
    return;
  }
  // The computed hash calculated from DER-encoded signed attributes
  auto calculated_computed_hash = msg_->CalculateComputedHash(signer_index_);
  if (!calculated_computed_hash) {
    std::cerr << "Error calculating computed hash value\n";
    SetFatal();
    return;
  }
  // Get the Computed Hash value from CryptoApi
  if (calculated_computed_hash->GetValue() !=
      msg_->GetComputedHash(signer_index_)) {
    std::cerr << "The computed hash does not match for signer " << signer_index_
              << "\n";
    res_.computed_hash_ok = false;
    SetFatal();
    return;
  }
  computed_hash_ = std::move(calculated_computed_hash);
  res_.computed_hash_ok = true;
  ResetFatal();
}

/// @brief Calculate the signer's certificate hash and compare it with the hash
/// from the message
void BesChecks::CertificateHash() noexcept {
  constexpr const char *const func_name = "[BesChecks::CertificateHash] ";
  if (Fatal()) {
    return;
  }
  auto cert_id = msg_->GetSignerCertId(signer_index_);
  if (!cert_id) {
    std::cerr << func_name << "Certificate id was not found\n";
    SetFatal();
    return;
  }
  auto cert_hash = msg_->CalculateCertHash(signer_index_);
  if (!cert_hash) {
    std::cerr << "Calculate hash for signer's ceritifiacte failed\n";
    SetFatal();
    return;
  }
  res_.certificate_hash_ok = cert_hash->GetValue() == cert_id->hash_cert;
  if (res_.certificate_hash_ok) {
    ResetFatal();
  }
}
/// @brief check certificate date,chain,ocsp status (optional)
void BesChecks::CertificateStatus(bool ocsp_enable_check) noexcept {
  res_.certificate_ok = false;
  if (Fatal()) {
    return;
  }
  constexpr const char *const func_name = "[BesChecks::Certificate] ";
  // get a raw certificate
  auto raw_certificate = msg_->GetRawCertificate(signer_index_);
  if (!raw_certificate) {
    std::cerr << func_name << "GetRawCertificate failed\n";
    SetFatal();
    return;
  }
  // decode the certificate
  Certificate cert(raw_certificate.value(), symbols_);
  if (!cert.IsTimeValid()) {
    std::cerr << "Invaid certificate time for signer " << signer_index_ << "\n";
    SetFatal();
    return;
  }
  // check if it is suitable for signing
  res_.certificate_usage_signing = false;
  try {
    if (!CertificateHasKeyUsageBit(cert.GetContext(), 0)) {
      std::cerr << "The certificate is not suitable for signing\n";
      SetFatal();
      return;
    }
    res_.certificate_usage_signing = true;
  } catch (const std::exception &ex) {
    std::cerr << func_name << ex.what() << "\n";
    SetFatal();
    return;
  }
  // check the certificate chain
  if (!cert.IsChainOK()) {
    std::cerr << func_name << "The certificate chain status is not ok\n";
    SetFatal();
    return;
  }
  res_.certificate_chain_ok = true;
  try {
    res_.ocsp_online_used = ocsp_enable_check;
    if (ocsp_enable_check && !cert.IsOcspStatusOK()) {
      std::cerr << func_name << "OCSP status is not ok\n";
      res_.certificate_ocsp_ok = false;
      SetFatal();
      return;
    }
  } catch (const std::exception &ex) {
    std::cerr << func_name << ex.what() << "\n";
    res_.certificate_ocsp_ok = false;
    SetFatal();
    return;
  }
  if (ocsp_enable_check) {
    res_.certificate_ocsp_ok = true;
  }
  res_.certificate_ok = res_.certificate_usage_signing &&
                        res_.certificate_chain_ok && res_.certificate_hash_ok &&
                        (!ocsp_enable_check || res_.certificate_ocsp_ok);
  res_.bes_fatal = !res_.certificate_ok;
  signers_cert_ = std::move(cert);
}

void BesChecks::Signature() noexcept {
  constexpr const char *const func_name = "[BesChecks::Signature()] ";
  if (Fatal()) {
    return;
  }
  try {
    auto raw_certificate = msg_->GetRawCertificate(signer_index_);
    if (!raw_certificate) {
      std::cerr << func_name << "GetRawCertificate failed\n";
      SetFatal();
      return;
    }
    if (!computed_hash_) {
      std::cerr << func_name << "at first ComputedHash() should be called\n";
      SetFatal();
      return;
    }
    if (!signers_cert_) {
      std::cerr << func_name
                << "at first CertificateStatus() should be called\n";
      SetFatal();
      return;
    }
    // get the encrypted digest
    BytesVector encrypted_digest;
    {
      auto digest = msg_->GetEncryptedDigest(signer_index_);
      if (!digest) {
        throw std::runtime_error("Extract the encrypted digest failed");
      }
      std::reverse_copy(digest->cbegin(), digest->cend(),
                        std::back_inserter(encrypted_digest));
    }
    res_.encrypted_digest = encrypted_digest;
    if (encrypted_digest.empty()) {
      SetFatal();
      res_.msg_signature_ok = false;
      std::cout << func_name << "an empty message signature\n";
      return;
    }
    // import the public key
    HCRYPTKEY handler_pub_key = 0;
    ResCheck(symbols_->dl_CryptImportPublicKeyInfo(
                 computed_hash_->get_csp_hanler(),
                 PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
                 &signers_cert_->GetContext()->pCertInfo->SubjectPublicKeyInfo,
                 &handler_pub_key),
             "CryptImportPublicKeyInfo", symbols_);
    if (handler_pub_key == 0) {
      throw std::runtime_error("Import public key failed");
    }
    // verify the signature
    ResCheck(symbols_->dl_CryptVerifySignatureA(
                 computed_hash_->get_hash_handler(), encrypted_digest.data(),
                 encrypted_digest.size(), handler_pub_key, nullptr, 0),
             "CryptVerifySignatureA", symbols_);

  } catch (const std::exception &ex) {
    std::cerr << func_name << ex.what() << "\n";
    res_.msg_signature_ok = false;
    SetFatal();
    return;
  }
  res_.msg_signature_ok = true;
  res_.bes_fatal = !res_.msg_signature_ok;
}

void BesChecks::FinalDecision() noexcept {
  res_.bes_all_ok =
      res_.signer_index_ok && res_.cades_type_ok && res_.data_hash_ok &&
      res_.computed_hash_ok && res_.certificate_hash_ok &&
      res_.certificate_usage_signing && res_.certificate_chain_ok &&
      (res_.certificate_ocsp_ok || !res_.ocsp_online_used) &&
      res_.certificate_ok && res_.msg_signature_ok && !res_.bes_fatal &&
      !res_.cades_t_str.empty() && !res_.hashing_oid.empty();
}

} // namespace pdfcsp::csp::checks