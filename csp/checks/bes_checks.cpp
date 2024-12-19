/* File: bes_checks.cpp  
Copyright (C) Basealt LLC,  2024
Author: Oleg Proskurin, <proskurinov@basealt.ru>

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with this program; if not, write to the Free Software Foundation,
Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/


#include "bes_checks.hpp"
#include "cert_common_info.hpp"
#include "certificate.hpp"
#include "message.hpp"
#include "typedefs.hpp"
#include "utils.hpp"
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

void BesChecks::Free() noexcept {
  computed_hash_.reset();
  signers_cert_.reset();
}

/// @brief Performs all checks
/// @param data - a raw pdf data (extacted with a byterange)
const CheckResult &BesChecks::All(const BytesVector &data) noexcept {
  SignerIndex();
  CadesTypeFind();
  DataHash(data);
  ComputedHash();
  DecodeCertificate();
  SaveDigest();
  CertificateHash();
  CertificateStatus(ocsp_online_);
  Signature();
  FinalDecision();
  res_.bres.check_summary = res_.bres.bes_all_ok;
  Free();
  return res_;
}

/// @brief Check if a signer with this index exists.
bool BesChecks::SignerIndex() noexcept {
  auto signers_count = msg_->GetSignersCount();
  if (!res_.bres.bes_fatal && signers_count &&
      signers_count.value_or(0) > signer_index_) {
    res_.bres.signer_index_ok = true;
    BesChecks::ResetFatal();
    return true;
  }
  res_.bres.signer_index_ok = false;
  res_.signers_time = msg_->GetSignersTime(signer_index_).value_or(0);
  BesChecks::SetFatal();
  return false;
}

/// @brief find a cades_type
void BesChecks::CadesTypeFind() noexcept {
  const CadesType msg_type = msg_->GetCadesTypeEx(signer_index_);
  res_.cades_type = msg_type;
  res_.cades_t_str = utils::message::InternalCadesTypeToString(msg_type);
  if (Fatal() || msg_type < CadesType::kCadesBes) {
    symbols_->log->error("[CadesTypeFind] Unsupported cades type");
    BesChecks::SetFatal();
    res_.bres.cades_type_ok = false;
    return;
  }
  BesChecks::ResetFatal();
  res_.bres.cades_type_ok = true;
}

/// @brief Check the data hash.
void BesChecks::DataHash(const BytesVector &data) noexcept {
  constexpr const char *const func_name = "[BesChecks::DataHash] ";
  res_.bres.data_hash_ok = false;
  // basic checks
  if (Fatal() || data.empty() || !SignerIndex()) {
    symbols_->log->error("{} Can't check hash for an empty data", func_name);
    BesChecks::SetFatal();
    return;
  }
  // get a hashing algo OID
  auto hashing_algo = msg_->GetDataHashingAlgo(signer_index_);
  if (!hashing_algo) {
    symbols_->log->error("{} Data hashing algo OID was not found", func_name);
    BesChecks::SetFatal();
    return;
  }
  res_.hashing_oid = std::move(hashing_algo.value());
  // get hash value from signed_attibutes
  auto hash_signed = msg_->GetSignedDataHash(signer_index_);
  if (!hash_signed || hash_signed->empty()) {
    symbols_->log->error("{} Find signed data hash failed", func_name);
    BesChecks::SetFatal();
    return;
  }
  // create data hash
  auto calculated_data_hash = msg_->CalculateDataHash(res_.hashing_oid, data);
  if (!calculated_data_hash || calculated_data_hash->empty()) {
    symbols_->log->error("{} Calculate data hash failed", func_name);
    BesChecks::SetFatal();
    return;
  }
  res_.bres.data_hash_ok = calculated_data_hash == hash_signed;
  if (res_.bres.data_hash_ok) {
    BesChecks::ResetFatal();
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
    symbols_->log->error("Error calculating computed hash value");
    BesChecks::SetFatal();
    return;
  }
  // Get the Computed Hash value from CryptoApi
  if (calculated_computed_hash->GetValue() !=
      msg_->GetComputedHash(signer_index_)) {
    symbols_->log->error("The computed hash does not match for signer {}",
                         signer_index_);
    res_.bres.computed_hash_ok = false;
    BesChecks::SetFatal();
    return;
  }
  computed_hash_ = std::move(calculated_computed_hash);
  res_.bres.computed_hash_ok = true;
  BesChecks::ResetFatal();
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
    symbols_->log->error("{} Certificate id was not found", func_name);
    BesChecks::SetFatal();
    return;
  }
  auto cert_hash = msg_->CalculateCertHash(signer_index_);
  if (!cert_hash) {
    symbols_->log->error("{} Calculate hash for signer's ceritifiacte failed",
                         func_name);
    BesChecks::SetFatal();
    return;
  }
  res_.bres.certificate_hash_ok = cert_hash->GetValue() == cert_id->hash_cert;
  if (res_.bres.certificate_hash_ok) {
    BesChecks::ResetFatal();
  }
}

/// @decode a signers certificate from message
void BesChecks::DecodeCertificate() noexcept {
  constexpr const char *const func_name = "[BesChecks::DecodeCertificate] ";
  auto raw_certificate = msg_->GetRawCertificate(signer_index_);
  if (!raw_certificate) {
    symbols_->log->error("{} GetRawCertificate failed", func_name);
    BesChecks::SetFatal();
    return;
  }
  try {
    signers_cert_ = Certificate(raw_certificate.value(), symbols_);
    // save the certificate info
    res_.cert_issuer = signers_cert_->DecomposedIssuerName();
    res_.cert_subject = signers_cert_->DecomposedSubjectName();
    res_.cert_public_key = signers_cert_->PublicKey();
    auto time_bounds = signers_cert_->GetTimeBounds();
    res_.cert_not_before = time_bounds.not_before;
    res_.cert_not_after = time_bounds.not_after;
    res_.cert_serial = signers_cert_->Serial();
    {
      const CertCommonInfo cert_info(signers_cert_->GetContext()->pCertInfo);
      res_.signers_cert_version = cert_info.version;
      res_.signers_cert_key_usage = cert_info.key_usage;
    }
    res_.cert_der_encoded = signers_cert_->GetRawCopy();

  } catch (const std::exception &ex) {
    symbols_->log->error("{} decode the signers cerificate failed {}",
                         func_name, ex.what());
    BesChecks::SetFatal();
    return;
  }
}

/// @brief check certificate date,chain,ocsp status (optional)
void BesChecks::CertificateStatus(bool ocsp_enable_check) noexcept {
  res_.bres.certificate_ok = false;
  if (Fatal()) {
    return;
  }
  constexpr const char *const func_name = "[BesChecks::CertificateStatus] ";
  if (!signers_cert_) {
    symbols_->log->error("{} An empty signers certificate value", func_name);
    BesChecks::SetFatal();
    return;
  }
  res_.bres.certificate_usage_signing = false;
  try {
    // save the certificate info
    res().cert_issuer = signers_cert_->DecomposedIssuerName();
    res().cert_subject = signers_cert_->DecomposedSubjectName();
    res().cert_public_key = signers_cert_->PublicKey();
    res().signers_chain_json = signers_cert_->ChainInfo();

    if (!signers_cert_->IsTimeValid()) {
      symbols_->log->error("Invaid certificate time for signer {}",
                           signer_index_);
      BesChecks::SetFatal();
      return;
    }
    res_.bres.certificate_time_ok = true;
    // check if it is suitable for signing
    if (!utils::cert::CertificateHasKeyUsageBit(signers_cert_->GetContext(),
                                                0)) {
      symbols_->log->error("{} The certificate is not suitable for signing",
                           func_name);
      BesChecks::SetFatal();
      return;
    }
    res_.bres.certificate_usage_signing = true;
  } catch (const std::exception &ex) {
    symbols_->log->error("{} {}", func_name, ex.what());
    BesChecks::SetFatal();
    return;
  }
  // check the certificate chain
  if (!signers_cert_->IsChainOK()) {
    symbols_->log->error("{} The certificate chain status is not ok",
                         func_name);
    BesChecks::SetFatal();
    return;
  }
  res_.bres.certificate_chain_ok = true;
  try {
    res_.bres.ocsp_online_used = ocsp_enable_check;
    if (ocsp_enable_check && !signers_cert_->IsOcspStatusOK()) {
      symbols_->log->error("{} OCSP status is not ok");
      res_.bres.certificate_ocsp_ok = false;
      BesChecks::SetFatal();
      return;
    }
    // when no ocsp connection
  } catch (const std::exception &ex) {
    symbols_->log->warn("{} {}", func_name, ex.what());
    res_.bres.certificate_ocsp_ok = false;
    res_.bres.certificate_ocsp_check_failed = true;
    // not fatal
  }
  if (ocsp_enable_check) {
    res_.bres.certificate_ocsp_ok = true;
  }
  res_.bres.certificate_ok =
      res_.bres.certificate_usage_signing && res_.bres.certificate_chain_ok &&
      res_.bres.certificate_hash_ok &&
      (!ocsp_enable_check || (res_.bres.certificate_ocsp_ok ||
                              res_.bres.certificate_ocsp_check_failed)) &&
      res_.bres.certificate_time_ok;
  res_.bres.bes_fatal = !res_.bres.certificate_ok;
}

void BesChecks::SaveDigest() noexcept {
  // get the encrypted digest
  BytesVector encrypted_digest;
  {
    auto digest = msg_->GetEncryptedDigest(signer_index_);
    if (!digest) {
      symbols_->log->error(
          "[BesChecks::SaveDigest] Extract the encrypted digest failed");
      BesChecks::SetFatal();
      return;
    }
    std::reverse_copy(digest->cbegin(), digest->cend(),
                      std::back_inserter(encrypted_digest));
  }
  res_.encrypted_digest = encrypted_digest;
}

void BesChecks::Signature() noexcept {
  constexpr const char *const func_name = "[BesChecks::Signature()] ";
  if (Fatal()) {
    return;
  }
  try {
    if (!computed_hash_) {
      symbols_->log->error("{} at first ComputedHash() should be called",
                           func_name);
      BesChecks::SetFatal();
      return;
    }
    if (!signers_cert_) {
      symbols_->log->error("{} at first CertificateStatus() should be called",
                           func_name);
      BesChecks::SetFatal();
      return;
    }

    if (res_.encrypted_digest.empty()) {
      BesChecks::SetFatal();
      res_.bres.msg_signature_ok = false;
      symbols_->log->error("{} an empty message signature", func_name);
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
                 computed_hash_->get_hash_handler(),
                 res_.encrypted_digest.data(), res_.encrypted_digest.size(),
                 handler_pub_key, nullptr, 0),
             "CryptVerifySignatureA", symbols_);

  } catch (const std::exception &ex) {
    symbols_->log->error("{} {}", func_name, ex.what());
    res_.bres.msg_signature_ok = false;
    BesChecks::SetFatal();
    return;
  }
  res_.bres.msg_signature_ok = true;
  res_.bres.bes_fatal = !res_.bres.msg_signature_ok;
}

void BesChecks::FinalDecision() noexcept {
  res_.bres.bes_all_ok = res_.bres.signer_index_ok && res_.bres.cades_type_ok &&
                         res_.bres.data_hash_ok && res_.bres.computed_hash_ok &&
                         res_.bres.certificate_hash_ok &&
                         res_.bres.certificate_usage_signing &&
                         res_.bres.certificate_chain_ok &&
                         (!res_.bres.ocsp_online_used ||
                          (res_.bres.certificate_ocsp_ok ||
                           res_.bres.certificate_ocsp_check_failed)) &&
                         res_.bres.certificate_ok &&
                         res_.bres.msg_signature_ok && !res_.bres.bes_fatal &&
                         !res_.cades_t_str.empty() && !res_.hashing_oid.empty();
}

} // namespace pdfcsp::csp::checks