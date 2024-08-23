#include "pks_checks.hpp"
#include "bes_checks.hpp"
#include "hash_handler.hpp"
#include "message.hpp"
#include "utils.hpp"
#include "utils_msg.hpp"
#include <algorithm>
#include <stdexcept>
#include <utility>

namespace pdfcsp::csp::checks {

PksChecks::PksChecks(const Message *pmsg, unsigned int signer_index,
                     bool ocsp_online, PtrSymbolResolver symbols)
    : BesChecks(pmsg, signer_index, ocsp_online, std::move(symbols)) {}

const CheckResult &PksChecks::All(const BytesVector &data) noexcept {
  SignerIndex();
  CadesTypeFind();
  CertificateStatus(ocsp_online());
  PksSignature(data);
  res().pks_all_ok =
      !res().pks_fatal && res().signer_index_ok && res().cades_type_ok &&
      res().certificate_chain_ok &&
      (res().certificate_ocsp_ok || res().certificate_ocsp_check_failed ||
       !res().ocsp_online_used) &&
      res().certificate_usage_signing && res().msg_signature_ok;
  res().check_summary = res().pks_all_ok;

  // res().check_summary =
  Free();
  return res();
}

/// @brief find a cades_type
void PksChecks::CadesTypeFind() noexcept {
  const CadesType msg_type = msg()->GetCadesTypeEx(signer_index());
  res().cades_type = msg_type;
  res().cades_t_str = utils::message::InternalCadesTypeToString(msg_type);
  if (Fatal() || msg_type != CadesType::kPkcs7) {
    std::cerr << "[CadesTypeFind] Unsupported cades type\n";
    SetFatal();
    res().cades_type_ok = false;
    return;
  }
  ResetFatal();
  res().cades_type_ok = true;
}

// NOLINTNEXTLINE
void PksChecks::PksSignature(const BytesVector &data) noexcept {
  constexpr const char *const func_name = "[PksChecks::PksSignature()] ";
  if (Fatal()) {
    return;
  }
  try {
    const auto &cert = signers_cert();
    if (!cert || cert->GetContext() == nullptr) {
      SetFatal();
      return;
    }

    // Compute a data hash
    auto hashing_oid = msg()->GetDataHashingAlgo(signer_index());
    if (!hashing_oid) {
      throw std::runtime_error("No data hashing algorithm was found");
    }
    HashHandler hash(hashing_oid.value(), symbols());
    hash.SetData(data);

    BytesVector encrypted_digest;
    {
      auto digest = msg()->GetEncryptedDigest(signer_index());
      if (!digest) {
        throw std::runtime_error("Extract the encrypted digest failed");
      }
      std::reverse_copy(digest->cbegin(), digest->cend(),
                        std::back_inserter(encrypted_digest));
    }
    res().encrypted_digest = encrypted_digest;
    if (encrypted_digest.empty()) {
      SetFatal();
      res().msg_signature_ok = false;
      std::cout << func_name << "an empty message signature\n";
      return;
    }
    // import the public key
    HCRYPTKEY handler_pub_key = 0;
    ResCheck(symbols()->dl_CryptImportPublicKeyInfo(
                 hash.get_csp_hanler(), PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
                 &cert->GetContext()->pCertInfo->SubjectPublicKeyInfo,
                 &handler_pub_key),
             "CryptImportPublicKeyInfo", symbols());
    if (handler_pub_key == 0) {
      throw std::runtime_error("Import public key failed");
    }
    // verify the signature
    ResCheck(symbols()->dl_CryptVerifySignatureA(
                 hash.get_hash_handler(), encrypted_digest.data(),
                 encrypted_digest.size(), handler_pub_key, nullptr, 0),
             "CryptVerifySignatureA", symbols());

  } catch (const std::exception &ex) {
    std::cerr << func_name << ex.what() << "\n";
    res().msg_signature_ok = false;
    SetFatal();
    return;
  }
  res().msg_signature_ok = true;
  res().pks_fatal = !res().msg_signature_ok;
}

} // namespace pdfcsp::csp::checks