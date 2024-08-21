#pragma once

#include "certificate.hpp"
#include "check_result.hpp"
#include "hash_handler.hpp"
#include "resolve_symbols.hpp"
#include "typedefs.hpp"
#include <optional>

namespace pdfcsp::csp::checks {

using pdfcsp::csp::CheckResult;

/**
 * @brief CADES_BES checks
 * @throws runtime_error only on construct
 */

class BesChecks {
public:
  BesChecks(const Message *pmsg, unsigned int signer_index, bool ocsp_online,
            PtrSymbolResolver symbols);

  /// @brief Performs all checks
  /// @param data - a raw pdf data (extacted with a byterange)
  [[nodiscard]] const CheckResult &All(const BytesVector &data) noexcept;

  /// @brief Check if a signer with this index exists.
  [[maybe_unused]] bool SignerIndex() noexcept;

  /// @brief find a cades_type
  void CadesTypeFind() noexcept;

  /// @brief Check the data hash.
  void DataHash(const BytesVector &data) noexcept;

  /// @brief Check a COMPUTED_HASH, a hash of signed attributes.
  void ComputedHash() noexcept;

  /// @brief Calculate the signer's certificate hash and compare it with the
  /// hash from the message
  void CertificateHash() noexcept;

  /// @brief check certificate date,chain,ocsp status (optional)
  void CertificateStatus(bool ocsp_enable_check = true) noexcept;

  /// @brief Verify the message signature.
  void Signature() noexcept;

private:
  void SetFatal() noexcept { res_.bes_fatal = true; }
  void ResetFatal() noexcept { res_.bes_fatal = false; }
  [[nodiscard]] bool Fatal() const noexcept { return res_.bes_fatal; }
  void FinalDecision() noexcept;

  const Message *msg_ = nullptr;
  unsigned int signer_index_ = 0;
  bool ocsp_online_ = true;
  CheckResult res_;
  PtrSymbolResolver symbols_;

  std::optional<HashHandler> computed_hash_;
  std::optional<Certificate> signers_cert_;
};

} // namespace pdfcsp::csp::checks