#pragma once

#include "check_result.hpp"
#include "message.hpp"

namespace pdfcsp::csp::checks {

using pdfcsp::csp::CheckResult;

/**
 * @brief CADES_BES checks
 * @throws runtime_error only on construct
 */
class BesChecks {
public:
  BesChecks(Message *pmsg, unsigned int signer_index, bool ocsp_online);

  [[nodiscard]] const CheckResult &All() noexcept;

  /// @brief Check if a signer with this index exists.
  [[maybe_unused]] bool SignerIndex() noexcept;

  /// @brief find a cades_type
  void CadesTypeFind() noexcept;

private:
  Message *msg_ = nullptr;
  unsigned int signer_index_ = 0;
  bool ocsp_online_ = false; // NOLINT
  CheckResult res_;

  static constexpr const char *const class_name = "[BesChecks] ";
};

} // namespace pdfcsp::csp::checks