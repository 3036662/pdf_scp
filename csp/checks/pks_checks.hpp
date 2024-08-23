#pragma once

#include "bes_checks.hpp"
#include "typedefs.hpp"
namespace pdfcsp::csp::checks {

class PksChecks : public BesChecks {
public:
  PksChecks(const Message *pmsg, unsigned int signer_index, bool ocsp_online,
            PtrSymbolResolver symbols);

  /// @brief Performs all checks
  /// @param data - a raw pdf data (extacted with a byterange)
  [[nodiscard]] const CheckResult &
  All(const BytesVector &data) noexcept override;

  /// @brief find a cades_type
  void CadesTypeFind() noexcept override;

private:
  void SetFatal() noexcept override { res().pks_fatal = true; }
  void ResetFatal() noexcept override { res().pks_fatal = false; }
  [[nodiscard]] bool Fatal() const noexcept override { return res().pks_fatal; }

  void PksSignature(const BytesVector &data) noexcept;
};

} // namespace pdfcsp::csp::checks