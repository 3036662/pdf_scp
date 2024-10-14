#pragma once

#include "bes_checks.hpp"
#include "check_result.hpp"
#include "crypto_attribute.hpp"
#include "t_structs.hpp"

namespace pdfcsp::csp::checks {

/// @brief CADES_T cheks
/// @details includes all CADES_BES checks
/// @throws runtime_error only on construct
class TChecks : public BesChecks {
public:
  TChecks(const Message *pmsg, unsigned int signer_index, bool ocsp_online,
          PtrSymbolResolver symbols);

  /// @brief Performs all checks
  /// @param data - a raw pdf data (extacted with a byterange)
  [[nodiscard]] const CheckResult &
  All(const BytesVector &data) noexcept override;

protected:
  /// @brief Check all CADES_T timestamps
  void CheckAllCadesTStamps() noexcept;

  /// @throws runtime_error
  [[nodiscard]] CheckOneCadesTSPResult
  CheckOneCadesTStmap(const CryptoAttribute &tsp_attribute,
                      const BytesVector &val_for_hashing);

  [[nodiscard]] std::vector<time_t> &times_collection() noexcept {
    return times_collection_;
  }

private:
  void SetFatal() noexcept override { res().bres.t_fatal = true; }
  void ResetFatal() noexcept override { res().bres.t_fatal = false; }
  [[nodiscard]] bool Fatal() const noexcept override {
    return res().bres.t_fatal;
  }

  [[nodiscard]] CheckAllSignaturesInTspResult
  CheckAllSignaturesInTsp(Message &tsp_message);

  [[nodiscard]] CheckTspContentResult
  CheckTspContent(const Message &tsp_message,
                  const BytesVector &val_for_hashing);

  std::vector<time_t> times_collection_;
};

} // namespace pdfcsp::csp::checks