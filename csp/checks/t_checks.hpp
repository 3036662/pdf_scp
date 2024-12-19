/* File: t_checks.hpp  
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