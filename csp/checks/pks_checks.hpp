/* File: pks_checks.hpp
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
#include "typedefs.hpp"
namespace pdfcsp::csp::checks {

class PksChecks : public BesChecks {
 public:
  PksChecks(const Message *pmsg, unsigned int signer_index, bool ocsp_online,
            PtrSymbolResolver symbols);

  /// @brief Performs all checks
  /// @param data - a raw pdf data (extacted with a byterange)
  [[nodiscard]] const CheckResult &All(
    const BytesVector &data) noexcept override;

  /// @brief find a cades_type
  void CadesTypeFind() noexcept override;

 private:
  void SetFatal() noexcept override { res().bres.pks_fatal = true; }
  void ResetFatal() noexcept override { res().bres.pks_fatal = false; }
  [[nodiscard]] bool Fatal() const noexcept override {
    return res().bres.pks_fatal;
  }

  void PksSignature(const BytesVector &data) noexcept;
};

}  // namespace pdfcsp::csp::checks