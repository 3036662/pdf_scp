/* File: bes_checks.hpp
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

#include <optional>

#include "certificate.hpp"
#include "check_result.hpp"
#include "hash_handler.hpp"
#include "i_check_stategy.hpp"
#include "resolve_symbols.hpp"
#include "typedefs.hpp"

namespace pdfcsp::csp::checks {

/**
 * @brief CADES_BES checks
 * @throws runtime_error only on construct
 */

class BesChecks : public ICheckStrategy {
 public:
  BesChecks(const Message *pmsg, unsigned int signer_index, bool ocsp_online,
            PtrSymbolResolver symbols);
  /// @brief Performs all checks
  /// @param data - a raw pdf data (extacted with a byterange)
  [[nodiscard]] const CheckResult &All(
    const BytesVector &data) noexcept override;

 protected:
  /// @brief Check if a signer with this index exists.
  [[maybe_unused]] bool SignerIndex() noexcept;

  /// @brief find a cades_type
  virtual void CadesTypeFind() noexcept;

  /// @brief Check the data hash.
  void DataHash(const BytesVector &data) noexcept;

  /// @brief Check a COMPUTED_HASH, a hash of signed attributes.
  void ComputedHash() noexcept;

  /// @brief decode a signers certificate from message
  void DecodeCertificate() noexcept;

  /// @brief Calculate the signer's certificate hash and compare it with the
  /// hash from the message
  void CertificateHash() noexcept;

  /// @brief check certificate date,chain,ocsp status (optional)
  virtual void CertificateStatus(bool ocsp_enable_check) noexcept;

  /// @brief Save the encrypted Digest
  void SaveDigest() noexcept;

  /// @brief Verify the message signature.
  void Signature() noexcept;

  void FinalDecision() noexcept;

  void Free() noexcept;

  [[nodiscard]] CheckResult &res() noexcept { return res_; }
  [[nodiscard]] const CheckResult &res() const noexcept { return res_; }
  [[nodiscard]] bool ocsp_online() const noexcept { return ocsp_online_; }
  [[nodiscard]] const PtrSymbolResolver &symbols() const noexcept {
    return symbols_;
  }
  [[nodiscard]] const Message *msg() const noexcept { return msg_; }
  [[nodiscard]] const std::optional<Certificate> &signers_cert()
    const noexcept {
    return signers_cert_;
  }
  [[nodiscard]] unsigned int signer_index() const noexcept {
    return signer_index_;
  }

  //[[nodiscard]] const std::optional<HashHandler>& computed_hash() const
  // noexcept{ return computed_hash_;}
  [[nodiscard]] const std::optional<Certificate> &cert() const noexcept {
    return signers_cert_;
  }

 private:
  virtual void SetFatal() noexcept { res_.bres.bes_fatal = true; }
  virtual void ResetFatal() noexcept { res_.bres.bes_fatal = false; }
  [[nodiscard]] virtual bool Fatal() const noexcept {
    return res_.bres.bes_fatal;
  }
  const Message *msg_ = nullptr;
  unsigned int signer_index_ = 0;
  bool ocsp_online_ = true;
  CheckResult res_;
  PtrSymbolResolver symbols_;
  std::optional<HashHandler> computed_hash_;
  std::optional<Certificate> signers_cert_;
};

}  // namespace pdfcsp::csp::checks