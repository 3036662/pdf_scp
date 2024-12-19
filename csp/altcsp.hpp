/* File: altcsp.hpp
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

#include <memory>

#include "cert_common_info.hpp"
#include "message.hpp"
#include "resolve_symbols.hpp"
#include "typedefs.hpp"

namespace pdfcsp::csp {

using PtrMsg = std::shared_ptr<Message>;

class Csp {
 public:
  /**
   * @brief Construct a new Csp object
   * @throws std::runtime_error if failed to resolve symbols
   */
  Csp() : dl_{std::make_shared<ResolvedSymbols>()} {}

  // no-copy, no assignment
  Csp(const Csp &) = delete;
  Csp(Csp &&) = delete;
  Csp &operator=(const Csp &) = delete;
  Csp &operator=(Csp &&) = delete;
  ~Csp() = default;

  /**
   * @brief Open a detached message
   *
   * @param message raw message data
   * @param data data signed by this message
   * @return Message (smart pointer)
   */
  PtrMsg OpenDetached(const BytesVector &message) noexcept;

  /**
   * @brief Get the list of certificates for current user
   * @return std::vector<CertCommonInfo>
   */
  std::vector<CertCommonInfo> GetCertList() noexcept;

  /**
   * @brief Construct a CADES message
   *
   * @param cert_serial string
   * @param cert_subject string, common name
   * @param cades_type
   * @param data
   * @param tsp_link wide char string,the TSP server url
   * @return BytesVector - result message
   */
  [[nodiscard]] BytesVector SignData(const std::string &cert_serial,
                                     const std::string &cert_subject,
                                     CadesType cades_type,
                                     const BytesVector &data,
                                     const std::wstring &tsp_link = {}) const;

  // void EnableLogToStdErr(bool val) noexcept { std_err_flag_ = val; }

 private:
  PtrSymbolResolver dl_;
};

}  // namespace pdfcsp::csp