/* File: cert_common_info.hpp  
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
#include "resolve_symbols.hpp"
#include "typedefs.hpp"
#include <boost/json.hpp>
#include <boost/json/object.hpp>
#include <cstdint>
#include <ctime>
#include <string>

namespace pdfcsp::csp {

namespace json = boost::json;

/**
 * @brief A structure with common certificate info
 * @throws runtime_error on construct
 */
struct CertCommonInfo {
  unsigned int version = 0;
  BytesVector serial;
  std::string sig_algo;
  std::string issuer;
  std::string issuer_common_name;
  std::string subject;
  std::string subj_common_name;
  time_t not_before = 0;
  time_t not_after = 0;
  std::string pub_key_algo;
  uint64_t key_usage = 0;
  std::string key_usage_bits_str;
  CertCommonInfo() = default;
  std::optional<bool> trust_status;

  explicit CertCommonInfo(const _CERT_INFO *p_info);

  /**
   * @brief Set the Trust Status
   * @param symbols
   * @param dwErrorStatus from CERT_TRUST_STATUS struct
   * @param p_time time to use as "now"
   * @param ignore_revoc_check_errors
   */
  void SetTrustStatus(const PtrSymbolResolver &symbols, _CERT_INFO *p_info,
                      DWORD dwErrorStatus, FILETIME *p_time = nullptr,
                      bool ignore_revoc_check_errors = false);

  void PrintToStdOut() const noexcept;

  [[nodiscard]] json::object ToJson() const noexcept;
};

} // namespace pdfcsp::csp