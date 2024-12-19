/* File: check_result.hpp  
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

#include "bool_results.hpp"
#include "d_name.hpp"
#include "typedefs.hpp"
#include <ctime>
#include <string>
#include <sys/types.h>

namespace pdfcsp::csp::checks {

struct CheckResult {
  BoolResults bres;
  CadesType cades_type = CadesType::kUnknown;
  std::string cades_t_str;
  std::string hashing_oid;
  BytesVector encrypted_digest;
  std::vector<time_t> times_collection;
  std::vector<time_t> x_times_collection;
  std::vector<BytesVector> revoced_cers_serials;
  asn::DName cert_issuer;
  asn::DName cert_subject;
  BytesVector cert_public_key;
  BytesVector cert_serial;
  BytesVector cert_der_encoded;
  std::string signers_chain_json;
  std::string tsp_json_info;
  std::string signers_cert_ocsp_json_info;
  time_t signers_time = 0;
  time_t cert_not_before = 0;
  time_t cert_not_after = 0;
  uint signers_cert_version = 0;
  uint8_t signers_cert_key_usage = 0;

  [[nodiscard]] std::string Str() const noexcept;
};

} // namespace pdfcsp::csp::checks