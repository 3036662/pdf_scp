/* File: bool_results.hpp
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

namespace pdfcsp::csp::checks {

struct BoolResults {
  // CADES_BES
  bool signer_index_ok = false;
  bool cades_type_ok = false;
  bool data_hash_ok = false;
  bool computed_hash_ok = false;
  bool certificate_hash_ok = false;
  bool certificate_usage_signing = false;
  bool certificate_chain_ok = false;
  bool certificate_time_ok = false;
  bool certificate_ocsp_ok = false;
  bool certificate_ocsp_check_failed = false;
  bool certificate_ok = false;
  bool msg_signature_ok = false;
  bool ocsp_online_used = false;
  bool bes_fatal = false;
  bool bes_all_ok = false;

  // CADES_T

  bool t_fatal = false;
  bool t_all_tsp_msg_signatures_ok = false;
  bool t_all_tsp_contents_ok = false;
  bool t_all_ok = false;

  // CADES_X
  bool x_fatal = false;
  bool x_esc_tsp_ok = false;
  bool x_data_ok = false;
  bool x_all_revoc_refs_have_value = false;
  bool x_all_cert_refs_have_value = false;
  bool x_signing_cert_found = false;
  bool x_signing_cert_chain_ok = false;
  bool x_singers_cert_has_ocsp_response = false;
  bool x_singers_cert_has_crl_response = false;
  bool x_signers_cert_is_ca = false;
  bool x_all_ocsp_responses_valid = false;
  bool x_all_crls_valid = false;
  bool x_all_ok = false;

  // PKSC_7
  bool pks_fatal = false;
  bool pks_all_ok = false;
  // common
  bool check_summary = false;
};

}  // namespace pdfcsp::csp::checks