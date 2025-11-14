/* File: bool_results.hpp
Copyright (C) Basealt LLC,  2025
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

#ifdef __cplusplus
#define DEFAULT_FALSE = false
namespace pdfcsp::csp::checks {
#else
#define DEFAULT_FALSE
#include <stdbool.h>
#endif

#pragma pack(push, 8)

struct BoolResults {
  // CADES_BES
  bool signer_index_ok DEFAULT_FALSE;
  bool cades_type_ok DEFAULT_FALSE;
  bool data_hash_ok DEFAULT_FALSE;
  bool computed_hash_ok DEFAULT_FALSE;
  bool certificate_hash_ok DEFAULT_FALSE;
  bool certificate_usage_signing DEFAULT_FALSE;
  bool certificate_chain_ok DEFAULT_FALSE;
  bool certificate_time_ok DEFAULT_FALSE;
  bool certificate_ocsp_ok DEFAULT_FALSE;
  bool certificate_ocsp_check_failed DEFAULT_FALSE;
  bool certificate_ok DEFAULT_FALSE;
  bool msg_signature_ok DEFAULT_FALSE;
  bool ocsp_online_used DEFAULT_FALSE;
  bool bes_fatal DEFAULT_FALSE;
  bool bes_all_ok DEFAULT_FALSE;

  // CADES_T

  bool t_fatal DEFAULT_FALSE;
  bool t_all_tsp_msg_signatures_ok DEFAULT_FALSE;
  bool t_all_tsp_contents_ok DEFAULT_FALSE;
  bool t_all_ok DEFAULT_FALSE;

  // CADES_X
  bool x_fatal DEFAULT_FALSE;
  bool x_esc_tsp_ok DEFAULT_FALSE;
  bool x_data_ok DEFAULT_FALSE;
  bool x_all_revoc_refs_have_value DEFAULT_FALSE;
  bool x_all_cert_refs_have_value DEFAULT_FALSE;
  bool x_signing_cert_found DEFAULT_FALSE;
  bool x_signing_cert_chain_ok DEFAULT_FALSE;
  bool x_singers_cert_has_ocsp_response DEFAULT_FALSE;
  bool x_singers_cert_has_crl_response DEFAULT_FALSE;
  bool x_signers_cert_is_ca DEFAULT_FALSE;
  bool x_all_ocsp_responses_valid DEFAULT_FALSE;
  bool x_all_crls_valid DEFAULT_FALSE;
  bool x_all_ok DEFAULT_FALSE;

  // PKSC_7
  bool pks_fatal DEFAULT_FALSE;
  bool pks_all_ok DEFAULT_FALSE;
  // common
  bool check_summary DEFAULT_FALSE;
};

#pragma pack(pop)

#ifdef __cplusplus
}  // namespace pdfcsp::csp::checks
#endif