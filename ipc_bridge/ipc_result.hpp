/* File: ipc_result.hpp
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
#include "ipc_typedefs.hpp"
#include "typedefs.hpp"

namespace pdfcsp::ipc_bridge {

/**
 * @brief Used for passing result for signature creation and check  through
 * the IPC
 * @details @see csp/checks/check_result.hpp
 */
struct IPCResult {
  pdfcsp::csp::checks::BoolResults bres;
  pdfcsp::csp::CadesType cades_type = pdfcsp::csp::CadesType::kUnknown;
  IpcString cades_t_str;
  IpcString hashing_oid;
  IpcBytesVector encrypted_digest;
  IpcTimeTVector times_collection;
  IpcTimeTVector x_times_collection;
  IpcString cert_issuer_dname;
  IpcString cert_subject_dname;
  IpcBytesVector cert_public_key;
  IpcBytesVector cert_serial;
  IpcBytesVector cert_der_encoded;
  IpcString issuer_common_name;
  IpcString issuer_email;
  IpcString issuer_organization;
  IpcString subj_common_name;
  IpcString subj_email;
  IpcString subj_organization;
  IpcString signers_chain_json;
  IpcString tsp_json_info;
  IpcString signers_cert_ocsp_json_info;
  IpcString user_certifitate_list_json;
  // for signing
  IpcBytesVector signature_raw;
  // common error string
  IpcString err_string;
  bool common_execution_status = false;

  time_t signers_time = 0;
  time_t cert_not_before = 0;
  time_t cert_not_after = 0;
  uint signers_cert_version = 0;
  uint64_t signers_cert_key_usage = 0;

  explicit IPCResult(const IpcStringAllocator &string_alloc,
                     const IpcByteAllocator &byte_allocator,
                     const IpcTimeTAllocator &time_allocator)
    : cades_t_str(string_alloc),
      hashing_oid(string_alloc),
      encrypted_digest(byte_allocator),
      times_collection(time_allocator),
      x_times_collection(time_allocator),
      cert_issuer_dname(string_alloc),
      cert_subject_dname(string_alloc),
      cert_public_key(byte_allocator),
      cert_serial(byte_allocator),
      cert_der_encoded(byte_allocator),
      issuer_common_name(string_alloc),
      issuer_email(string_alloc),
      issuer_organization(string_alloc),
      subj_common_name(string_alloc),
      subj_email(string_alloc),
      subj_organization(string_alloc),
      signers_chain_json(string_alloc),
      tsp_json_info(string_alloc),
      signers_cert_ocsp_json_info(string_alloc),
      user_certifitate_list_json(string_alloc),
      signature_raw(byte_allocator),
      err_string(string_alloc) {}
};

}  // namespace pdfcsp::ipc_bridge