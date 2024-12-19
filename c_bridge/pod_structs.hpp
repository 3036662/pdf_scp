/* File: pod_structs.hpp
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
#include <cstddef>
#include <cstdint>

#include "bool_results.hpp"
#include "bridge_obj_storage.hpp"
#include "typedefs.hpp"

namespace pdfcsp::c_bridge {

/**
 * @brief The parameters pack must be passed through the IPC.
 */
struct CPodParam {
  /**  command to be executed with IPC provider
     empty string - chech signature
     user_cert_list - get user's certificate list
     sign_pdf - perform sign
     @warning no need to set this field; it will be set by c_bridge
  */
  const char *command = nullptr;
  uint64_t command_size = 0;
  uint64_t *byte_range_arr = nullptr;  // flattened array of byteranges
  uint64_t byte_ranges_size = 0;
  const unsigned char *raw_signature_data = nullptr;
  uint64_t raw_signature_size = 0;  // a raw signature to check
  const char *file_path = nullptr;  // for check or for sign
  uint64_t file_path_size = 0;
  // for signature creating
  const char *cert_serial = nullptr;
  const char *cert_subject = nullptr;
  // "CADES_BES" or "CADES_T" or "CADES_XLT1"
  const char *cades_type = nullptr;
  const char *tsp_link = nullptr;  // Link to timestamp service
};

/**
 * @brief Describes the result of an operation performed by the IPC provider
 * @details description @see csp/checks/check_result.hpp#CheckResult
 */
struct CPodResult {
  pdfcsp::csp::checks::BoolResults bres;  // boolean results bunch CheckResult
  pdfcsp::csp::CadesType cades_type = pdfcsp::csp::CadesType::kUnknown;
  const char *cades_t_str = nullptr;          // signature CADES type
  const char *hashing_oid = nullptr;          // hashing algo OID
  unsigned char *encrypted_digest = nullptr;  // raw signature digest
  size_t encrypted_digest_size = 0;
  time_t *times_collection = nullptr;  // array of tSTInfo timestamps
  size_t times_collection_size = 0;
  time_t *x_times_collection = nullptr;  //  escTimeStamps
  size_t x_times_collection_size = 0;
  const char *cert_issuer_dname = nullptr;
  const char *cert_subject_dname = nullptr;

  // cert_info - issuer
  const char *issuer_common_name = nullptr;
  const char *issuer_email = nullptr;
  const char *issuer_organization = nullptr;
  // cert_info - subject
  const char *subj_common_name = nullptr;
  const char *subj_email = nullptr;
  const char *subj_organization = nullptr;
  // cert_chain JSON representation
  const char *cert_chain_json = nullptr;
  // tsp stamp JSON representation
  const char *tsp_json_info = nullptr;
  // ocsp info JSON representation
  const char *signers_cert_ocsp_json_info = nullptr;
  unsigned char *cert_public_key = nullptr;
  size_t cert_public_key_size = 0;
  unsigned char *cert_serial = nullptr;
  size_t cert_serial_size = 0;
  unsigned char *cert_der_encoded = nullptr;
  size_t cert_der_encoded_size = 0;
  // user's certificate list
  const char *user_certifitate_list_json = nullptr;
  // raw signature (create result)
  unsigned char *raw_signature = nullptr;
  size_t raw_signature_size = 0;
  // common error string
  const char *err_string = nullptr;
  // primitive types
  bool common_execution_status = false;
  time_t signers_time = 0;
  time_t cert_not_before = 0;
  time_t cert_not_after = 0;
  uint signers_cert_version = 0;
  uint64_t signers_cert_key_usage = 0;
  BrigeObjStorage *p_stor = nullptr;
};

}  // namespace pdfcsp::c_bridge