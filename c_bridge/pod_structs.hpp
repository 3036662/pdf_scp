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

// C++ headers
#ifdef __cplusplus
#include <cstddef>
#include <cstdint>

#include "bridge_obj_storage.hpp"
#include "typedefs.hpp"
#endif

#include "bool_results.hpp"

// C++ default values
#ifdef __cplusplus
#define DEFAULT_NULLPTR = nullptr
#define DEFAULT_NULL = 0
// C++ namespace  pdfcsp::csp::checks
#define NAMESPACE_CHECKS pdfcsp::csp::checks::
// C++ namespace
namespace pdfcsp::c_bridge {
#else
// C has no default values
#define DEFAULT_NULLPTR
#define DEFAULT_NULL
// C has no namespaces
#define NAMESPACE_CHECKS
// time_t for C
#include <time.h>
// uint64_t for C
#include <stdint.h>
// C++ CadesType underlying type is uint8_t
typedef uint8_t CadesType;
typedef struct BoolResults BoolResults;
typedef struct BrigeObjStorage BrigeObjStorage;
typedef struct SeparateSignatureParams SeparateSignatureParams;
typedef struct CPodResult CPodResult;
typedef struct CPodParam CPodParam;
#endif

#pragma pack(push, 8)
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
  const char *command DEFAULT_NULLPTR;
  uint64_t command_size DEFAULT_NULL;
  uint64_t *byte_range_arr DEFAULT_NULLPTR;  // flattened array of byteranges
  uint64_t byte_ranges_size DEFAULT_NULL;
  const unsigned char *raw_signature_data DEFAULT_NULLPTR;
  uint64_t raw_signature_size DEFAULT_NULL;  // a raw signature to check
  const char *file_path DEFAULT_NULLPTR;     // for check or for sign
  uint64_t file_path_size DEFAULT_NULL;
  // for signature creating
  const char *cert_serial DEFAULT_NULLPTR;
  const char *cert_subject DEFAULT_NULLPTR;
  // "CADES_BES" or "CADES_T" or "CADES_XLT1"
  const char *cades_type DEFAULT_NULLPTR;
  const char *tsp_link DEFAULT_NULLPTR;  // Link to timestamp service
  // for separate signature checking
  const char *sig_file_path DEFAULT_NULLPTR;
  uint64_t sig_file_path_size DEFAULT_NULL;
  // for sig_file_creating
  bool create_attached DEFAULT_FALSE;
  bool create_base_64_encoded DEFAULT_FALSE;
};

/**
 * @brief Describes the result of an operation performed by the IPC provider
 * @details description @see csp/checks/check_result.hpp#CheckResult
 */

struct CPodResult {
  NAMESPACE_CHECKS BoolResults bres;  // boolean results bunch CheckResult
#ifdef __cplusplus
  pdfcsp::csp::CadesType cades_type = pdfcsp::csp::CadesType::kUnknown;
#else
  CadesType cades_type;
#endif
  const char *cades_t_str DEFAULT_NULLPTR;          // signature CADES type
  const char *hashing_oid DEFAULT_NULLPTR;          // hashing algo OID
  unsigned char *encrypted_digest DEFAULT_NULLPTR;  // raw signature digest
  size_t encrypted_digest_size DEFAULT_NULL;
  time_t *times_collection DEFAULT_NULLPTR;  // array of tSTInfo timestamps
  size_t times_collection_size DEFAULT_NULL;
  time_t *x_times_collection DEFAULT_NULLPTR;  //  escTimeStamps
  size_t x_times_collection_size DEFAULT_NULL;
  const char *cert_issuer_dname DEFAULT_NULLPTR;
  const char *cert_subject_dname DEFAULT_NULLPTR;

  // cert_info - issuer
  const char *issuer_common_name DEFAULT_NULLPTR;
  const char *issuer_email DEFAULT_NULLPTR;
  const char *issuer_organization DEFAULT_NULLPTR;
  // cert_info - subject
  const char *subj_common_name DEFAULT_NULLPTR;
  const char *subj_email DEFAULT_NULLPTR;
  const char *subj_organization DEFAULT_NULLPTR;
  // cert_chain JSON representation
  const char *cert_chain_json DEFAULT_NULLPTR;
  // tsp stamp JSON representation
  const char *tsp_json_info DEFAULT_NULLPTR;
  // ocsp info JSON representation
  const char *signers_cert_ocsp_json_info DEFAULT_NULLPTR;
  unsigned char *cert_public_key DEFAULT_NULLPTR;
  size_t cert_public_key_size DEFAULT_NULL;
  unsigned char *cert_serial DEFAULT_NULLPTR;
  size_t cert_serial_size DEFAULT_NULL;
  unsigned char *cert_der_encoded DEFAULT_NULLPTR;
  size_t cert_der_encoded_size DEFAULT_NULL;
  // user's certificate list
  const char *user_certifitate_list_json DEFAULT_NULLPTR;
  // raw signature (create result)
  unsigned char *raw_signature DEFAULT_NULLPTR;
  size_t raw_signature_size DEFAULT_NULL;
  // common error string
  const char *err_string DEFAULT_NULLPTR;
  // primitive types
  bool common_execution_status DEFAULT_FALSE;
  time_t signers_time DEFAULT_NULL;
  time_t cert_not_before DEFAULT_NULL;
  time_t cert_not_after DEFAULT_NULL;
  uint32_t signers_cert_version DEFAULT_NULL;
  uint64_t signers_cert_key_usage DEFAULT_NULL;
  uint64_t current_signer_index DEFAULT_NULL;
  uint64_t total_signers DEFAULT_NULL;
  // check if attached result
  bool message_is_attached DEFAULT_FALSE;

  // for internal usage
  BrigeObjStorage *p_stor DEFAULT_NULLPTR;
};

struct SeparateSignatureParams {
  const char *sig_file_path DEFAULT_NULLPTR;
  uint64_t sig_file_path_size DEFAULT_NULL;
  const char *data_file_path DEFAULT_NULLPTR;
  uint64_t data_file_path_size DEFAULT_NULL;
};

/// @brief Command Package
struct TaskBatch {
  const CPodParam *const *params DEFAULT_NULLPTR;
  uint64_t params_size DEFAULT_NULL;
};

/// @brief The result of executing a batch of commands
struct TaskBatchResult {
  CPodResult **results DEFAULT_NULLPTR;
  uint64_t results_size DEFAULT_NULL;
};

/// @brief Setting for the batch signing
struct BatchSignatureSettings {
  const char *cert_serial DEFAULT_NULLPTR;
  const char *cert_subject DEFAULT_NULLPTR;
  const char *cades_type DEFAULT_NULLPTR;
  const char *tsp_link DEFAULT_NULLPTR;
  const char *sig_extension DEFAULT_NULLPTR;
  const char *dest_dir_path DEFAULT_NULLPTR;
  bool create_attached DEFAULT_FALSE;
  bool create_base_64_encoded DEFAULT_FALSE;
  bool pack_to_zip DEFAULT_FALSE;
  bool pack_separate_zips DEFAULT_FALSE;
};

#pragma pack(pop)

#ifdef __cplusplus
}  // namespace pdfcsp::c_bridge
#endif