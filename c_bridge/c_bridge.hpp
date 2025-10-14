/* File: c_bridge.hpp
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
#include "pod_structs.hpp"

#ifdef __cplusplus
namespace pdfcsp::c_bridge {
#endif

#define LIB_API __attribute__((visibility("default")))
#define LIB_LOCAL __attribute__((visibility("hidden")))

#ifdef __cplusplus
extern "C" {
#endif

#ifndef __cplusplus
typedef struct CPodResult CPodResult;
typedef struct CPodParam CPodParam;
typedef struct TaskBatchResult TaskBatchResult;
typedef struct TaskBatch TaskBatch;

#endif

/**
 * @brief Check the signature
 * @details calls CGetIPCResult with and empty command
 * @param params @see pod_structs.hpp#CPodParam
 * @return CPodResult* @see  pod_structs.hpp#CPodResult
 * @warning the caller must call CFreeResult
 */
LIB_API
CPodResult *CGetCheckResult(CPodParam params);

/**
 * @brief Check the detached signature (simple with no byteranges)
 * @details calls CGetIPCResult with and check_simple_detached command
 * @param params @see pod_structs.hpp#CPodParam
 * @return CPodResult* @see  pod_structs.hpp#CPodResult
 * @warning the caller must call CFreeResult
 * @details params.sig_file_path (and size) or params.raw_signature_data must be
 * set
 * @details params.file_path (and size) must be set
 * @details if using raw_signature_data it must be ASN1 encoded
 */
LIB_API
CPodResult *CheckSimpleDetached(CPodParam params);

/**
 * @brief Check the attached signature (simple with no byteranges)
 * @details calls CGetIPCResult with and check_simple_attached command
 * @param params @see pod_structs.hpp#CPodParam
 * @return CPodResult* @see  pod_structs.hpp#CPodResult
 * @warning the caller must call CFreeResult
 * @details params.sig_file_path (and size) or params.raw_signature_data must be
 * set
 * @details if using raw_signature_data it must be ASN1 encoded
 */
LIB_API
CPodResult *CheckSimpleAttached(CPodParam params);

/**
 * @brief Common function to call csp with IPC bridge
 * @details Creates an IPC client and calls the IPC provider
 * @param params @see pod_structs.hpp#CPodParam
 * @return CPodResult* @see  pod_structs.hpp#CPodResult
 * @warning the caller must call CFreeResult
 */
LIB_API
CPodResult *CGetIPCResult(CPodParam params);

/**
 * @brief Get user's certificate list
 * @details Calls an IPC Provider with "user_cert_list" command
 * @param params Should be called with default constructed CPodParam struct
 * @return CPodResult* @see  pod_structs.hpp#CPodResult
 * @warning the caller must call CFreeResult c
 */
LIB_API
CPodResult *CGetCertList(CPodParam params);

/**
 * @brief Perform a PDF file sign
 * @details Creates an IPC client and calls the IPC provider with "sign_pdf"
 * command
 * @param params @see pod_structs.hpp#CPodParam
 * @return CPodResult* @see  pod_structs.hpp#CPodResult.signature_raw
 * @warning the caller must call CFreeResult
 */
LIB_API
CPodResult *CSignPdf(CPodParam params);

/**
 * @brief Free resources occupied by CSignPdf, CGetCertList,CGetCheckResult
 * @details Creates an IPC client and calls the IPC provider with
 * "check_if_attached"
 * @param p_res CPodResult*
 */
LIB_API
void CFreeResult(CPodResult *p_res);

/**
 * @brief Extract a file from an attached signature
 *
 * @param sig_file_params.sig_file_path path to an attached signature
 * @param sig_file_params.data_file_path destination file
 * @return true on success
 */
LIB_API bool ExtractFileFromAttachedSig(
  SeparateSignatureParams *sig_file_params);

/**
 * @brief Check if the message is Attached
 * @param sig_file_params SeparateSignatureParams struct
 * @return 0 if not,1 if attached, -1 on error
 */
LIB_API int IsMessageAttached(SeparateSignatureParams *sig_file_params);

/**
 * @brief Execute a list of tasks
 *
 * @param tasks The TaskBatch struct is an array of pointers to CPodParam.
 * @return pointer to TaskBatchResult which is an array of pointers to
 * CPodResult
 * @details Results will be stored in the same order as the tasks.
 * @details This function allows you to make a call to the CSP with a batch of
 * tasks. It is supposed to make possible batch signing with one password entry.
 */
LIB_API const TaskBatchResult *ExecuteTaskBatch(const TaskBatch *tasks);

/**
 * @brief Free the TaskBatchResult
 * @param p_tasks A pointer to the TaskBatchResult struct
 */
LIB_API void FreeTaskBatchResult(const TaskBatchResult *p_tasks);

#ifdef __cplusplus
}
}  // namespace pdfcsp::c_bridge
#endif