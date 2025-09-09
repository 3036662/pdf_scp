/* File: c_bridge.cpp
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

#include "c_bridge.hpp"

#include <array>
#include <cstdint>
#include <exception>
#include <iostream>

#include "ipc_bridge/ipc_client.hpp"
#include "logger_utils.hpp"
#include "pod_structs.hpp"

namespace pdfcsp::c_bridge {

using RangesVector = std::vector<std::pair<uint64_t, uint64_t>>;

CPodResult *CGetCheckResult(CPodParam params) { return CGetIPCResult(params); }

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
CPodResult *CheckSimpleDetached(CPodParam params) {
  params.command = "check_simple_detached";
  params.command_size = 21;
  return CGetIPCResult(params);
}

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
CPodResult *CheckSimpleAttached(CPodParam params) {
  params.command = "check_simple_attached";
  params.command_size = 21;
  return CGetIPCResult(params);
}

/**
 * @brief Check the signature
 * @details Creates an IPC client and calls the IPC provider with given
 * parameters and empty command
 * @param params @see pod_structs.hpp#CPodParam
 * @return CPodResult* @see  pod_structs.hpp#CPodResult
 * @warning the caller must call CFreeResult
 */
CPodResult *CGetIPCResult(CPodParam params) {
  if (params.command == nullptr &&
      (params.byte_range_arr == nullptr || params.byte_ranges_size == 0 ||
       params.raw_signature_data == nullptr || params.raw_signature_size == 0 ||
       params.file_path == nullptr || params.file_path_size == 0)) {
    return nullptr;
  }
  ipc_bridge::IpcClient ipc_client;
  try {
    TaskBatch tasks;
    const std::array<CPodParam *, 1> arr{&params};
    tasks.params = arr.data();
    tasks.params_size = 1;
    const TaskBatchResult batch_res = ipc_client.CallProvider(tasks);
    CPodResult *res = nullptr;
    if (batch_res.results != nullptr && batch_res.results_size > 0) {
      res = batch_res.results[0];
      batch_res.results[0] = nullptr;
      delete[] batch_res.results;  // NOLINT
    }
    return res;
  } catch (const std::exception &ex) {
    auto logger = logger::InitLog();
    if (logger) {
      logger->error("[CGetIPCResult] {}", ex.what());
    } else {
      std::cerr << "[ERROR] " << ex.what() << "\n";
    }
    return nullptr;
  }
}

/**
 * @brief Execute a list of task
 *
 * @param tasks Array of pointers to CPodParam
 * @return pointer to TaskBatchResult witch is array of pointers to CPodResult
 * @details results will be stored in same order as tasks
 */
LIB_API const TaskBatchResult *ExecuteTaskBatch(const TaskBatch *p_tasks) {
  if (p_tasks == nullptr || p_tasks->params == nullptr ||
      p_tasks->params_size == 0) {
    return nullptr;
  }
  ipc_bridge::IpcClient ipc_client;
  try {
    const TaskBatchResult batch_res = ipc_client.CallProvider(*p_tasks);
    if (batch_res.results == nullptr || batch_res.results_size == 0) {
      return nullptr;
    }
    TaskBatchResult *result = new TaskBatchResult(batch_res);  // NOLINT
    return result;
  } catch (const std::exception &ex) {
    auto logger = logger::InitLog();
    if (logger) {
      logger->error("[ExecuteTaskBatch] {}", ex.what());
    } else {
      std::cerr << "[ERROR] " << ex.what() << "\n";
    }
    return nullptr;
  }
}

/*  pointer to TaskBatchResult
 *   => contains an array of pointers to the CpodResult
 *     => each CPodResult contains a pointer to the BridgeObjStorage
 */
void FreeTaskBatchResult(const TaskBatchResult *p_tasks) {
  if (p_tasks == nullptr) {
    return;
  }
  if (p_tasks->results != nullptr && p_tasks->results_size > 0) {
    // for each CPodResult
    for (uint64_t ind = 0; ind < p_tasks->results_size; ++ind) {
      // delete CPodResult
      CPodResult *p_cpod_res = p_tasks->results[ind];
      CFreeResult(p_cpod_res);
      p_tasks->results[ind] = nullptr;
    }
    // delete the array of pointers CPodResult*[]
    delete[] p_tasks->results;  // NOLINT
  }
  // delete TaskBatchResult
  delete p_tasks;  // NOLINT
}

/**
 * @brief Get user's certificate list
 * @details Calls an IPC Provider with "user_cert_list" command
 * @param params Should be called with default constructed CPodParam struct
 * @return CPodResult* @see  pod_structs.hpp#CPodResult
 * @warning the caller must call CFreeResult c
 */
CPodResult *CGetCertList(CPodParam params) {
  params.command = "user_cert_list";
  params.command_size = 14;
  return CGetIPCResult(params);
}

/**
 * @brief Perform a PDF file sign
 * @details Creates an IPC client and calls the IPC provider with "sign_pdf"
 * command
 * @param params @see pod_structs.hpp#CPodParam
 * @return CPodResult* @see  pod_structs.hpp#CPodResult
 * @warning the caller must call CFreeResult
 */
CPodResult *CSignPdf(CPodParam params) {
  params.command = "sign_pdf";
  params.command_size = 8;
  if (params.byte_range_arr == nullptr || params.byte_ranges_size == 0 ||
      params.file_path == nullptr || params.file_path_size == 0 ||
      params.cert_serial == nullptr || params.cert_subject == nullptr ||
      params.cades_type == nullptr) {
    return nullptr;
  }
  return CGetIPCResult(params);
}

/**
 * @brief Extract a file from an attached signature
 *
 * @param sig_file_params.sig_file_path path to an attached signature
 * @param sig_file_params.data_file_path destination file
 * @return true on success
 */
LIB_API bool ExtractFileFromAttachedSig(
  SeparateSignatureParams *sig_file_params) {
  if (sig_file_params == nullptr || sig_file_params->sig_file_path == nullptr ||
      sig_file_params->sig_file_path_size == 0 ||
      sig_file_params->data_file_path == nullptr ||
      sig_file_params->data_file_path_size == 0) {
    return false;
  }
  CPodParam params;
  params.command = "extract_attached";
  params.command_size = 16;
  params.sig_file_path = sig_file_params->sig_file_path;
  params.sig_file_path_size = sig_file_params->sig_file_path_size;
  params.file_path = sig_file_params->data_file_path;
  params.file_path_size = sig_file_params->data_file_path_size;
  auto *res = CGetIPCResult(params);
  const bool result = (res != nullptr) && res->common_execution_status;
  CFreeResult(res);
  return result;
}

// NOLINTBEGIN(cppcoreguidelines-owning-memory)

/**
 * @brief Free resources occupied by CSignPdf, CGetCertList,CGetCheckResult
 * @param p_res CPodResult*
 */
void CFreeResult(CPodResult *p_res) {
  if (p_res != nullptr) {
    delete p_res->p_stor;
  }
  delete p_res;
}
// NOLINTEND(cppcoreguidelines-owning-memory)

int IsMessageAttached(SeparateSignatureParams *sig_file_params) {
  CPodParam params;
  params.command = "check_if_attached";
  params.command_size = 17;
  params.sig_file_path = sig_file_params->sig_file_path;
  params.sig_file_path_size = sig_file_params->sig_file_path_size;
  auto *p_res = CGetIPCResult(params);
  if (p_res == nullptr) {
    return -1;
  }
  const bool result = p_res->message_is_attached;
  const bool parse_err = !p_res->common_execution_status;
  CFreeResult(p_res);
  if (parse_err) {
    return -1;
  }
  return result ? 1 : 0;
}

}  // namespace pdfcsp::c_bridge