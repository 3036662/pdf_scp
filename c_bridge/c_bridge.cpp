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
#include "ipc_bridge/ipc_client.hpp"
#include "logger_utils.hpp"
#include "pod_structs.hpp"
#include <exception>
#include <iostream>

namespace pdfcsp::c_bridge {

using RangesVector = std::vector<std::pair<uint64_t, uint64_t>>;

/**
 * @brief Check the signature
 * @details Creates an IPC client and calls the IPC provider with given
 * parameters and empty command
 * @param params @see pod_structs.hpp#CPodParam
 * @return CPodResult* @see  pod_structs.hpp#CPodResult
 * @warning the caller must call CFreeResult
 */
CPodResult *CGetCheckResult(CPodParam params) {
  if (params.command == nullptr &&
      (params.byte_range_arr == nullptr || params.byte_ranges_size == 0 ||
       params.raw_signature_data == nullptr || params.raw_signature_size == 0 ||
       params.file_path == nullptr || params.file_path_size == 0)) {
    return nullptr;
  }
  ipc_bridge::IpcClient ipc_client(params);
  try {
    return ipc_client.CallProvider();
  } catch (const std::exception &ex) {
    auto logger = logger::InitLog();
    if (logger) {
      logger->error("[CGetCheckResult] {}", ex.what());
    } else {
      std::cerr << "[ERROR] " << ex.what() << "\n";
    }
    return nullptr;
  }
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
  return CGetCheckResult(params);
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
  return CGetCheckResult(params);
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

} // namespace pdfcsp::c_bridge