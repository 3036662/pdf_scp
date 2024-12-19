/* File: c_bridge.hpp
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
#include "pod_structs.hpp"

namespace pdfcsp::c_bridge {

#define LIB_API __attribute__((visibility("default")))
#define LIB_LOCAL __attribute__((visibility("hidden")))

extern "C" {

/**
 * @brief Check the signature
 * @details Creates an IPC client and calls the IPC provider with given
 * parameters and empty command
 * @param params @see pod_structs.hpp#CPodParam
 * @return CPodResult* @see  pod_structs.hpp#CPodResult
 * @warning the caller must call CFreeResult
 */
LIB_API
CPodResult *CGetCheckResult(CPodParam params);

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
 * @return CPodResult* @see  pod_structs.hpp#CPodResult
 * @warning the caller must call CFreeResult
 */
LIB_API
CPodResult *CSignPdf(CPodParam params);

/**
 * @brief Free resources occupied by CSignPdf, CGetCertList,CGetCheckResult
 * @param p_res CPodResult*
 */
LIB_API
void CFreeResult(CPodResult *p_res);
}

}  // namespace pdfcsp::c_bridge