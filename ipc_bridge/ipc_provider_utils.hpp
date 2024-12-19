/* File: ipc_provider_utils.hpp
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
#include <optional>

#include "ipc_param.hpp"
#include "ipc_result.hpp"

namespace pdfcsp::ipc_bridge {

/**
 * @brief Fill all results for message check
 * @param params (IPCParam)
 * @param res (IPCResult)
 */
void FillResult(const IPCParam &params, IPCResult &res);

/**
 * @brief Fill only user_certifitate_list_json
 * @param params (IPCParam.command should be "user_cert_list")
 * @param res (IPCResult)
 */
void FillCertListResult(const IPCParam &, IPCResult &res);

/**
 * @brief Fill all results for signature creation
 * @param params (IPCParam)
 * @param res (IPCResult)
 */
void FillSignResult(const IPCParam &params, IPCResult &res);

/**
 * @brief Fill the result with no data and execution_status=false
 * @param error_string to pass client
 * @param res (IPCResult)
 */
void FillFailResult(const std::string &error_string, IPCResult &res);

/// @brief copy file content to vector
std::optional<std::vector<unsigned char>> FileToVector(
  const std::string &path,
  const std::vector<std::pair<uint64_t, uint64_t>> &byteranges) noexcept;
}  // namespace pdfcsp::ipc_bridge