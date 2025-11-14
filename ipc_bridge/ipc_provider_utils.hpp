/* File: ipc_provider_utils.hpp
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
#include <optional>

#include "ipc_param.hpp"
#include "ipc_result.hpp"

namespace pdfcsp::ipc_bridge {

/**
 * @brief Fill all results for detached message check (PDF with byteranges)
 * @param params (IPCParam)
 * @param [out] res (IPCResult)
 */
void CheckDetachedWithByteRanges(const IPCParam &params, IPCResult &res);

/**
 * @brief Fill all check results for a detached message
 * @param params (IPCParam)
 * @param [out] res (IPCResult)
 * @details params.sig_file_path or params.raw_signature_data must be set
 * @details params.file_path must be set
 * @details if using raw_signature_data it must be ASN1 encoded
 */
void CheckSimpleDetached(const IPCParam &params, IPCResult &res);

/**
 * @brief Fill all check results for an attached message
 * @param params (IPCParam)
 * @param [out] res (IPCResult)
 * @details params.sig_file_path or params.raw_signature_data must be set
 * @details if using raw_signature_data it must be ASN1 encoded
 */
void CheckSimpleAttached(const IPCParam &params, IPCResult &res);

/**
 * @brief Fill only user_certificate_list_json
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

/**
 * @brief Check if the message is attached
 * @param params (IPCParam)
 * @param res (IPCResult)
 * @details fills only message_is_attached,common_execution_status
 */
void FillCheckIfAttached(const IPCParam &params, IPCResult &res);

/**
 * @brief Extracts the attached file
 *
 * @param params.sig_file_path  - path to an attached signature
 * @param params.file_path  - path to a destination file
 * @return res.common_execution_status == true on success
 */
void ExtractFileFromAttached(const IPCParam &params, IPCResult &res);

/**
 * @brief Create a Signature
 *
 * @param [in] params.file_path a source file
 * @param [in] params.sig_file_path a destination file
 * @param [in] params.cert_subject a certificate subject common name
 * @param [in] params.cert_serial a certificate serial (lowercase)
 * @param [in] params.cades_type  "CADES_BES" | "CADES_T" |  "CADES_XLT1"
 * @param [in] params.tsp_link TSP service URL
 * @param [in] params.create_attached attached if true
 * @param [in] params.create_base_64_encoded base64 encoded if true
 * @param [out] res.common_execution_status == true on success
 */
void CreateSignatureFile(const IPCParam &params, IPCResult &res);

/// @brief copy file content to vector
std::optional<std::vector<unsigned char>> FileToVector(
  const std::string &path,
  const std::vector<std::pair<uint64_t, uint64_t>> &byteranges) noexcept;

}  // namespace pdfcsp::ipc_bridge