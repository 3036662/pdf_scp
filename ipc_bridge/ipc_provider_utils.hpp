#pragma once
#include "ipc_param.hpp"
#include "ipc_result.hpp"
#include <optional>

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

std::optional<std::vector<unsigned char>> FileToVector(
    const std::string &path,
    const std::vector<std::pair<uint64_t, uint64_t>> &byteranges) noexcept;

} // namespace pdfcsp::ipc_bridge