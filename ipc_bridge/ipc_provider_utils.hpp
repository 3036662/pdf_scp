#pragma once
#include "ipc_param.hpp"
#include "ipc_result.hpp"
#include <optional>

namespace pdfcsp::ipc_bridge {

void FillResult(const IPCParam &params, IPCResult &res);

std::optional<std::vector<unsigned char>> FileToVector(
    const std::string &path,
    const std::vector<std::pair<uint64_t, uint64_t>> &byteranges) noexcept;

} // namespace pdfcsp::ipc_bridge