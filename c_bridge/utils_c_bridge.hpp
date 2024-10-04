#pragma once

#include "check_result.hpp"
#include "pod_structs.hpp"
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace pdfcsp::c_bridge::utils {

std::optional<std::vector<unsigned char>> FileToVector(
    const std::string &path,
    const std::vector<std::pair<uint64_t, uint64_t>> &byteranges) noexcept;

CPodResult *
PodResultFromResult(const csp::checks::CheckResult &cppres) noexcept;

} // namespace pdfcsp::c_bridge::utils