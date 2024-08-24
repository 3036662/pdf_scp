#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace pdfcsp::pdf {
/**
 * @brief Load file to vector
 *
 * @return optional std::vector<unsigned char> - empty if fail
 */
std::optional<std::vector<unsigned char>>
FileToVector(const std::string &path) noexcept;

/**
 * @brief Extract data specified by byterange
 *
 * @param path path to file
 * @param byterange vector of pairs {start,length}
 * @return std::optional<std::vector<unsigned char>>
 */
std::optional<std::vector<unsigned char>> FileToVector(
    const std::string &path,
    const std::vector<std::pair<uint64_t, uint64_t>> &byteranges) noexcept;

} // namespace pdfcsp::pdf