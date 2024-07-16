#pragma once

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
    const std::vector<std::pair<long long, long long>> &byteranges) noexcept;

/**
 * @brief Create a Buffer object
 *
 * @param size
 * @return std::vector<unsigned char>
 */
std::vector<unsigned char> CreateBuffer(size_t size);

} // namespace pdfcsp::pdf