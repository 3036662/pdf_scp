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
} // namespace pdfcsp::pdf