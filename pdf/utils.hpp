#pragma once

#include <optional>
#include <vector>

namespace pdfcsp::pdf {
/**
 * @brief Load file to vector
 *
 * @return optional std::vector<unsigned char> - empty if fail
 */
std::optional<std::vector<unsigned char>> FileToVector() noexcept;
} // namespace pdfcsp::pdf