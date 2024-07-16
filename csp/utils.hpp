#pragma once

#include <vector>

namespace pdfcsp::csp {

/**
 * @brief Create a Buffer object
 *
 * @param size
 * @return std::vector<unsigned char>
 */
std::vector<unsigned char> CreateBuffer(size_t size);

} // namespace pdfcsp::csp