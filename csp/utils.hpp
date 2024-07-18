#pragma once

#include "resolve_symbols.hpp"
#include <sstream>
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Winvalid-utf8"
#include <CSP_WinCrypt.h> /// NOLINT
#pragma GCC diagnostic pop

#include <optional>
#include <string>
#include <vector>

namespace pdfcsp::csp {

/**
 * @brief Create a Buffer object
 *
 * @param size
 * @return std::vector<unsigned char>
 * @throws logic_error if size>max_size
 */
std::vector<unsigned char> CreateBuffer(size_t size);

/**
 * @brief Copy little-endian blob to flat vector
 *
 * @param p_blob
 * @return std::optional<std::vector<unsigned char>>
 */
std::optional<std::vector<unsigned char>>
IntBlobToVec(const CRYPT_INTEGER_BLOB *p_blob) noexcept;

// throw exception if FALSE
void ResCheck(BOOL res, const std::string &msg,
              const PtrSymbolResolver &symbols);

std::string
VecBytesStringRepresentation(const std::vector<unsigned char> &vec) noexcept;

// TODO(oleg): move from message
[[nodiscard]] std::optional<std::string>
NameBlobToString(CERT_NAME_BLOB *ptr_name_blob) noexcept;

} // namespace pdfcsp::csp