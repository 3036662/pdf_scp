#include "utils.hpp"
#include <iostream>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <vector>

namespace pdfcsp::csp {

std::vector<unsigned char> CreateBuffer(size_t size) {
  std::vector<unsigned char> res;
  if (size > res.max_size()) {
    throw std::logic_error("Can't reserve a buffer, size > max_size");
  }
  res.reserve(size + 1);
  return res;
}

std::optional<std::vector<unsigned char>>
IntBlobToVec(const CRYPT_INTEGER_BLOB *p_blob) noexcept {
  if (p_blob == nullptr || p_blob->cbData <= 0 || p_blob->cbData > 0x7FFFFFFF) {
    return std::nullopt;
  }
  std::vector<unsigned char> res;
  const DWORD index_last = p_blob->cbData - 1;
  for (int i = static_cast<int>(index_last); i >= 0; --i) {
    // NOLINTNEXTLINE (cppcoreguidelines-pro-bounds-pointer-arithmetic)
    res.push_back(p_blob->pbData[i]);
  }
  if (res.empty()) {
    return std::nullopt;
  }
  return res;
}

std::string
VecBytesStringRepresentation(const std::vector<unsigned char> &vec) noexcept {
  std::stringstream builder;
  for (const auto symbol : vec) {
    builder << std::hex << symbol;
  }
  return builder.str();
}

} // namespace pdfcsp::csp