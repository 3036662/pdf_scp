#pragma once
#include <optional>
#include <string>
#include <vector>

namespace pdfcsp::utils {

std::optional<std::vector<unsigned char>> FileToVector(
  const std::string &path) noexcept;

std::string VecBytesStringRepresentation(
  const std::vector<unsigned char> &vec) noexcept;

}  // namespace pdfcsp::utils