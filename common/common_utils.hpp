#pragma once
#include <optional>
#include <string>
#include <vector>

namespace pdfcsp::utils {

std::optional<std::vector<unsigned char>> FileToVector(
  const std::string &path) noexcept;

bool VecToFile(const std::vector<unsigned char> &data,
               const std::string &dest) noexcept;

std::string VecBytesStringRepresentation(
  const std::vector<unsigned char> &vec) noexcept;

void RemoveWhiteSpacesInline(std::string &str);

}  // namespace pdfcsp::utils