#pragma once
#include <optional>
#include <string>
#include <vector>

namespace pdfcsp::utils {

std::optional<std::vector<unsigned char>> FileToVector(
  const std::string &path) noexcept;

}  // namespace pdfcsp::utils