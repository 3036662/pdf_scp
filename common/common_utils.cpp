#include "common_utils.hpp"

#include <algorithm>
#include <filesystem>
#include <fstream>

namespace pdfcsp::utils {

// read file to vector
std::optional<std::vector<unsigned char>> FileToVector(
  const std::string &path) noexcept {
  namespace fs = std::filesystem;
  if (path.empty() || !fs::exists(path) || !fs::is_regular_file(path)) {
    return std::nullopt;
  }
  std::ifstream file(path, std::ios_base::binary);
  if (!file.is_open()) {
    return std::nullopt;
  }
  std::vector<unsigned char> res;
  res.reserve(std::filesystem::file_size(path));
  try {
    for (auto it = std::istreambuf_iterator<char>(file);
         it != std::istreambuf_iterator<char>(); ++it) {
      res.push_back(*it);
    }
  } catch ([[maybe_unused]] const std::exception & /*ex*/) {
    file.close();
    return std::nullopt;
  }
  file.close();
  return res;
}

std::string VecBytesStringRepresentation(
  const std::vector<unsigned char> &vec) noexcept {
  std::stringstream builder;
  for (const auto symbol : vec) {
    builder << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<int>(symbol);
  }
  return builder.str();
}

void RemoveWhiteSpacesInline(std::string &str) {
  auto it_tmp = std::remove_if(str.begin(), str.end(), [](char val) {
    return val == ' ' || val == '\n' || val == '\t' || val == '\r';
  });
  str.erase(it_tmp, str.end());
}

}  // namespace pdfcsp::utils