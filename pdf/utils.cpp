#include "utils.hpp"
#include <exception>
#include <filesystem>
#include <fstream>
#include <ios>
#include <iterator>
#include <optional>
#include <vector>

namespace pdfcsp::pdf {

// read file to vector
std::optional<std::vector<unsigned char>>
FileToVector(const std::string &path) noexcept {
  namespace fs = std::filesystem;
  if (path.empty() || !fs::exists(path)) {
    return std::nullopt;
  }
  std::ifstream file(path, std::ios_base::binary);
  if (!file.is_open()) {
    return std::nullopt;
  }
  std::vector<unsigned char> res;
  try {
    std::vector<unsigned char> tmp((std::istream_iterator<unsigned char>(file)),
                                   std::istream_iterator<unsigned char>());
    res = std::move(tmp);
  } catch ([[maybe_unused]] const std::exception &ex) {
    file.close();
    return std::nullopt;
  }
  file.close();
  return res;
}

} // namespace pdfcsp::pdf