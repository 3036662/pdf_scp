#include "utils.hpp"
#include <exception>
#include <filesystem>
#include <fstream>
#include <ios>
#include <optional>

namespace pdfcsp::pdf {

std::optional<std::vector<unsigned char>>
FileToVector(const std::string &path) noexcept {
  namespace fs = std::filesystem;
  std::vector<unsigned char> res;
  if (path.empty() || !fs::exists(path)) {
    return std::nullopt;
  }
  uintmax_t size = fs::file_size(path);
  try {
    res.resize(size, 0x00);
  } catch ([[maybe_unused]] const std::exception &ex) {
    return std::nullopt;
  }
  std::ifstream file(path, std::ios_base::binary);
  if (!file.is_open()) {
    return std::nullopt;
  }
  file.read(reinterpret_cast<char *>(res.data()), size);
  if (file.bad()) {
    return std::nullopt;
  }
  file.close();
  return res;
}

} // namespace pdfcsp::pdf