#include "utils.hpp"
#include <exception>
#include <filesystem>
#include <fstream>
#include <ios>
#include <iterator>
#include <numeric>
#include <optional>
#include <stdexcept>
#include <vector>

namespace pdfcsp::pdf {

std::vector<unsigned char> CreateBuffer(size_t size) {
  std::vector<unsigned char> res;
  res.reserve(size + 1);
  return res;
}

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

std::optional<std::vector<unsigned char>> FileToVector(
    const std::string &path,
    const std::vector<std::pair<long long, long long>> &byteranges) noexcept {
  namespace fs = std::filesystem;
  if (path.empty() || !fs::exists(path)) {
    return std::nullopt;
  }
  std::ifstream file(path, std::ios_base::binary);
  if (!file.is_open()) {
    return std::nullopt;
  }
  std::vector<unsigned char> res;
  long long buff_size = 0;
  for (const auto &range : byteranges) {
    if (range.second < 0 || range.first < 0) {
      file.close();
      return std::nullopt;
    }
    buff_size += range.second;
  }
  if (buff_size <= 0) {
    return std::nullopt;
  }
  try {
    res.reserve(buff_size);
    for (const auto &brange : byteranges) {
      file.seekg(brange.first);
      if (!file) {
        throw std::exception();
      }
      for (long long i = 0ll; i < brange.second; ++i) {
        char ch = 0;
        file.get(ch);
        if (!file) {
          throw std::exception();
        }
        res.push_back(ch);
      }
    }
  } catch ([[maybe_unused]] const std::exception &ex) {
    file.close();
    return std::nullopt;
  }
  file.close();
  return res;
}

} // namespace pdfcsp::pdf