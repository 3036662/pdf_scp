#include "utils.hpp"
#include "pdf_structs.hpp"
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <filesystem>
#include <fstream>
#include <ios>
#include <iostream>
#include <iterator>
#include <limits>
#include <numeric>
#include <optional>
#include <stdexcept>
#include <utility>
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
  res.reserve(std::filesystem::file_size(path));
  try {
    for (auto it = std::istreambuf_iterator<char>(file);
         it != std::istreambuf_iterator<char>(); ++it) {
      res.push_back(*it);
    }
  } catch ([[maybe_unused]] const std::exception &ex) {
    file.close();
    return std::nullopt;
  }
  file.close();
  return res;
}

std::optional<std::vector<unsigned char>> FileToVector(
    const std::string &path,
    const std::vector<std::pair<uint64_t, uint64_t>> &byteranges) noexcept {
  namespace fs = std::filesystem;
  if (path.empty() || !fs::exists(path)) {
    return std::nullopt;
  }
  std::ifstream file(path, std::ios_base::binary);
  if (!file.is_open()) {
    return std::nullopt;
  }
  std::vector<unsigned char> res;
  uint64_t buff_size = 0;
  for (const auto &range : byteranges) {
    buff_size += range.second;
  }
  try {
    res.reserve(buff_size);
    for (const auto &brange : byteranges) {
      if (brange.first >
          static_cast<uint64_t>(std::numeric_limits<int64_t>::max())) {
        throw std::runtime_error(
            "[FileToVector] byterange offset is > max_int64\n");
      }

      file.seekg(static_cast<int64_t>(brange.first));
      if (!file) {
        throw std::exception();
      }
      for (uint64_t i = 0; i < brange.second; ++i) {
        char symbol = 0;
        file.get(symbol);
        if (!file) {
          throw std::exception();
        }
        res.push_back(symbol);
      }
    }
  } catch ([[maybe_unused]] const std::exception &ex) {
    std::cerr << ex.what() << "\n";
    file.close();
    return std::nullopt;
  }
  file.close();
  return res;
}

std::string DoubleToString10(double val) {
  std::ostringstream builder;
  builder << std::setprecision(10) << std::fixed << val;
  std::string res = builder.str();
  res.erase(res.find_last_not_of('0') + 1, std::string::npos);
  if (res.back() == '.') {
    res.pop_back();
  }
  if (res == "-0") {
    res = "0";
  }
  return res;
}

/**
 * @brief Return page rect
 * @param obj
 * @return BBox
 */
std::optional<BBox> PageRect(const PtrPdfObjShared &page_obj) noexcept {
  if (!page_obj || page_obj->isNull() || !page_obj->isDictionary() ||
      !page_obj->hasKey(kTagType) ||
      page_obj->getKey(kTagType).getName() != kTagPage ||
      !page_obj->hasKey(kTagMediaBox) ||
      !page_obj->getKey(kTagMediaBox).isArray()) {
    return std::nullopt;
  }
  auto arr = page_obj->getKey(kTagMediaBox).getArrayAsRectangle();
  BBox res;
  res.left_bottom.x = arr.llx;
  res.left_bottom.y = arr.lly;
  res.right_top.x = arr.urx;
  res.right_top.y = arr.ury;
  return res;
}

std::map<std::string, std::string> DictToUnparsedMap(QPDFObjectHandle &dict) {
  if (!dict.isDictionary()) {
    return {};
  }
  auto src_map = dict.getDictAsMap();
  std::map<std::string, std::string> unparsed_map;
  std::for_each(src_map.begin(), src_map.end(),
                [&unparsed_map](
                    std::pair<const std::string, QPDFObjectHandle> &pair_val) {
                  unparsed_map[pair_val.first] = pair_val.second.unparse();
                });
  return unparsed_map;
}

std::string UnparsedMapToString(const std::map<std::string, std::string> &map) {
  {
    std::ostringstream builder;
    std::for_each(map.cbegin(), map.cend(),
                  [&builder](const std::pair<std::string, std::string> &pair) {
                    builder << pair.first << " " << pair.second << "\n";
                  });
    return builder.str();
  }
}

} // namespace pdfcsp::pdf