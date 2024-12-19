/* File: pdf_utils.cpp
Copyright (C) Basealt LLC,  2024
Author: Oleg Proskurin, <proskurinov@basealt.ru>

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with this program; if not, write to the Free Software Foundation,
Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

#include "pdf_utils.hpp"

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
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "logger_utils.hpp"
#include "pdf_defs.hpp"
#include "pdf_structs.hpp"

namespace pdfcsp::pdf {

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
    auto logger = logger::InitLog();
    if (logger) {
      logger->error("pdf_utils {}", ex.what());
    }
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
std::optional<BBox> VisiblePageSize(const PtrPdfObjShared &page_obj) noexcept {
  if (!page_obj || page_obj->isNull() || !page_obj->isDictionary() ||
      !page_obj->hasKey(kTagType) ||
      page_obj->getKey(kTagType).getName() != kTagPage) {
    return std::nullopt;
  }
  QPDFPageObjectHelper page_helper(*page_obj);
  auto media_box = page_helper.getMediaBox();
  if (!media_box.isArray()) {
    return std::nullopt;
  }
  auto crop_box = page_helper.getCropBox();
  auto crop_box_rect = crop_box.getArrayAsRectangle();
  BBox res;
  res.left_bottom.x = 0;
  res.left_bottom.y = 0;
  res.right_top.x = crop_box_rect.urx - crop_box_rect.llx;
  res.right_top.y = crop_box_rect.ury - crop_box_rect.lly;
  return res;
}

/**
 * @brief Return horizontal and vertical offset of cropbox
 * @param page_obj
 * @return XYReal
 */
std::optional<XYReal> CropBoxOffsetsXY(
  const PtrPdfObjShared &page_obj) noexcept {
  if (!page_obj || page_obj->isNull() || !page_obj->isDictionary() ||
      !page_obj->hasKey(kTagType) ||
      page_obj->getKey(kTagType).getName() != kTagPage) {
    return std::nullopt;
  }
  QPDFPageObjectHelper page_helper(*page_obj);
  auto crop_box = page_helper.getCropBox();
  auto crop_box_rect = crop_box.getArrayAsRectangle();
  return XYReal{crop_box_rect.llx, crop_box_rect.lly};
}

/**
 * @brief Converts pdf dictionary to unparsed map "/Key" -> "Value"
 * @param dict object
 * @return std::map<std::string, std::string>  unparsed dictionary
 */
std::map<std::string, std::string> DictToUnparsedMap(QPDFObjectHandle &dict) {
  if (!dict.isDictionary()) {
    return {};
  }
  auto src_map = dict.getDictAsMap();
  std::map<std::string, std::string> unparsed_map;
  std::for_each(
    src_map.begin(), src_map.end(),
    [&unparsed_map](std::pair<const std::string, QPDFObjectHandle> &pair_val) {
      unparsed_map[pair_val.first] = pair_val.second.unparse();
    });
  return unparsed_map;
}

/**
 * @brief Join an unparsed dictionary map to signle string
 * @param map
 * @return std::string
 */
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

/**
 * @brief Build a cross-reference table
 * @details 7.5.4 Cross-Reference Table
 * @param entries
 * @return std::string ready for embedding
 */
std::string BuildXrefRawTable(const std::vector<XRefEntry> &entries) {
  auto entries_cp = entries;
  std::sort(entries_cp.begin(), entries_cp.end(),
            [](const XRefEntry &left, const XRefEntry &right) {
              return left.id.id < right.id.id;
            });
  int prev = 0;
  int counter = 0;
  int start_id = 0;
  std::ostringstream res;
  res << kXref;
  std::string tmp;
  for (size_t i = 0; i < entries_cp.size(); ++i) {
    // first iteration or current entry element id is sequentinal
    if (i == 0 || entries_cp[i].id.id == prev + 1) {
      if (counter == 0) {  // store first el number
        start_id = entries_cp[i].id.id;
      }
      tmp.append(entries_cp[i].ToString());
      prev = entries_cp[i].id.id;
      ++counter;
      continue;
    }
    // not sequentinal element was encountered
    res << start_id << " " << counter << "\n" << tmp;
    counter = 1;
    tmp.clear();
    tmp.append(entries_cp[i].ToString());
    start_id = entries_cp[i].id.id;
    prev = entries_cp[i].id.id;
  }
  res << start_id << " " << counter << "\n" << tmp;
  return res.str();
}

/**
 * @brief sorts entries, builds sections for cross-reference stream
 * @param entries
 * @return std::vector<std::pair<int, int>>
 * @details ISO 32000 [7.5.8 Cross-Reference Streams]
 * @details TEST_CASE("XrefStreamSections")
 */
std::vector<std::pair<int, int>> BuildXRefStreamSections(
  std::vector<XRefEntry> &entries) {
  std::vector<std::pair<int, int>> res;
  if (entries.empty()) {
    return res;
  }
  std::sort(entries.begin(), entries.end(),
            [](const XRefEntry &left, const XRefEntry &right) {
              return left.id.id < right.id.id;
            });
  int prev = 0;
  int counter = 0;
  int start_id = 0;
  for (size_t i = 0; i < entries.size(); ++i) {
    // first iteration or current entry element id is sequentinal
    const int curr_id = entries[i].id.id;
    if (curr_id == prev) {  // duplicates found
      throw std::runtime_error("[BuildXRefStreamSections] non unique entries");
    }
    if (i == 0 || curr_id == prev + 1) {
      if (counter == 0) {  // store first el number
        start_id = curr_id;
      }
      ++counter;
      prev = curr_id;
      continue;
    }
    // not sequentinal element was encountered
    res.emplace_back(start_id, counter);  // save section to result
    counter = 1;
    start_id = curr_id;
    prev = curr_id;
  }
  if (start_id != 0 && counter > 0) {
    res.emplace_back(start_id, counter);
  }
  return res;
}

/**
 * @brief Find last startxref in buffer
 * @param buf
 * @return string - offset in byres
 */
std::optional<std::string> FindXrefOffset(const BytesVector &buf) {
  std::vector<unsigned char> tag = {'s', 't', 'a', 'r', 't',
                                    'x', 'r', 'e', 'f'};
  // const size_t end = buf.size() - tag.size() - 1;
  const size_t tag_size = tag.size();
  size_t last = std::string::npos;

  for (size_t i = buf.size() - tag_size; (i > 1 && last == std::string::npos);
       --i) {
    for (size_t j = 0; j < tag_size; ++j) {
      if (buf[i + j] != tag[j]) {
        break;
      }
      if (j == tag_size - 1) {
        last = i;
      }
    }
  }
  if (last == std::string::npos) {
    return std::nullopt;
  }
  last += tag_size;
  while (last < buf.size() && (buf[last] == '\r' || buf[last] == '\n')) {
    ++last;
  }
  size_t last_end = last;
  while (
    last_end < buf.size() &&
    (buf[last_end] != '\r' && buf[last_end] != '\n' && buf[last_end] != ' ')) {
    ++last_end;
  }
  if (last_end > last && last_end < buf.size()) {
    std::string res;
    std::copy(buf.data() + last, buf.data() + last_end,
              std::back_inserter(res));
    return res;
  }
  return std::nullopt;
}

/**
 * @brief Convert byte array to simple hex string
 * @param vec
 * @return std::string
 */
std::string ByteVectorToHexString(const BytesVector &vec) {
  std::ostringstream oss;
  for (const unsigned char byte : vec) {
    oss << std::hex << std::setw(2) << std::setfill('0')
        << static_cast<int>(byte);
  }
  return oss.str();
}

void PatchDataToFile(const std::string &path, size_t offset,
                     const std::string &data) {
  const std::string func_name = "[PatchDataToFile] ";
  if (path.empty() || data.empty() || !std::filesystem::exists(path)) {
    throw std::invalid_argument(func_name + "invalid args");
  }
  std::fstream file(path, std::ios::in | std::ios::out | std::ios_base::binary);
  if (!file.is_open()) {
    throw std::runtime_error(func_name + "error opening file " + path);
  }
  if (offset >
      std::numeric_limits<std::basic_ofstream<char>::off_type>::max()) {
    throw std::runtime_error(func_name + "offset is to big");
  }
  file.seekp(static_cast<std::basic_ofstream<char>::off_type>(offset));
  if (file.fail()) {
    file.close();
    throw std::runtime_error(func_name + "error seeking to offset");
  }
  for (const auto &symbol : data) {
    file << symbol;
  }
  if (file.fail()) {
    file.close();
    throw std::runtime_error(func_name + "error write to file");
  }
  file.close();
}

}  // namespace pdfcsp::pdf
