/* File: common_utils.cpp
Copyright (C) Basealt LLC,  2025
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

#include "common_utils.hpp"

#include <algorithm>
#include <exception>
#include <filesystem>
#include <fstream>
#include <ios>

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

bool VecToFile(const std::vector<unsigned char> &data,
               const std::string &dest) noexcept {
  try {
    const std::filesystem::path fpath{dest};
    if (!std::filesystem::exists(fpath.parent_path()) &&
        !std::filesystem::create_directories(fpath.parent_path())) {
      return false;
    }
  } catch (const std::exception &) {
    return false;
  }
  if (dest.empty()) {
    return false;
  }
  std::ofstream file(dest,
                     std::ios::out | std::ios_base::binary | std::ios::trunc);
  if (!file.is_open()) {
    return false;
  }
  if (data.size() > std::numeric_limits<std::streamsize>::max()) {
    return false;
  }
  file.write(reinterpret_cast<const char *>(data.data()),  // NOLINT
             static_cast<std::streamsize>(data.size()));
  file.close();
  return true;
}

}  // namespace pdfcsp::utils