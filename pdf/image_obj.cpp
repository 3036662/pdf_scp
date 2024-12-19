/* File: image_obj.cpp
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

#include "image_obj.hpp"

#include <filesystem>
#include <iterator>
#include <sstream>
#include <utility>

#include "pdf_structs.hpp"
#include "pdf_utils.hpp"

namespace pdfcsp::pdf {

std::string ImageObj::ToString() const {
  std::ostringstream builder;
  builder << id.ToString() << "\n"
          << kDictStart << "\n"
          << kTagType << " " << kTagXObject << "\n"
          << kTagSubType << " " << kTagImage << "\n"
          << kTagWidth << " " << width << "\n"
          << kTagHeight << " " << height << "\n"
          << kTagColorSpace << " " << kDeviceRgb << "\n"
          << kTagBitsPerComponent << " " << bits_per_component << "\n"
          << kTagLength << " " << data.size() << "\n"
          << kDictEnd << "\n";
  return builder.str();
}

BytesVector ImageObj::ToRawData() const {
  BytesVector res;
  std::string strdata = ToString();
  strdata += kStreamStart;
  res.reserve(data.size() + strdata.size());
  std::copy(strdata.cbegin(), strdata.cend(), std::back_inserter(res));
  std::copy(data.cbegin(), data.cend(), std::back_inserter(res));
  strdata = "\n";
  strdata += kStreamEnd;
  strdata += kObjEnd;
  std::copy(strdata.cbegin(), strdata.cend(), std::back_inserter(res));
  return res;
}

bool ImageObj::ReadFile(const std::string &path, uint32_t pix_width,
                        uint32_t pix_height,
                        int32_t bits_p_component) noexcept {
  if (path.empty() || !std::filesystem::exists(path) || pix_width == 0 ||
      pix_height == 0 || bits_p_component == 0) {
    return false;
  }
  // read file
  auto buf = FileToVector(std::string(path));
  if (!buf || buf->empty()) {
    return false;
  }
  data = std::move(buf.value());
  width = pix_width;
  height = pix_height;
  bits_per_component = bits_p_component;
  return true;
}

}  // namespace pdfcsp::pdf