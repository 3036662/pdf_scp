/* File: image_obj.hpp
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

#pragma once

#include <cstdint>
#include <vector>

#include "pdf_structs.hpp"

namespace pdfcsp::pdf {

struct ImageObj {
  ObjRawId id;
  std::string type = kTagXObject;
  std::string subtype = kTagImage;
  uint32_t width = 0;
  uint32_t height = 0;
  std::string colorspace = kDeviceRgb;
  int32_t bits_per_component = 8;
  std::vector<unsigned char> data;
  double resize_factor_x = 1.0;
  double resize_factor_y = 1.0;

  [[nodiscard]] BytesVector ToRawData() const;
  [[nodiscard]] std::string ToString() const;

  bool ReadFile(const std::string &path, uint32_t pix_width,
                uint32_t pix_height, int32_t bits_p_component) noexcept;
};

}  // namespace pdfcsp::pdf