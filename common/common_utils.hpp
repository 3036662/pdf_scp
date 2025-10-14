#pragma once

/* File: common_utils.hpp

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

#include <optional>
#include <string>
#include <vector>

namespace pdfcsp::utils {

std::optional<std::vector<unsigned char>> FileToVector(
  const std::string &path) noexcept;

bool VecToFile(const std::vector<unsigned char> &data,
               const std::string &dest) noexcept;

std::string VecBytesStringRepresentation(
  const std::vector<unsigned char> &vec) noexcept;

void RemoveWhiteSpacesInline(std::string &str);

}  // namespace pdfcsp::utils