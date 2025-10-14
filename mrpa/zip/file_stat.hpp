#pragma once

/* File: file_stat.hpp
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

#include <boost/json/object.hpp>
#include <cstdint>
#include <optional>
#include <string>

namespace zip_cpp {

struct FileStat {
  std::optional<std::string> name;
  std::optional<uint64_t> index;
  std::optional<uint64_t> size;
  std::optional<uint64_t> size_compressed;
  std::optional<time_t> time_mod;
  std::optional<uint32_t> crc;
  std::optional<uint16_t> comp_method;
  std::optional<uint16_t> encryption_method;
  bool encrypted = false;

  [[nodiscard]] std::string toString() const noexcept;
  [[nodiscard]] boost::json::object toJson() const;
};

}  // namespace zip_cpp