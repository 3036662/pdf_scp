/* File: sig_val.hpp  
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
#include "pdf_defs.hpp"
#include "pdf_structs.hpp"
#include <cstddef>
#include <optional>

namespace pdfcsp::pdf {

struct SigVal {
  ObjRawId id;
  std::string type = kTagSig;
  std::string filter = kAdobePPKLite;
  std::string subfilter = kETSICAdESdetached;
  BytesVector contents_raw;
  // std::vector<std::pair<uint64_t, uint64_t>> byteranges;
  std::optional<std::string> date; //(D:20241015123037Z) only for CADES_BES
  std::optional<std::string> app_fullname = kAltLinuxPdfSignTool;

  size_t hex_str_offset = 0;
  size_t hex_str_length = 0;
  size_t byteranges_str_offset = 0;

  ///@brief calculate offset for hex string
  void CalcOffsets();

  [[nodiscard]] std::string ToString() const;
};

} // namespace pdfcsp::pdf