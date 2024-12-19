/* File: sig_field.hpp  
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
#include "pdf_structs.hpp"
#include <optional>

namespace pdfcsp::pdf {

// SigField signature annotation
struct SigField {
  ObjRawId id;
  std::string type = kTagAnnot;
  std::string subtype = kTagWidget;
  ObjRawId parent;
  ObjRawId appearance_ref;
  BBox rect; // the location of the annotation on the page in default user space
             // units.
  std::string ft = kTagSig;
  int flags = 0b100;
  std::optional<std::string> name;
  std::optional<ObjRawId> value;

  [[nodiscard]] std::string ToString() const;
};

} // namespace pdfcsp::pdf