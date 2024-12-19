/* File: form_x_object.hpp  
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

namespace pdfcsp::pdf {

/*
Transformation matrix in pdf
[a b 0]
[c d 0]
[e f 0]

*/

struct FormXObject {
  ObjRawId id;
  std::string type = kTagXObject;
  std::string subtype = kTagForm;
  BBox bbox; // An array of four numbers in the form coordinate system ,the
             // coordinates of the left, bottom, right, and top edges
             // respectively, of the form XObject’s bounding box.
  int form_type = 1;
  std::string resources_img_tag_name = "/img_sig1";
  ObjRawId resources_img_ref;
  Matrix matrix;

  [[nodiscard]] std::string ToString() const;
};

} // namespace pdfcsp::pdf