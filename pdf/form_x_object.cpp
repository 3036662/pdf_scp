/* File: form_x_object.cpp  
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


#include "form_x_object.hpp"

namespace pdfcsp::pdf {

/*
Transformation matrix in pdf
[a b 0]
[c d 0]
[e f 0]

*/

std::string FormXObject::ToString() const {
  // build a stream
  std::string xstream;
  {
    Matrix matrix2{};
    matrix2.a = bbox.right_top.x;
    matrix2.d = bbox.right_top.y;
    std::ostringstream stream_builder;
    stream_builder << "q\n"
                   << matrix.toString() << " cm\n"
                   << matrix2.toString() << " cm\n"
                   << resources_img_tag_name << " " << "Do\n"
                   << "Q";
    xstream = stream_builder.str();
  }
  // build dict
  std::ostringstream builder;
  builder << id.ToString() << "\n"
          << kDictStart << "\n"
          << kTagLength << " " << xstream.size() << "\n" // stream size
          << kTagType << " " << kTagXObject << "\n"
          << kTagSubType << " " << kTagForm << "\n"
          << kTagBBox << " " << bbox.ToString() << "\n"
          << kTagFormType << " " << form_type << "\n"
          << kTagResources << " " << kDictStart
          << "\n"
          // Resources dict fields
          << kTagXObject << " " << kDictStart
          << "\n"
          // Xobject nested dict
          << resources_img_tag_name << " " << resources_img_ref.ToStringRef()
          << "\n"
          << kDictEnd << "\n"  // end xobject dict
          << kDictEnd << "\n"  // end resources dict
          << kDictEnd << "\n"; // end this object dict
  // write a stream
  builder << kStreamStart << xstream << "\n" << kStreamEnd;
  builder << kObjEnd;
  return builder.str();
}

} // namespace pdfcsp::pdf