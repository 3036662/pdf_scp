/* File: sig_field.cpp  
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


#include "sig_field.hpp"
#include "pdf_structs.hpp"
#include <sstream>

namespace pdfcsp::pdf {

std::string SigField::ToString() const {
  std::ostringstream builder;
  builder << id.ToString() << "\n"
          << kDictStart << "\n" // dict start
          << kTagFT << " " << ft << "\n"
          << kTagF << " " << flags << "\n";
  if (name.has_value()) {
    builder << kTagT << " (" << name.value() << ")\n";
  }
  builder << kTagType << " " << type << "\n"
          << kTagSubType << " " << subtype << "\n"
          << kTagP << " " << parent.ToStringRef() << "\n"
          << kTagRect << " " << rect.ToString() << "\n";
  // /AP dict start
  builder << kTagAP << " " << kDictStart << "\n"
          << kTagN << " " << appearance_ref.ToStringRef() << "\n"
          << kDictEnd << "\n";
  // /AP dict end
  // /Sig
  if (value.has_value()) {
    builder << kTagV << " " << value->ToStringRef() << "\n";
  }
  builder << kDictEnd << "\n" // dict end
          << kObjEnd;
  return builder.str();
}

} // namespace pdfcsp::pdf