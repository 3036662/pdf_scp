/* File: pdf_structs.cpp  
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


#include "pdf_structs.hpp"
#include "pdf_utils.hpp"
#include <iomanip>
#include <ios>
#include <sstream>
#include <string>
namespace pdfcsp::pdf {

std::string XYReal::ToString() const {
  std::ostringstream builder;
  builder << DoubleToString10(x) << " " << DoubleToString10(y);
  return builder.str();
}

std::string BBox::ToString() const {
  std::ostringstream builder;
  builder << "[ " << left_bottom.ToString() << " " << right_top.ToString()
          << " ]";
  return builder.str();
}

std::string Matrix::toString() const {
  std::ostringstream builder;
  builder << DoubleToString10(a) << " " << DoubleToString10(b) << " "
          << DoubleToString10(c) << " " << DoubleToString10(d) << " "
          << DoubleToString10(e) << " " << DoubleToString10(f);
  return builder.str();
}

ObjRawId ObjRawId::CopyIdFromExisting(const QPDFObjectHandle &other) noexcept {
  return {other.getObjectID(), other.getGeneration()};
}

std::string XRefEntry::ToString() const {
  std::string res;
  const std::string offs = std::to_string(offset);
  if (offs.size() < 10) {
    res.append(std::string(10 - offs.size(), '0'));
  }
  res.append(offs);
  res += ' ';
  const std::string gens = std::to_string(gen);
  if (gens.size() < 10) {
    res.append(std::string(5 - gens.size(), '0'));
  }
  res.append(gens);
  res += " n \n";
  return res; // result size must be 20 bytes
}

} // namespace pdfcsp::pdf