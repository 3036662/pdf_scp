/* File: acro_form.hpp  
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

// iso table 218
struct AcroForm {
  ObjRawId id;
  std::vector<ObjRawId> fields; // SigField
  int sig_flags = 0b11;         // iso table 219

  std::map<std::string, std::string> other_fields_copied;

  /**
   * @brief Copies an Acroform and it's ID
   * @param other Acroform object
   * @return AcroForm
   * @throws runtime_error if invalid parameter
   */
  static AcroForm ShallowCopy(const PtrPdfObjShared &other);

  [[nodiscard]] std::string ToString() const;
};

} // namespace pdfcsp::pdf
