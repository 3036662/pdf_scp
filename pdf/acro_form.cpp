/* File: acro_form.cpp
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

#include "acro_form.hpp"

#include <stdexcept>
#include <string>

#include "pdf_defs.hpp"
#include "pdf_structs.hpp"
#include "pdf_utils.hpp"

namespace pdfcsp::pdf {

std::string AcroForm::ToString() const {
  std::ostringstream builder;
  builder << id.ToString() << "\n"
          << kDictStart << "\n"
          << kTagFields << " " << "[ ";
  for (const auto &field : fields) {
    builder << field.ToStringRef() << " ";
  }
  builder << "]\n";
  builder << kTagSigFlags << " " << std::to_string(sig_flags) << "\n";
  for (const auto &field_pair : other_fields_copied) {
    builder << field_pair.first << " " << field_pair.second << "\n";
  }
  builder << kDictEnd << "\n" << kObjEnd;
  return builder.str();
}

AcroForm AcroForm::ShallowCopy(const PtrPdfObjShared &other) {
  if (!other || !other->isDictionary()) {
    throw std::runtime_error("[AcroForm::ShallowCopy] not a dictionary");
  }
  AcroForm res;
  // res.id
  res.id.id = other->getObjectID();
  res.id.gen = other->getGeneration();
  // fields vector
  if (other->hasKey(kTagFields) && other->getKey(kTagFields).isArray()) {
    for (auto &lnk : other->getKey(kTagFields).getArrayAsVector()) {
      if (lnk.isDictionary()) {
        res.fields.push_back({lnk.getObjectID(), lnk.getGeneration()});
      }
    }
  }
  // copy all the rest fields except SigFlags,Fields
  auto unparsed_map = DictToUnparsedMap(*other);
  for (const auto &field_pair : unparsed_map) {
    if (field_pair.first != kTagFields && field_pair.first != kTagSigFlags) {
      res.other_fields_copied.insert(field_pair);
    }
  }

  return res;
}

}  // namespace pdfcsp::pdf