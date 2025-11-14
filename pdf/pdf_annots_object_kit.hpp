/* File: pdf_annots_object_kit.hpp
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

#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "annotation.hpp"
#include "form_x_object.hpp"
#include "image_obj.hpp"
#include "pdf_defs.hpp"
#include "pdf_structs.hpp"

namespace pdfcsp::pdf {

struct SingleAnnot {
  Annotation annot;
  std::optional<FormXObject> form;
  std::optional<ImageObj> img;
  std::optional<ImageObj> img_mask;
};

struct PdfAnnotsObjectKit {
  ObjRawId original_last_id;  /// original doc last object id
  ObjRawId last_assigned_id;  /// last used id
  std::string users_tmp_dir;
  std::vector<SingleAnnot> annots;
  std::unordered_map<ObjRawId, std::vector<ObjRawId>> pages_for_update;
  std::vector<std::pair<ObjRawId, std::string>> pages_updated;
};

}  // namespace pdfcsp::pdf