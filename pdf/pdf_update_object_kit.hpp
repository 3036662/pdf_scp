/* File: pdf_update_object_kit.hpp
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

#include <optional>
#include <vector>

#include "acro_form.hpp"
#include "form_x_object.hpp"
#include "image_obj.hpp"
#include "pdf_pod_structs.hpp"
#include "pdf_structs.hpp"
#include "sig_field.hpp"
#include "sig_val.hpp"

namespace pdfcsp::pdf {

struct PdfUpdateObjectKit {
  ObjRawId original_last_id;  /// original doc last object id
  ObjRawId last_assigned_id;  /// last used id
  std::string users_tmp_dir;
  PtrPdfObjShared p_page_original;  /// pointer to original page object
  PtrPdfObjShared p_root_original;
  std::optional<BBox> origial_page_rect;

  ImageObj image_obj;                    // stamp image
  std::optional<ImageObj> img_mask_obj;  // mask
  FormXObject form_x_object;
  SigVal sig_val;
  SigField sig_field;
  AcroForm acroform;
  std::string updated_page;            // page raw data
  std::string root_updated;            // root object raw
  std::vector<XRefEntry> ref_entries;  // XRef
  std::vector<unsigned char> updated_file_data;
  PrepareEmptySigResult stage1_res;
};

}  // namespace pdfcsp::pdf