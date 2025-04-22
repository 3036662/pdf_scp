/* File: pdf_pod_structs.hpp
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

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "image_obj.hpp"
namespace pdfcsp::pdf {

/// @brief parameters for file signing
struct CSignParams {
  int page_index = 0;
  double page_width = 0;
  double page_height = 0;
  double stamp_x = 0;
  double stamp_y = 0;
  double stamp_width = 0;
  double stamp_height = 0;
  const char *logo_path = nullptr;
  const char *config_path = nullptr;
  const char *cert_serial = nullptr;
  const char *cert_serial_prefix = nullptr;
  const char *cert_subject = nullptr;
  const char *cert_subject_prefix = nullptr;
  const char *cert_time_validity = nullptr;
  const char *stamp_type = nullptr;
  const char *cades_type = nullptr;  /// CADES_BES or CADES_T or CADES_XLT1
  const char *file_to_sign_path = nullptr;
  const char *temp_dir_path = nullptr;
  const char *tsp_link = nullptr;
  const char *stamp_title = nullptr;
  // for batch file processing - cached ImageObj may be passed
  bool perform_cache_image = false;
  bool image_generator_with_masks = false;
  ImageObj *cached_img = nullptr;
  ImageObj *cached_img_mask = nullptr;
};

struct CSignPrepareResult {
  struct SignResStorage {
    std::string file_path;
    std::string err_string;
    std::shared_ptr<ImageObj> cached_img;
    std::shared_ptr<ImageObj> cached_img_mask;
  };

  bool status = false;
  const char *tmp_file_path = nullptr;
  const char *err_string = nullptr;
  SignResStorage *storage = nullptr;
};

struct StampResizeFactor {
  double x = 1.0;
  double y = 1.0;
};

struct PrepareEmptySigResult {
  std::string file_name;  // temporary file with space reserved for a signature
  size_t sig_offset = 0;  // offset where the signature value should be pasted
  size_t sig_max_size = 0;  // maximal size to paste
  std::vector<std::pair<uint64_t, uint64_t>> byteranges;
  // for batch file processing - cached ImageObj may be returned with result
  std::shared_ptr<ImageObj> cached_img;
  std::shared_ptr<ImageObj> cached_mask;
};

/**
 * @brief Parameters for one annotation embedding
 * @details Width and height may be any measure units, but all sizes must be in
 * the same units.
 */
struct CAnnotParams {
  int page_index = 0;
  double page_width = 0;  // any units
  double page_height = 0;
  double stamp_x = 0;
  double stamp_y = 0;
  double stamp_width = 0;
  double stamp_height = 0;
  unsigned char *img = nullptr;
  size_t img_size = 0;
  unsigned char *img_mask = nullptr;
  size_t img_mask_size = 0;
  uint32_t res_x = 0;
  uint32_t res_y = 0;
  const char *link = nullptr;
};

struct EmbedAnnotResultStorage {
  std::string tmp_file_path;
  std::string err_string;
};

struct CEmbedAnnotResult {
  bool status = false;
  const char *tmp_file_path = nullptr;
  const char *err_string = nullptr;
  EmbedAnnotResultStorage *storage = nullptr;
};

}  // namespace pdfcsp::pdf