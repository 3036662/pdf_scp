/* File: pdf_utils.hpp
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

#include <cstdint>
#include <limits>
#include <optional>
#include <qpdf/QPDFObjectHandle.hh>
#include <qpdf/QPDFPageObjectHelper.hh>
#include <stdexcept>
#include <string>
#include <vector>

#include "annotation.hpp"
#include "csppdf.hpp"
#include "pdf_defs.hpp"
#include "pdf_structs.hpp"

namespace pdfcsp::pdf {
/**
 * @brief Load file to vector
 *
 * @return optional std::vector<unsigned char> - empty if fail
 */
std::optional<std::vector<unsigned char>> FileToVector(
  const std::string &path) noexcept;

/**
 * @brief Extract data specified by byterange
 *
 * @param path path to file
 * @param byterange vector of pairs {start,length}
 * @return std::optional<std::vector<unsigned char>>
 */
std::optional<std::vector<unsigned char>> FileToVector(
  const std::string &path,
  const std::vector<std::pair<uint64_t, uint64_t>> &byteranges) noexcept;

/**
 * @brief Return double as string with max 10 digits after point
 * @param val
 * @return std::string
 */
std::string DoubleToString10(double val);

/**
 * @brief Return the size of visible page rectangle [0,0,width,height]
 * @param page obj
 * @return BBox [0,0,width,height]
 */
std::optional<BBox> VisiblePageSize(const PtrPdfObjShared &page_obj) noexcept;

/**
 * @brief Return horizontal and vertical offset of cropbox
 * @param page_obj
 * @return XYReal
 */
std::optional<XYReal> CropBoxOffsetsXY(
  const PtrPdfObjShared &page_obj) noexcept;

/**
 * @brief Converts pdf dictionary to unparsed map "/Key" -> "Value"
 * @param dict object
 * @return std::map<std::string, std::string>  unparsed dictionary
 */
std::map<std::string, std::string> DictToUnparsedMap(QPDFObjectHandle &dict);

/**
 * @brief Join an unparsed dictionary map to signle string
 * @param map
 * @return std::string
 */
std::string UnparsedMapToString(const std::map<std::string, std::string> &map);

/**
 * @brief Build a cross-reference table
 * @details 7.5.4 Cross-Reference Table
 * @param entries
 * @return std::string ready for embedding
 */
std::string BuildXrefRawTable(const std::vector<XRefEntry> &entries);

/**
 * @brief sorts entries, builds sections for cross-reference stream
 *
 * @param entries XRefEntry for cross reference
 * @return std::vector<std::pair<int, int>>
 * @details ISO 32000 [7.5.8 Cross-Reference Streams]
 * @details TEST_CASE("XrefStreamSections")
 */
std::vector<std::pair<int, int>> BuildXRefStreamSections(
  std::vector<XRefEntry> &entries);

/**
 * @brief Find last startxref in buffer
 * @param buf
 * @return string - offset in byres
 */
std::optional<std::string> FindXrefOffset(const BytesVector &buf);

/**
 * @brief Convert byte array to simple hex string
 * @param vec
 * @return std::string
 */
std::string ByteVectorToHexString(const BytesVector &vec);

void PatchDataToFile(const std::string &path, size_t offset,
                     const std::string &data);

/**
 * @brief Takes result size, goal size, and calculates a ratio.
 *
 * @tparam TRES result_t
 * @tparam TGOAL goal_t
 * @param goal_size
 * @param res_size
 * @return double res/goal
 * @throws runtime_error
 * @details Template because we are not sure in stamp library data types.
 */
template <typename TRES, typename TGOAL>
double CalcResizeFactor(TGOAL goal_size, TRES res_size) {
  if (goal_size > std::numeric_limits<double>::max()) {
    throw std::runtime_error(
      "[CalcResizeFactor] cant convert goal size to double");
  }
  if (res_size > std::numeric_limits<double>::max()) {
    throw std::runtime_error(
      "[CalcResizeFactor] cant convert result size to double");
  }
  if (goal_size == 0) {
    throw std::runtime_error("[CalcResizeFactor] goal size is 0]");
  }
  return static_cast<double>(res_size) / static_cast<double>(goal_size);
}

/**
 * @brief Create a Page updated with the Annots objects
 * @param p_page_original
 * @param annot_ids
 * @return std::string unparsed page
 * @details inserts the new ids to the /Annots array of page
 */
std::string CreatePageUpdateWithAnnots(const PtrPdfObjShared &p_page_original,
                                       std::vector<ObjRawId> annot_ids);

/**
 * @brief Take one SingleAnnot and append it's data to xref_entries and
 * file_buff
 * @param ann SingleAnnot
 * @param [in,out] xref_entries
 * @param [in,out] file_buff
 * @details appends Annotation,XForm, Image, Image mask
 */
void PushOneAnnotationToXRefAndBuffer(const SingleAnnot &ann,
                                      std::vector<XRefEntry> &xref_entries,
                                      BytesVector &file_buff);

/* This function are called from CreateXRef
 * We need to create simple table if previous table is simple,
 * create a cross-reference stream if previous table is cross-ref. stream
 */

/**
 * @brief Create a Cross Ref Stream object
 * @details ISO3200 [7.5.8] Cross-Reference Streams
 * @param old_trailer_fields
 * @param prev_x_ref_offset
 * @param [in,out] result_file_buf
 * @param [in,out] last_assigned_id  reference to the last_assigned_id
 * @param [in,out] ref_entries referenct to the XRefEntry vector
 */
void CreateCrossRefStream(
  std::map<std::string, std::string> &old_trailer_fields,
  const std::string &prev_x_ref_offset,
  std::vector<unsigned char> &result_file_buf, ObjRawId &last_assigned_id,
  std::vector<XRefEntry> &ref_entries);

/**
 * @brief Create a simple trailer and xref table
 *
 * @param[in,out] old_trailer_fields - previous trailer fields string->string
 * @param[in] prev_x_ref_offset - offset in bytes of previous x_ref (string)
 * @param[in,out] result_file_buf  - resulting signed file buffer
 * @param [in,out] last_assigned_id  reference to the last_assigned_id
 * @param [in,out] ref_entries referenct to the XRefEntry vector
 */
void CreateSimpleXref(std::map<std::string, std::string> &old_trailer_fields,
                      const std::string &prev_x_ref_offset,
                      std::vector<unsigned char> &result_file_buf,
                      ObjRawId &last_assigned_id,
                      std::vector<XRefEntry> &ref_entries);

/**
 * @brief Create a temporary file in the temporary dir,writes data
 * @param temp_dir_path temporary directory path
 * @param file_to_sign_path original file path
 * @param data data to write
 *
 */
[[nodiscard]] std::string WriteUpdatedFile(const std::string &temp_dir_path,
                                           const std::string &file_to_sign_path,
                                           const BytesVector &data);

/**
 * @brief Create a ImageParamWrapper object
 * @param params @see CSignParams
 * @return parameters ready to call the Pdf::image_generator
 */
Pdf::SharedImgParams CreateImgParams(const CSignParams &params);

}  // namespace pdfcsp::pdf