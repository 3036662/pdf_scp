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

}  // namespace pdfcsp::pdf