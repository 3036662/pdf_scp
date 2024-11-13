#pragma once

#include "pdf_defs.hpp"
#include "pdf_structs.hpp"
#include <cstdint>
#include <limits>
#include <optional>
#include <qpdf/QPDFObjectHandle.hh>
#include <qpdf/QPDFPageObjectHelper.hh>
#include <stdexcept>
#include <string>
#include <vector>

namespace pdfcsp::pdf {
/**
 * @brief Load file to vector
 *
 * @return optional std::vector<unsigned char> - empty if fail
 */
std::optional<std::vector<unsigned char>>
FileToVector(const std::string &path) noexcept;

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
std::optional<XYReal>
CropBoxOffsetsXY(const PtrPdfObjShared &page_obj) noexcept;

std::map<std::string, std::string> DictToUnparsedMap(QPDFObjectHandle &dict);

std::string UnparsedMapToString(const std::map<std::string, std::string> &map);

std::string BuildXrefRawTable(const std::vector<XRefEntry> &entries);

// find last xref offset
std::optional<std::string> FindXrefOffset(const BytesVector &buf);

/**
 * @brief Convert byte array to simple hex string
 * @param vec
 * @return std::string
 */
std::string ByteVectorToHexString(const BytesVector &vec);

void PatchDataToFile(const std::string &path, size_t offset,
                     const std::string &data);

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

} // namespace pdfcsp::pdf