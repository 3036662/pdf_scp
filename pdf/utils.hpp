#pragma once

#include "pdf_defs.hpp"
#include "pdf_structs.hpp"
#include <cstdint>
#include <optional>
#include <qpdf/QPDFObjectHandle.hh>
#include <qpdf/QPDFPageObjectHelper.hh>
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
 * @brief Return page rect
 * @param obj
 * @return BBox
 */
std::optional<BBox> PageRect(const PtrPdfObjShared &page_obj) noexcept;

std::map<std::string, std::string> DictToUnparsedMap(QPDFObjectHandle &dict);

std::string UnparsedMapToString(const std::map<std::string, std::string> &map);

std::string BuildXrefRawTable(const std::vector<XRefEntry> &entries);

// find last xref offset
std::optional<std::string> FindXrefOffset(const BytesVector &buf);

} // namespace pdfcsp::pdf