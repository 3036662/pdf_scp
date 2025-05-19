/* File: pdf_utils.cpp
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

#include "pdf_utils.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <filesystem>
#include <fstream>
#include <ios>
#include <iostream>
#include <iterator>
#include <limits>
#include <numeric>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "cross_ref_stream.hpp"
#include "logger_utils.hpp"
#include "pdf_defs.hpp"
#include "pdf_pod_structs.hpp"
#include "pdf_structs.hpp"

namespace pdfcsp::pdf {

// read file to vector
std::optional<std::vector<unsigned char>> FileToVector(
  const std::string &path) noexcept {
  namespace fs = std::filesystem;
  if (path.empty() || !fs::exists(path) || !fs::is_regular_file(path)) {
    return std::nullopt;
  }
  std::ifstream file(path, std::ios_base::binary);
  if (!file.is_open()) {
    return std::nullopt;
  }
  std::vector<unsigned char> res;
  res.reserve(std::filesystem::file_size(path));
  try {
    for (auto it = std::istreambuf_iterator<char>(file);
         it != std::istreambuf_iterator<char>(); ++it) {
      res.push_back(*it);
    }
  } catch ([[maybe_unused]] const std::exception & /*ex*/) {
    file.close();
    return std::nullopt;
  }
  file.close();
  return res;
}

std::optional<std::vector<unsigned char>> FileToVector(
  const std::string &path,
  const std::vector<std::pair<uint64_t, uint64_t>> &byteranges) noexcept {
  namespace fs = std::filesystem;
  if (path.empty() || !fs::exists(path)) {
    return std::nullopt;
  }
  std::ifstream file(path, std::ios_base::binary);
  if (!file.is_open()) {
    return std::nullopt;
  }
  std::vector<unsigned char> res;
  const uint64_t buff_size = std::accumulate(
    byteranges.cbegin(), byteranges.cend(), static_cast<uint64_t>(0),
    [](uint64_t res, const std::pair<uint64_t, uint64_t> &range) {
      return res + range.second;
    });
  try {
    res.reserve(buff_size);
    for (const auto &brange : byteranges) {
      if (brange.first >
          static_cast<uint64_t>(std::numeric_limits<int64_t>::max())) {
        throw std::runtime_error(
          "[FileToVector] byterange offset is > max_int64\n");
      }

      file.seekg(static_cast<int64_t>(brange.first));
      if (!file) {
        throw std::exception();
      }
      for (uint64_t i = 0; i < brange.second; ++i) {
        char symbol = 0;
        file.get(symbol);
        if (!file) {
          throw std::exception();
        }
        res.push_back(symbol);
      }
    }
  } catch ([[maybe_unused]] const std::exception &ex) {
    auto logger = logger::InitLog();
    if (logger) {
      logger->error("pdf_utils {}", ex.what());
    }
    file.close();
    return std::nullopt;
  }
  file.close();
  return res;
}

std::string DoubleToString10(double val) {
  std::ostringstream builder;
  builder << std::setprecision(10) << std::fixed << val;
  std::string res = builder.str();
  res.erase(res.find_last_not_of('0') + 1, std::string::npos);
  if (res.back() == '.') {
    res.pop_back();
  }
  if (res == "-0") {
    res = "0";
  }
  return res;
}

/**
 * @brief Return page rect
 * @param obj
 * @return BBox
 */
std::optional<BBox> VisiblePageSize(const PtrPdfObjShared &page_obj) noexcept {
  if (!page_obj || page_obj->isNull() || !page_obj->isDictionary() ||
      !page_obj->hasKey(kTagType) ||
      page_obj->getKey(kTagType).getName() != kTagPage) {
    return std::nullopt;
  }
  QPDFPageObjectHelper page_helper(*page_obj);
  auto media_box = page_helper.getMediaBox();
  if (!media_box.isArray()) {
    return std::nullopt;
  }
  auto crop_box = page_helper.getCropBox();
  auto crop_box_rect = crop_box.getArrayAsRectangle();
  BBox res;
  res.left_bottom.x = 0;
  res.left_bottom.y = 0;
  res.right_top.x = crop_box_rect.urx - crop_box_rect.llx;
  res.right_top.y = crop_box_rect.ury - crop_box_rect.lly;
  return res;
}

/**
 * @brief Return horizontal and vertical offset of cropbox
 * @param page_obj
 * @return XYReal
 */
std::optional<XYReal> CropBoxOffsetsXY(
  const PtrPdfObjShared &page_obj) noexcept {
  if (!page_obj || page_obj->isNull() || !page_obj->isDictionary() ||
      !page_obj->hasKey(kTagType) ||
      page_obj->getKey(kTagType).getName() != kTagPage) {
    return std::nullopt;
  }
  QPDFPageObjectHelper page_helper(*page_obj);
  auto crop_box = page_helper.getCropBox();
  auto crop_box_rect = crop_box.getArrayAsRectangle();
  return XYReal{crop_box_rect.llx, crop_box_rect.lly};
}

/**
 * @brief Converts pdf dictionary to unparsed map "/Key" -> "Value"
 * @param dict object
 * @return std::map<std::string, std::string>  unparsed dictionary
 */
std::map<std::string, std::string> DictToUnparsedMap(QPDFObjectHandle &dict) {
  if (!dict.isDictionary()) {
    return {};
  }
  auto src_map = dict.getDictAsMap();
  std::map<std::string, std::string> unparsed_map;
  std::for_each(
    src_map.begin(), src_map.end(),
    [&unparsed_map](std::pair<const std::string, QPDFObjectHandle> &pair_val) {
      unparsed_map[pair_val.first] = pair_val.second.unparse();
    });
  return unparsed_map;
}

/**
 * @brief Join an unparsed dictionary map to signle string
 * @param map
 * @return std::string
 */
std::string UnparsedMapToString(const std::map<std::string, std::string> &map) {
  {
    std::ostringstream builder;
    std::for_each(map.cbegin(), map.cend(),
                  [&builder](const std::pair<std::string, std::string> &pair) {
                    builder << pair.first << " " << pair.second << "\n";
                  });
    return builder.str();
  }
}

/**
 * @brief Build a cross-reference table
 * @details 7.5.4 Cross-Reference Table
 * @param entries
 * @return std::string ready for embedding
 */
std::string BuildXrefRawTable(const std::vector<XRefEntry> &entries) {
  auto entries_cp = entries;
  std::sort(entries_cp.begin(), entries_cp.end(),
            [](const XRefEntry &left, const XRefEntry &right) {
              return left.id.id < right.id.id;
            });
  int prev = 0;
  int counter = 0;
  int start_id = 0;
  std::ostringstream res;
  res << kXref;
  std::string tmp;
  for (size_t i = 0; i < entries_cp.size(); ++i) {
    // first iteration or current entry element id is sequentinal
    if (i == 0 || entries_cp[i].id.id == prev + 1) {
      if (counter == 0) {  // store first el number
        start_id = entries_cp[i].id.id;
      }
      tmp.append(entries_cp[i].ToString());
      prev = entries_cp[i].id.id;
      ++counter;
      continue;
    }
    // not sequentinal element was encountered
    res << start_id << " " << counter << "\n" << tmp;
    counter = 1;
    tmp.clear();
    tmp.append(entries_cp[i].ToString());
    start_id = entries_cp[i].id.id;
    prev = entries_cp[i].id.id;
  }
  res << start_id << " " << counter << "\n" << tmp;
  return res.str();
}

/**
 * @brief sorts entries, builds sections for cross-reference stream
 * @param entries
 * @return std::vector<std::pair<int, int>>
 * @details ISO 32000 [7.5.8 Cross-Reference Streams]
 * @details TEST_CASE("XrefStreamSections")
 */
std::vector<std::pair<int, int>> BuildXRefStreamSections(
  std::vector<XRefEntry> &entries) {
  std::vector<std::pair<int, int>> res;
  if (entries.empty()) {
    return res;
  }
  std::sort(entries.begin(), entries.end(),
            [](const XRefEntry &left, const XRefEntry &right) {
              return left.id.id < right.id.id;
            });
  int prev = 0;
  int counter = 0;
  int start_id = 0;
  for (size_t i = 0; i < entries.size(); ++i) {
    // first iteration or current entry element id is sequentinal
    const int curr_id = entries[i].id.id;
    if (curr_id == prev) {  // duplicates found
      throw std::runtime_error("[BuildXRefStreamSections] non unique entries");
    }
    if (i == 0 || curr_id == prev + 1) {
      if (counter == 0) {  // store first el number
        start_id = curr_id;
      }
      ++counter;
      prev = curr_id;
      continue;
    }
    // not sequentinal element was encountered
    res.emplace_back(start_id, counter);  // save section to result
    counter = 1;
    start_id = curr_id;
    prev = curr_id;
  }
  if (start_id != 0 && counter > 0) {
    res.emplace_back(start_id, counter);
  }
  return res;
}

/**
 * @brief Find last startxref in buffer
 * @param buf
 * @return string - offset in bytes
 */
std::optional<std::string> FindXrefOffset(const BytesVector &buf) {
  std::vector<unsigned char> tag = {'s', 't', 'a', 'r', 't',
                                    'x', 'r', 'e', 'f'};
  // const size_t end = buf.size() - tag.size() - 1;
  const size_t tag_size = tag.size();
  size_t last = std::string::npos;

  for (size_t i = buf.size() - tag_size; (i > 1 && last == std::string::npos);
       --i) {
    for (size_t j = 0; j < tag_size; ++j) {
      if (buf[i + j] != tag[j]) {
        break;
      }
      if (j == tag_size - 1) {
        last = i;
      }
    }
  }
  if (last == std::string::npos) {
    return std::nullopt;
  }
  last += tag_size;
  while (last < buf.size() && (buf[last] == '\r' || buf[last] == '\n')) {
    ++last;
  }
  size_t last_end = last;
  while (
    last_end < buf.size() &&
    (buf[last_end] != '\r' && buf[last_end] != '\n' && buf[last_end] != ' ')) {
    ++last_end;
  }
  if (last_end > last && last_end < buf.size()) {
    std::string res;
    std::copy(buf.data() + last, buf.data() + last_end,
              std::back_inserter(res));
    return res;
  }
  return std::nullopt;
}

/**
 * @brief Convert byte array to simple hex string
 * @param vec
 * @return std::string
 */
std::string ByteVectorToHexString(const BytesVector &vec) {
  std::ostringstream oss;
  for (const unsigned char byte : vec) {
    oss << std::hex << std::setw(2) << std::setfill('0')
        << static_cast<int>(byte);
  }
  return oss.str();
}

void PatchDataToFile(const std::string &path, size_t offset,
                     const std::string &data) {
  const std::string func_name = "[PatchDataToFile] ";
  if (path.empty() || data.empty() || !std::filesystem::exists(path)) {
    throw std::invalid_argument(func_name + "invalid args");
  }
  std::fstream file(path, std::ios::in | std::ios::out | std::ios_base::binary);
  if (!file.is_open()) {
    throw std::runtime_error(func_name + "error opening file " + path);
  }
  if (offset >
      std::numeric_limits<std::basic_ofstream<char>::off_type>::max()) {
    throw std::runtime_error(func_name + "offset is to big");
  }
  file.seekp(static_cast<std::basic_ofstream<char>::off_type>(offset));
  if (file.fail()) {
    file.close();
    throw std::runtime_error(func_name + "error seeking to offset");
  }
  for (const auto &symbol : data) {
    file << symbol;
  }
  if (file.fail()) {
    file.close();
    throw std::runtime_error(func_name + "error write to file");
  }
  file.close();
}

/**
 * @brief Create a Page updated with the Annots objects
 * @param p_page_original
 * @param annot_ids
 * @return std::string unparsed page
 * @details inserts the new ids to the /Annots array of page
 */
std::string CreatePageUpdateWithAnnots(const PtrPdfObjShared &p_page_original,
                                       std::vector<ObjRawId> annot_ids) {
  if (p_page_original->hasKey(kTagAnnots) &&
      p_page_original->getKey(kTagAnnots).isArray()) {
    // copy ids to annot_ids
    const auto vec_annots =
      p_page_original->getKey(kTagAnnots).getArrayAsVector();
    std::vector<ObjRawId> tmp;
    std::for_each(vec_annots.cbegin(), vec_annots.cend(),
                  [&tmp](const QPDFObjectHandle &val) {
                    tmp.emplace_back(ObjRawId::CopyIdFromExisting(val));
                  });
    std::copy(annot_ids.cbegin(), annot_ids.cend(), std::back_inserter(tmp));
    std::swap(annot_ids, tmp);
  }
  auto unparsed_map = DictToUnparsedMap(*p_page_original);
  std::string annots_unparsed_val;
  {
    std::ostringstream builder;
    builder << "[ ";
    std::for_each(
      annot_ids.cbegin(), annot_ids.cend(),
      [&builder](const ObjRawId &ann) { builder << ann.ToStringRef() << " "; });
    builder << "]";
    annots_unparsed_val = builder.str();
  }
  unparsed_map.insert_or_assign(kTagAnnots, annots_unparsed_val);

  std::ostringstream builder;
  builder << ObjRawId::CopyIdFromExisting(*p_page_original).ToString() << " \n"
          << kDictStart << "\n";
  builder << UnparsedMapToString(unparsed_map);
  builder << kDictEnd << "\n" << kObjEnd;
  return builder.str();
}

void PushOneAnnotationToXRefAndBuffer(const SingleAnnot &ann,
                                      std::vector<XRefEntry> &xref_entries,
                                      BytesVector &file_buff) {
  // reserve buffer size
  size_t size_to_expand =
    1000 + (ann.img.has_value() ? ann.img->data.size() : 0);
  if (ann.img_mask) {
    size_to_expand += ann.img_mask->data.size();
  }
  file_buff.reserve(file_buff.size() + size_to_expand);
  // Annotation
  xref_entries.emplace_back(XRefEntry{ann.annot.id, file_buff.size(), 0});
  {
    const auto annot_raw = ann.annot.ToString();
    std::copy(annot_raw.cbegin(), annot_raw.cend(),
              std::back_inserter(file_buff));
  }
  // FormXObject
  if (ann.form) {
    xref_entries.emplace_back(XRefEntry{ann.form->id, file_buff.size(), 0});
    auto raw_form = ann.form->ToString();
    std::copy(raw_form.cbegin(), raw_form.cend(),
              std::back_inserter(file_buff));
  }
  // ImageObj
  if (ann.img) {
    xref_entries.emplace_back(XRefEntry{ann.img->id, file_buff.size(), 0});
    auto raw_img_obj = ann.img->ToRawData();
    std::copy(raw_img_obj.cbegin(), raw_img_obj.cend(),
              std::back_inserter(file_buff));
  }
  // image mask  ImageObj
  if (ann.img_mask) {
    xref_entries.emplace_back(XRefEntry{ann.img_mask->id, file_buff.size(), 0});
    auto raw_img_obj = ann.img_mask->ToRawData();
    std::copy(raw_img_obj.cbegin(), raw_img_obj.cend(),
              std::back_inserter(file_buff));
  }
}

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
  std::vector<XRefEntry> &ref_entries) {
  CrossRefStream crs{};
  // first create xref object id
  crs.id = ++last_assigned_id;
  crs.size_val = crs.id.id + 1;  // highest object number + 1
  // push the trailer itself
  ref_entries.push_back(XRefEntry{crs.id, result_file_buf.size(), 0});
  crs.entries = ref_entries;
  // sort entries and build sections
  crs.index_vec = BuildXRefStreamSections(crs.entries);
  // offset to previous xref
  crs.prev_val = prev_x_ref_offset;
  // copy fields from the previous trailer
  // root
  if (old_trailer_fields.count(kTagRoot) > 0) {
    crs.root_id = old_trailer_fields.at(kTagRoot);
  }
  // info
  if (old_trailer_fields.count(kTagInfo) > 0) {
    crs.info_id = old_trailer_fields.at(kTagInfo);
  }
  // ID
  if (old_trailer_fields.count(kTagID) > 0) {
    crs.id_val = old_trailer_fields.at(kTagID);
  }
  if (old_trailer_fields.count(kTagEncrypt) > 0) {
    crs.enctypt = old_trailer_fields.at(kTagEncrypt);
  }
  // set stream length
  if (crs.entries.size() > std::numeric_limits<int>::max()) {
    throw std::runtime_error("[Pdf::CreateCrossRefStream] can not cast to int");
  }
  crs.length = (crs.w_field_0_size + crs.w_field_1_size + crs.w_field_2_size) *
               static_cast<int>(crs.entries.size());

  // complete the file
  const size_t xref_table_offset = result_file_buf.size();
  {
    auto buf = crs.ToRawData();
    std::copy(buf.cbegin(), buf.cend(), std::back_inserter(result_file_buf));
  }

  // final info
  {
    std::string final_info = kStartXref;
    final_info += "\n";
    final_info += std::to_string(xref_table_offset);
    final_info += "\n";
    final_info += kEof;
    final_info += "\n";
    std::copy(final_info.cbegin(), final_info.cend(),
              std::back_inserter(result_file_buf));
  }
}

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
                      std::vector<XRefEntry> &ref_entries) {
  old_trailer_fields.insert_or_assign(kTagPrev, prev_x_ref_offset);
  old_trailer_fields.insert_or_assign(
    kTagSize, std::to_string(++last_assigned_id.id + 1));
  // fields to copy from old trailer
  {
    const std::set<std::string> trailer_possible_fields{
      kTagSize, kTagPrev, kTagRoot, kTagEncrypt, kTagInfo, kTagID};
    std::map<std::string, std::string> tmp_trailer;
    std::copy_if(old_trailer_fields.cbegin(), old_trailer_fields.cend(),
                 std::inserter(tmp_trailer, tmp_trailer.end()),
                 [&trailer_possible_fields](
                   const std::pair<std::string, std::string> &pair_val) {
                   return trailer_possible_fields.count(pair_val.first) > 0;
                 });
    std::swap(old_trailer_fields, tmp_trailer);
  }
  std::string raw_trailer = "trailer\n<<";
  raw_trailer += UnparsedMapToString(old_trailer_fields);
  raw_trailer += ">>\n";
  // complete the file
  // push xref_table to file
  const size_t xref_table_offset = result_file_buf.size();
  const std::string raw_xref_table = BuildXrefRawTable(ref_entries);
  std::copy(raw_xref_table.cbegin(), raw_xref_table.cend(),
            std::back_inserter(result_file_buf));
  std::copy(raw_trailer.cbegin(), raw_trailer.cend(),
            std::back_inserter(result_file_buf));
  // final info
  {
    std::string final_info = kStartXref;
    final_info += "\n";
    final_info += std::to_string(xref_table_offset);
    final_info += "\n";
    final_info += kEof;
    final_info += "\n";
    std::copy(final_info.cbegin(), final_info.cend(),
              std::back_inserter(result_file_buf));
  }
}

std::string WriteUpdatedFile(const std::string &temp_dir_path,
                             const std::string &file_to_sign_path,
                             const BytesVector &data) {
  std::string output_file = temp_dir_path;
  output_file += "/altcsp_";
  output_file += std::filesystem::path(file_to_sign_path).filename().string();
  output_file += ".sig_prepared";
  if (std::filesystem::exists(output_file)) {
    if (!std::filesystem::remove(output_file)) {
      throw std::runtime_error("[PDF::WriteUpdatedFile] remove file failed");
    }
  }
  {
    std::ofstream ofile(output_file, std::ios_base::binary);
    ofile.close();
    std::filesystem::permissions(
      output_file,
      std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
      std::filesystem::perm_options::replace);
  }

  std::ofstream ofile(output_file, std::ios_base::binary);
  if (!ofile.is_open()) {
    throw std::runtime_error("Can't create a file");
  }
  for (const auto symbol : data) {
    ofile << symbol;
  }
  ofile.close();
  return output_file;
}

// NOLINTNEXTLINE(readability-function-cognitive-complexity)
Pdf::SharedImgParams CreateImgParams(const CSignParams &params) {
  const std::string func_name = "[Pdf::CreateImgParams] ";
  const bool harcoded_for_national_standart =
    params.stamp_type != nullptr && std::string(params.stamp_type) == "ГОСТ";
  // wrapper for parameters
  auto res = std::make_shared<ImageParamWrapper>();
  namespace ig = signimage::c_wrapper;
  // C structure with parameter (stored within the ImageParamWrapper)
  ig::Params &img_params = res->img_params;
  constexpr auto white = ig::RGBAColor{0xFF, 0xFF, 0xFF};
  constexpr auto blue = ig::RGBAColor{50, 62, 168};
  img_params.bg_color = white;
  img_params.text_color =
    harcoded_for_national_standart
      ? blue
      : ig::RGBAColor{params.text_color.red, params.text_color.green,
                      params.text_color.blue};
  img_params.border_color =
    harcoded_for_national_standart
      ? blue
      : ig::RGBAColor{params.border_color.red, params.border_color.green,
                      params.border_color.blue};
  img_params.border_radius =
    harcoded_for_national_standart
      ? ig::BorderRadius{50, 50}
      : ig::BorderRadius{params.border_radius, params.border_radius};

  // stamp opacity
  if (!harcoded_for_national_standart) {
    img_params.bg_transparent = params.bg_transparent;
    if (params.bg_transparent) {
      img_params.bg_transparent = true;
      img_params.bg_color.alpha = params.bg_opacity;
    }
  }
  if (params.stamp_height != 0 && params.stamp_width != 0) {
    img_params.signature_size = {
      kStampImgDefaultWidth,
      static_cast<uint64_t>(kStampImgDefaultWidth *
                            (params.stamp_height / params.stamp_width))};
  } else {
    img_params.signature_size = {kStampImgDefaultWidth, kStampImgDefaultHeight};
  }
  img_params.title_font_size = kStampTitleFontSize;
  img_params.font_size = kStampFontSize;
  res->font_family = "Garuda";
  img_params.font_family = res->font_family.c_str();
  img_params.border_width =
    harcoded_for_national_standart ? kStampBorderWidth : params.border_width;
  // img_params.debug_enabled = true;
  res->title = params.stamp_title == nullptr ? kStampTitle : params.stamp_title;
  img_params.title = res->title.c_str();
  res->cert_prefix = params.cert_serial_prefix == nullptr
                       ? kStampCertText
                       : params.cert_serial_prefix;
  res->cert_text = res->cert_prefix + params.cert_serial;
  img_params.cert_serial = res->cert_text.c_str();
  res->subj_prefix = params.cert_serial_prefix == nullptr
                       ? kStampSubjText
                       : params.cert_subject_prefix;
  res->subj_text = res->subj_prefix + params.cert_subject;

  img_params.subject = res->subj_text.c_str();
  res->cert_time_validity = params.cert_time_validity;
  img_params.time_validity = res->cert_time_validity.c_str();
  // logo
  if (params.logo_path != nullptr) {
    std::filesystem::path logo_path(params.logo_path);  // path from profile
    std::string path_in_config = params.config_path;
    path_in_config += '/';
    path_in_config += logo_path.filename();
    if (path_in_config != logo_path.string()) {
      logo_path = std::filesystem::path(path_in_config);
    }
    if (std::filesystem::exists(logo_path.string())) {
      res->img_raw = FileToVector(logo_path.string());
    } else {
      res->img_raw = FileToVector(params.logo_path);
    }
    std::optional<BytesVector> &img_raw = res->img_raw;
    if (!img_raw.has_value() || img_raw->empty()) {
      throw std::runtime_error(func_name + "Can not read logo file " +
                               logo_path.string());
    }
    img_params.ptr_logo_data = img_raw->data();
    img_params.ptr_logo_size = img_raw->size();

  } else {
    img_params.ptr_logo_data = nullptr;
    img_params.ptr_logo_size = 0;
  }
  const auto logo_x_goal = img_params.signature_size.height / 2;
  img_params.logo_size_goal = {logo_x_goal, logo_x_goal};
  img_params.logo_preserve_ratio = true;
  img_params.logo_position = {20, 20};
  // change the logo position if border_radius is big
  const uint64_t logo_pos_x =
    static_cast<uint64_t>(std::ceil(0.42 * params.border_radius)) +
    params.border_width;
  if (logo_pos_x > img_params.logo_position.x) {
    img_params.logo_position = {logo_pos_x, logo_pos_x};
  }
  img_params.title_position = {logo_x_goal + logo_pos_x + 30, logo_x_goal / 3};
  img_params.cert_serial_position = {30, logo_x_goal + 30};
  img_params.subject_position = {30, img_params.cert_serial_position.y + 40};
  img_params.time_validity_position = {
    img_params.logo_position.x > 30 ? img_params.logo_position.x : 30,
    img_params.subject_position.y + 40};
  img_params.title_alignment = ig::TextAlignment::CENTER;
  img_params.content_alignment = ig::TextAlignment::CENTER;
  return res;
}

}  // namespace pdfcsp::pdf
