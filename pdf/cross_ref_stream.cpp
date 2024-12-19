/* File: cross_ref_stream.cpp  
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


#include "cross_ref_stream.hpp"
#include "pdf_defs.hpp"
#include <algorithm>
#include <cstdint>
#include <iterator>
#include <limits>
#include <sstream>
#include <stdexcept>

namespace pdfcsp::pdf {

/**
 * @brief Return data ready for copying to file
 * @return BytesVector
 * @throws runtime_error on duplicate values
 */
BytesVector CrossRefStream::ToRawData() const {
  BytesVector res;
  // --------------------
  // data before stream - dictionary
  {
    std::ostringstream builder;
    builder << id.ToString() << "\n"
            << kDictStart << "\n"
            << kTagType << " " << type << "\n"
            << kTagSize << " " << size_val << "\n";
    // index
    if (!index_vec.empty()) {
      builder << kTagIndex << " [ ";
      for (const auto ind_pair : index_vec) {
        builder << ind_pair.first << " " << ind_pair.second << " ";
      }
      builder << "]\n";
    }
    // W
    builder << kTagW << " [ " << w_field_0_size << " " << w_field_1_size << " "
            << w_field_2_size << " ]\n";
    // prev
    builder << kTagPrev << " " << prev_val << "\n";
    // root
    builder << kTagRoot << " " << root_id << "\n";
    // length
    builder << kTagLength << " " << length << "\n";
    // info (optional)
    if (info_id.has_value()) {
      builder << kTagInfo << " " << info_id.value() << "\n";
    }
    // ID (optional)
    if (id_val.has_value()) {
      builder << kTagID << " " << id_val.value() << "\n";
    }
    // Encrypt (optional)
    if (enctypt.has_value()) {
      builder << kTagEncrypt << " " << enctypt.value() << "\n";
    }
    builder << kDictEnd << "\n";
    // start stream
    builder << kStreamStart;
    const std::string tmp = builder.str();
    std::copy(tmp.cbegin(), tmp.cend(), std::back_inserter(res));
  }
  // --------------------
  // stream data
  {
    BytesVector stream_data;
    stream_data.reserve(length);
    const uint32_t tmp_32bit = 1;
    const bool big_endian =
        (reinterpret_cast<const unsigned char *>(&tmp_32bit))[3] == 1; // NOLINT
    for (const auto &entry : entries) {
      stream_data.push_back(0x01);
      if (entry.offset > std::numeric_limits<uint32_t>::max()) {
        throw std::runtime_error("[CrossRefStream::ToRawData()] can not cast "
                                 "entry offset to 32bit integer");
      }
      const auto tmp = static_cast<uint32_t>(entry.offset);
      const auto *offset_bytes =
          reinterpret_cast<const unsigned char *>(&tmp); // NOLINT
      if (big_endian) {
        std::copy(offset_bytes, offset_bytes + sizeof(uint32_t),
                  std::back_inserter(stream_data));
      } else {
        std::reverse_copy(offset_bytes, offset_bytes + sizeof(uint32_t),
                          std::back_inserter(stream_data));
      }
      stream_data.push_back(0x00);
      stream_data.push_back(0x00);
    }
    std::copy(stream_data.cbegin(), stream_data.cend(),
              std::back_inserter(res));
  }
  // --------------------
  // finish object
  {
    std::string obj_end = "\n";
    obj_end += kStreamEnd;
    obj_end += kObjEnd;
    std::copy(obj_end.cbegin(), obj_end.cend(), std::back_inserter(res));
  }
  return res;
}

} // namespace pdfcsp::pdf