/* File: csp_for_poppl.hpp
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

#include <sys/types.h>

#include <algorithm>
#include <cstdint>

#include "c_bridge.hpp"
#include "pod_structs.hpp"
#include "structs.hpp"

namespace pdfcsp::poppler {

using RangesVector = std::vector<std::pair<uint64_t, uint64_t>>;

/**
 * @brief Check the signature
 *
 * @param byte_ranges std::vector<std::pair<int64_t, int64_t>> byterange
 * @param raw_signature std::vector<unsigned char> a raw signature data
 * @param file_path  std::sttring - path to file
 * @return ESInfo
 */
inline ESInfo CheckES(const RangesVector &byte_ranges,
                      const BytesVector &raw_signature,
                      const std::string &file_path) noexcept {
  pdfcsp::c_bridge::CPodParam pod_params{};
  // Put the byteranges into the flat memory.
  std::vector<uint64_t> flat_ranges;
  std::for_each(byte_ranges.cbegin(), byte_ranges.cend(),
                [&flat_ranges](const auto &range_pair) {
                  flat_ranges.emplace_back(range_pair.first);
                  flat_ranges.emplace_back(range_pair.second);
                });
  pod_params.byte_range_arr = flat_ranges.data();
  pod_params.byte_ranges_size = flat_ranges.size();
  // raw signature
  pod_params.raw_signature_data = raw_signature.data();
  pod_params.raw_signature_size = raw_signature.size();
  // file path
  pod_params.file_path = file_path.c_str();
  pod_params.file_path_size = file_path.size() + 1;
  // call the library
  c_bridge::CPodResult *const pod_result = CGetCheckResult(pod_params);
  ESInfo result(pod_result);
  CFreeResult(pod_result);
  return result;
}

}  // namespace pdfcsp::poppler