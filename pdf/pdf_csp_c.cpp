/* File: pdf_csp_c.cpp
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

#include "pdf_csp_c.hpp"

#include <SignatureImageCWrapper/c_wrapper.hpp>
#include <SignatureImageCWrapper/pod_structs.hpp>
#include <codecvt>
#include <cstdint>
#include <exception>
#include <fstream>
#include <iostream>
#include <iterator>
#include <memory>
#include <ostream>
#include <stdexcept>

#include "altcsp.hpp"
#include "c_bridge.hpp"
#include "csppdf.hpp"
#include "logger_utils.hpp"
#include "pdf_defs.hpp"
#include "pdf_pod_structs.hpp"
#include "pdf_utils.hpp"
#include "pod_structs.hpp"

namespace pdfcsp::pdf {

void FreePrepareDocResult(CSignPrepareResult *ptr_res) {
  if (ptr_res == nullptr) {
    return;
  }
  delete ptr_res->storage;  // NOLINT
  delete ptr_res;           // NOLINT
}

CSignPrepareResult *PrepareDoc(CSignParams params) {
  c_bridge::CPodResult *pod_res_csp = nullptr;
  auto logger = logger::InitLog();
  if (!logger) {
    std::cerr << "[PrepareDoc] init logger failed\n";
    return nullptr;
  }
  try {
    if (params.file_to_sign_path == nullptr) {
      throw std::runtime_error("file_to_sign == nullptr");
    }
    auto pdf = std::make_unique<Pdf>(params.file_to_sign_path);
    auto stage1_result = pdf->CreateObjectKit(params);
    pdf.reset();  // free the source file
    // sign file
    // prepare parameters
    // byteranges
    std::vector<uint64_t> flat_ranges;
    for (const auto &pair_val : stage1_result.byteranges) {
      flat_ranges.emplace_back(pair_val.first);
      flat_ranges.emplace_back(pair_val.second);
    }
    c_bridge::CPodParam sign_params{};
    sign_params.byte_range_arr = flat_ranges.data();
    sign_params.byte_ranges_size = flat_ranges.size();
    // file path
    sign_params.file_path = stage1_result.file_name.c_str();
    sign_params.file_path_size = stage1_result.file_name.size();
    // cert serial and subject
    sign_params.cert_serial = params.cert_serial;
    sign_params.cert_subject = params.cert_subject;
    sign_params.cades_type = params.cades_type;
    sign_params.tsp_link = params.tsp_link;
    logger->info("PrepareDoc tsp link {}", sign_params.tsp_link);
    // call CSP
    pod_res_csp = c_bridge::CSignPdf(sign_params);  // NOLINT
    if (pod_res_csp == nullptr) {
      throw std::runtime_error("Failed to create signature");
    }
    if (pod_res_csp->common_execution_status) {
      BytesVector raw_sig;
      raw_sig.reserve(pod_res_csp->raw_signature_size);
      std::copy(pod_res_csp->raw_signature,
                pod_res_csp->raw_signature + pod_res_csp->raw_signature_size,
                std::back_inserter(raw_sig));
      if (!raw_sig.empty() && raw_sig.size() < stage1_result.sig_max_size) {
        PatchDataToFile(stage1_result.file_name, stage1_result.sig_offset,
                        ByteVectorToHexString(raw_sig));
      }
    }
    CSignPrepareResult *res = new CSignPrepareResult();  // NOLINT
    res->status = pod_res_csp->common_execution_status;
    res->storage = new CSignPrepareResult::SignResStorage();  // NOLINT
    res->storage->file_path = stage1_result.file_name;
    if (pod_res_csp->err_string != nullptr) {
      res->storage->err_string = pod_res_csp->err_string;
    }
    res->tmp_file_path = res->storage->file_path.c_str();
    res->err_string = res->storage->err_string.c_str();
    c_bridge::CFreeResult(pod_res_csp);
    return res;
  } catch (const std::exception &ex) {
    logger->error("[PDFCSP::PrepareDoc] error, {}", ex.what());
    c_bridge::CFreeResult(pod_res_csp);
  }
  return nullptr;
}

StampResizeFactor *GetStampResultingSizeFactor(CSignParams params) {
  try {
    // NOLINTNEXTLINE(cppcoreguidelines-owning-memory)
    return new StampResizeFactor(Pdf::CalcImgResizeFactor(params));
  } catch (const std::exception &ex) {
    auto logger = logger::InitLog();
    if (logger) {
      logger->error("[GetStampResultingSizeFactor] {}", ex.what());
    }
  }
  return nullptr;
}

void FreeImgResizeFactorResult(StampResizeFactor *p_resize_factor) {
  // NOLINTNEXTLINE(cppcoreguidelines-owning-memory)
  delete p_resize_factor;
}

}  // namespace pdfcsp::pdf