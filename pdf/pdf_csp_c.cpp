#include "pdf_csp_c.hpp"
#include "c_bridge.hpp"
#include "csppdf.hpp"
#include "pdf_defs.hpp"
#include "pdf_utils.hpp"
#include "pod_structs.hpp"
#include <cstdint>
#include <exception>
#include <fstream>
#include <iostream>
#include <iterator>
#include <memory>
#include <ostream>
#include <stdexcept>

namespace pdfcsp::pdf {

void FreePrepareDocResult(CSignPrepareResult *ptr_res) {
  if (ptr_res == nullptr) {
    return;
  }
  delete ptr_res->storage; // NOLINT
  delete ptr_res;          // NOLINT
}

CSignPrepareResult *PrepareDoc(CSignParams params) {
  // TODO(Oleg) implement
  std::cout << "PDFCSP Prepare doc\n";
  c_bridge::CPodResult *pod_res_csp = nullptr;
  try {
    if (params.file_to_sign_path == nullptr) {
      throw std::runtime_error("file_to_sign == nullptr");
    }
    auto pdf = std::make_unique<Pdf>(params.file_to_sign_path);
    auto stage1_result = pdf->CreateObjectKit(params);
    pdf.reset(); // free the source file
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
    // call CSP
    pod_res_csp = c_bridge::CSignPdf(sign_params); // NOLINT
    if (pod_res_csp == nullptr || pod_res_csp->raw_signature == nullptr ||
        pod_res_csp->raw_signature_size == 0) {
      throw std::runtime_error("Failed to create signature");
    }
    BytesVector raw_sig;
    raw_sig.reserve(pod_res_csp->raw_signature_size);
    std::copy(pod_res_csp->raw_signature,
              pod_res_csp->raw_signature + pod_res_csp->raw_signature_size,
              std::back_inserter(raw_sig));
    if (!raw_sig.empty() && raw_sig.size() < stage1_result.sig_max_size) {
      PatchDataToFile(stage1_result.file_name, stage1_result.sig_offset,
                      ByteVectorToHexString(raw_sig));
    }
    c_bridge::CFreeResult(pod_res_csp);

  } catch (const std::exception &ex) {
    std::cerr << "[PDFCSP::PrepareDoc] error, " << ex.what() << "\n";
    c_bridge::CFreeResult(pod_res_csp);
  }
  return {};
}

} // namespace pdfcsp::pdf