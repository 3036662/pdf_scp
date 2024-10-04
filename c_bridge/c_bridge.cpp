#include "c_bridge.hpp"
#include "altcsp.hpp"
#include "pod_structs.hpp"
#include "utils_c_bridge.hpp"
#include <iostream>

namespace pdfcsp::c_bridge {

using RangesVector = std::vector<std::pair<uint64_t, uint64_t>>;

CPodResult *CGetCheckResult(CPodParam params) {
  if (params.byte_range_arr == nullptr || params.byte_ranges_size == 0 ||
      params.raw_signature_data == nullptr || params.raw_signature_size == 0 ||
      params.file_path == nullptr || params.file_path_size == 0) {
    return nullptr;
  }
  // create a byterange
  if (params.byte_ranges_size % 2 != 0) {
    std::cerr << "[pfdcsp] ByteRanges array size is not even\n";
    return nullptr;
  }
  RangesVector byteranges;
  for (uint64_t i = 0; i < params.byte_ranges_size; i += 2) {
    byteranges.emplace_back(params.byte_range_arr[i],
                            params.byte_range_arr[i + 1]);
  }
  // read a signature data
  const csp::BytesVector raw_sig(params.raw_signature_data,
                                 params.raw_signature_data +
                                     params.raw_signature_size);

  // read a raw data
  const std::string file(params.file_path, params.file_path_size);
  auto raw_data = utils::FileToVector(file, byteranges);
  if (!raw_data || raw_data->empty()) {
    std::cerr << "[pdfcsp] Empty data read from file " << file << "\n";
    return nullptr;
  }
  // get the CheckResult
  csp::checks::CheckResult check_res;
  try {
    csp::Csp csp;
    const csp::PtrMsg msg = csp.OpenDetached(raw_sig);
    const csp::checks::CheckResult check_result = check_res =
        msg->ComprehensiveCheck(raw_data.value(), 0, true);
  } catch (const std::exception &ex) {
    std::cerr << ex.what() << "\n";
    return nullptr;
  }
  return utils::PodResultFromResult(check_res);
}

// NOLINTBEGIN(cppcoreguidelines-owning-memory)
void CFreeResult(CPodResult *p_res) {
  delete p_res->p_stor;
  delete p_res;
}
// NOLINTEND(cppcoreguidelines-owning-memory)

} // namespace pdfcsp::c_bridge