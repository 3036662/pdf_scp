#include "c_bridge.hpp"
#include "ipc_bridge/ipc_client.hpp"
#include "pod_structs.hpp"
#include <exception>
#include <iostream>

namespace pdfcsp::c_bridge {

using RangesVector = std::vector<std::pair<uint64_t, uint64_t>>;

CPodResult *CGetCheckResult(CPodParam params) {
  if (params.byte_range_arr == nullptr || params.byte_ranges_size == 0 ||
      params.raw_signature_data == nullptr || params.raw_signature_size == 0 ||
      params.file_path == nullptr || params.file_path_size == 0) {
    return nullptr;
  }
  ipc_bridge::IpcClient ipc_client(params);
  try {
    return ipc_client.CallProvider();
  } catch (const std::exception &ex) {
    std::cerr << "[CGetCheckResult][ERROR] " << ex.what() << "\n";
    return nullptr;
  }
}

// NOLINTBEGIN(cppcoreguidelines-owning-memory)
void CFreeResult(CPodResult *p_res) {
  if (p_res!=nullptr){
    delete p_res->p_stor;
  }
  delete p_res;
}
// NOLINTEND(cppcoreguidelines-owning-memory)

} // namespace pdfcsp::c_bridge