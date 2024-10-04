#include "ipc_bridge/ipc_client.hpp"
#include "ipc_param.hpp"
#include <boost/interprocess/interprocess_fwd.hpp>
#include <boost/interprocess/shared_memory_object.hpp>
#include <boost/interprocess/sync/named_semaphore.hpp>
#include <iostream>
#include <iterator>
#include <memory>
#include <string>
#include <unistd.h>

namespace pdfcsp::ipc_bridge {

IpcClient::IpcClient(const c_bridge::CPodParam &params)
    : pid_(getpid()), pid_str_(std::to_string(pid_)),
      mem_name_(kSharedMemoryName + pid_str_),
      sem_param_name_(kParamSemaphoreName + pid_str_),
      sem_result_name_(kParamSemaphoreName + pid_str_) {
  CleanUp();

  sem_param_ = std::make_unique<bip::named_semaphore>(
      bip::open_or_create, sem_param_name_.c_str(), 0);
  sem_result_ = std::make_unique<bip::named_semaphore>(
      bip::open_or_create, sem_result_name_.c_str(), 0);
  shared_mem_ = std::make_unique<bip::managed_shared_memory>(
      bip::open_or_create, mem_name_.c_str(), 65536);
  // NOLINTBEGIN(cppcoreguidelines-prefer-member-initializer)
  string_allocator_ =
      std::make_unique<IpcStringAllocator>(shared_mem_->get_segment_manager());
  bytes_allocator_ =
      std::make_unique<IpcByteAllocator>(shared_mem_->get_segment_manager());
  // NOLINTEND(cppcoreguidelines-prefer-member-initializer)

  IPCParam *p_param = shared_mem_->construct<IPCParam>(kParamName)(
      *string_allocator_, *bytes_allocator_);
  // copy byteranges
  if (params.byte_range_arr != nullptr && params.byte_ranges_size != 0) {
    std::copy(params.byte_range_arr,
              params.byte_range_arr + params.byte_ranges_size,
              std::back_inserter(p_param->byte_range_arr));
  }
  // copy raw signature data
  if (params.raw_signature_data != nullptr && params.raw_signature_size != 0) {
    std::copy(params.raw_signature_data,
              params.raw_signature_data + params.raw_signature_size,
              std::back_inserter(p_param->raw_signature_data));
  }
  // copy file path
  if (params.file_path != nullptr && params.file_path_size != 0) {
    p_param->file_path = params.file_path;
  }
  // parameters structure is ready
  sem_param_->post();
};

IpcClient::~IpcClient() { CleanUp(); }

void IpcClient::CleanUp() {
  bip::shared_memory_object::remove(mem_name_.c_str());
  bip::named_semaphore::remove(sem_param_name_.c_str());
  bip::named_semaphore::remove(sem_result_name_.c_str());
}

} // namespace pdfcsp::ipc_bridge