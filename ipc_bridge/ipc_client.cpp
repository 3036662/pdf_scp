#include "ipc_bridge/ipc_client.hpp"
#include "bridge_obj_storage.hpp"
#include "ipc_bridge/ipc_result.hpp"
#include "ipc_param.hpp"
#include "pod_structs.hpp"
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/interprocess/interprocess_fwd.hpp>
#include <boost/interprocess/shared_memory_object.hpp>
#include <boost/interprocess/sync/named_semaphore.hpp>
#include <csignal>
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

// NOLINTBEGIN(cppcoreguidelines-pro-type-vararg,hicpp-vararg,-warnings-as-errors)

//  caller must call delete
c_bridge::CPodResult *IpcClient::CallProvider() {
  const pid_t pid = fork();
  constexpr const char *exec_name = IPC_PROV_EXEC_NAME;
  if (pid == 0) {
    const int res =
        execl(exec_name, exec_name, mem_name_.c_str(), sem_param_name_.c_str(),
              sem_result_name_.c_str(), nullptr);
    if (res == -1) {
      std::cerr << "[IpcClient] run ipcProvider failed\n";
    }
  }
  std::cout << "Parent process (PID: " << getpid()
            << ") created child with PID: " << pid << "\n";
  const boost::posix_time::ptime timeout =
      boost::posix_time::microsec_clock::universal_time() +
      boost::posix_time::seconds(kMaxResultTimeout);
  const bool wait_result = sem_result_->timed_wait(timeout);
  if (!wait_result) {
    std::cerr << "[Client] Timeout exceeded\n";
    if (kill(pid, SIGTERM) == 0) {
      std::cout << "[Client] Sent SIGTERM to provider\n";
    } else {
      std::cerr << "Failed to send SIGTERM to child process.\n";
    }

  } else {
    try {
      std::cout << "[IPCClient] client reading result\n";
      const std::pair<IPCResult *, bip::managed_shared_memory::size_type>
          result_pair = shared_mem_->find<IPCResult>(kParamName);
      if (result_pair.second == 1 && result_pair.first != nullptr) {
        return CreatePodResult(*result_pair.first);
      }
      std::cerr << "[IPCClient] find result\n";
      return nullptr;
    } catch (const boost::interprocess::interprocess_exception &ex) {
      std::cerr << "[Client Exception]" << ex.what() << "\n";
    }
  }
  return nullptr;
};

// NOLINTEND(cppcoreguidelines-pro-type-vararg,hicpp-vararg,-warnings-as-errors)

// NOLINTBEGIN(cppcoreguidelines-owning-memory)

c_bridge::CPodResult *IpcClient::CreatePodResult(const IPCResult &ipc_res) {
  auto *res = new c_bridge::CPodResult{};
  res->p_stor = new c_bridge::BrigeObjStorage;
  c_bridge::BrigeObjStorage &storage = *res->p_stor;
  std::copy(ipc_res.cades_t_str.cbegin(), ipc_res.cades_t_str.cend(),
            std::back_inserter(storage.cades_t_str));
  return res;
}

// NOLINTEND(cppcoreguidelines-owning-memory)

} // namespace pdfcsp::ipc_bridge