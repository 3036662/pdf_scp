#pragma once

#include "ipc_result.hpp"
#include "pod_structs.hpp"
#include <boost/interprocess/interprocess_fwd.hpp>
#include <boost/interprocess/sync/named_semaphore.hpp>
#include <memory>
#include <string>
#include <unistd.h>

namespace pdfcsp::ipc_bridge {

/**
 * @brief IPC bridge to CSP
 * @throws boost::interprocess::interprocess_exception
 */
class IpcClient {

public:
  /**
   * @brief Construct a new Ipc Client object
   * @param c_bridge::CPodParam params
   */
  explicit IpcClient(const c_bridge::CPodParam &params);

  IpcClient(const IpcClient &) = delete;
  IpcClient(IpcClient &&) = delete;
  IpcClient &operator=(const IpcClient &) = delete;
  IpcClient &operator=(IpcClient &&) = delete;

  ~IpcClient();

  // call altcspIpcProvider
  // caller must call delete
  c_bridge::CPodResult *CallProvider();

private:
  /// @brief remove shared memory objects and semaphores
  void CleanUp();

  [[nodiscard]] static c_bridge::CPodResult *
  CreatePodResult(const IPCResult &ipc_res);

  pid_t pid_;
  std::string pid_str_;
  std::string mem_name_;
  std::string sem_param_name_;
  std::string sem_result_name_;

  std::unique_ptr<bip::named_semaphore> sem_param_;
  std::unique_ptr<bip::named_semaphore> sem_result_;
  std::unique_ptr<bip::managed_shared_memory> shared_mem_;
  std::unique_ptr<IpcStringAllocator> string_allocator_;
  std::unique_ptr<IpcByteAllocator> bytes_allocator_;
  std::unique_ptr<IpcUint64Allocator> uint64_allocator_;
};

} // namespace pdfcsp::ipc_bridge