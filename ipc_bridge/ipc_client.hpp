/* File: ipc_client.hpp
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

#include <unistd.h>

#include <boost/interprocess/interprocess_fwd.hpp>
#include <boost/interprocess/sync/named_semaphore.hpp>
#include <memory>
#include <string>

#include "ipc_result.hpp"
#include "logger_utils.hpp"
#include "pod_structs.hpp"

namespace pdfcsp::ipc_bridge {

using CPodResult = c_bridge::CPodResult;
using TaskBatch = c_bridge::TaskBatch;
using TaskBatchResult = c_bridge::TaskBatchResult;
using CPodParam = c_bridge::CPodParam;
using IPCResultPair =
  std::pair<IPCResult *, bip::managed_shared_memory::size_type>;

/**
 * @brief IPC bridge to CSP
 * @throws boost::interprocess::interprocess_exception
 */
class IpcClient {
 public:
  IpcClient();

  IpcClient(const IpcClient &) = delete;
  IpcClient(IpcClient &&) = delete;
  IpcClient &operator=(const IpcClient &) = delete;
  IpcClient &operator=(IpcClient &&) = delete;

  ~IpcClient();

  void SetTasks(const TaskBatch &tasks);

  /**
   * @brief executes altcspIpcProvider
   * @return c_bridge::TaskBatchResult - an array of CPodResult pointers
   * @warning caller must call delete CPodResult structs
   */
  TaskBatchResult CallProvider(const c_bridge::TaskBatch &tasks);

 private:
  /// @brief remove shared memory objects and semaphores
  void CleanUp();

  [[nodiscard]] bool RunProvider();
  [[nodiscard]] bool KillProvider();

  /// @brief restart the provider, just kill if last_task
  void RestartProvider(bool last_task);

  void PostExitCommand();

  [[nodiscard]] bool PostOneTask(const CPodParam &task);

  static CPodResult *CreateTimeOutResult();

  /// @brief convert the IPCResult to usual c_bridge::CPodResult
  [[nodiscard]] static c_bridge::CPodResult *CreatePodResult(
    const IPCResult &ipc_res);

  pid_t pid_;
  pid_t child_pid_ = 0;
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
  std::shared_ptr<spdlog::logger> logger_;
};

}  // namespace pdfcsp::ipc_bridge