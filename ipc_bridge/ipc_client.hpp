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
#include "pod_structs.hpp"

namespace pdfcsp::ipc_bridge {

/**
 * @brief IPC bridge to CSP
 * @throws boost::interprocess::interprocess_exception
 */
class IpcClient {
 public:
  /**
   * @brief Construct a new Ipc Client object
   * @param params @see c_bridge::CPodParam params
   */
  explicit IpcClient(const c_bridge::CPodParam &params);

  IpcClient(const IpcClient &) = delete;
  IpcClient(IpcClient &&) = delete;
  IpcClient &operator=(const IpcClient &) = delete;
  IpcClient &operator=(IpcClient &&) = delete;

  ~IpcClient();

  /**
   * @brief executes altcspIpcProvider
   * @return c_bridge::CPodResult*
   * @warning caller must call delete CPodResult*
   */
  c_bridge::CPodResult *CallProvider();

 private:
  /// @brief remove shared memory objects and semaphores
  void CleanUp();

  /// @brief convert the IPCResult to usual c_bridge::CPodResult
  [[nodiscard]] static c_bridge::CPodResult *CreatePodResult(
    const IPCResult &ipc_res);

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

}  // namespace pdfcsp::ipc_bridge