/* File: ipc_provider.cpp
Copyright (C) Basealt LLC,  2025
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

#include <sys/types.h>

#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/interprocess/creation_tags.hpp>
#include <boost/interprocess/exceptions.hpp>
#include <boost/interprocess/interprocess_fwd.hpp>
#include <boost/interprocess/managed_shared_memory.hpp>
#include <boost/interprocess/sync/named_mutex.hpp>
#include <boost/interprocess/sync/named_semaphore.hpp>
#include <cstddef>
#include <cstdlib>
#include <exception>
#include <iostream>
#include <memory>
#include <string>

#include "ipc_param.hpp"
#include "ipc_provider_utils.hpp"
#include "ipc_result.hpp"
#include "ipc_typedefs.hpp"
#include "logger_utils.hpp"

namespace ipcb = pdfcsp::ipc_bridge;

namespace bip = boost::interprocess;

namespace {

void ExecuteCommand(const ipcb::IPCParam &param, ipcb::IPCResult &res,
                    const std::unique_ptr<bip::named_semaphore> &sem_result) {
  // default behavior - check signature
  if (param.command.empty()) {
    pdfcsp::ipc_bridge::CheckDetachedWithByteRanges(param, res);
    sem_result->post();
    return;
  }
  if (param.command == "EXIT") {
    std::exit(0);  // NOLINT
  }
  if (param.command == "check_simple_detached") {
    CheckSimpleDetached(param, res);
    sem_result->post();
    return;
  }
  if (param.command == "check_simple_attached") {
    CheckSimpleAttached(param, res);
    sem_result->post();
    return;
  }
  // get certificate list for current user
  if (param.command == "user_cert_list") {
    FillCertListResult(param, res);
    sem_result->post();
    return;
  }
  // sign data
  if (param.command == "sign_pdf") {
    pdfcsp::ipc_bridge::FillSignResult(param, res);
    sem_result->post();
    return;
  }
  // check if attached
  if (param.command == "check_if_attached") {
    pdfcsp::ipc_bridge::FillCheckIfAttached(param, res);
    sem_result->post();
    return;
  }
  if (param.command == "extract_attached") {
    pdfcsp::ipc_bridge::ExtractFileFromAttached(param, res);
    sem_result->post();
    return;
  }
  if (param.command == "create_signature_file") {
    pdfcsp::ipc_bridge::CreateSignatureFile(param, res);
    sem_result->post();
    return;
  }
  res.err_string = "unsupported command";
  sem_result->post();
}

}  // namespace

using IPCParamPair =
  std::pair<ipcb::IPCParam *, bip::managed_shared_memory::size_type>;

/**
 * @brief IPC Provider executable
 * @warning It is not supposed to be executed as a free-standing application.
 * @param argc expected to be equal 4
 * @param argv[1] memory object name
 * @param argv[2] semaphore name for parameters
 * @param argv[3] semaphore name for result
 * @return int
 */
int main(int argc, char *argv[]) {
  auto logger = pdfcsp::logger::InitLog();
  const char *func_name = "[IpcProvider]";
  if (!logger) {
    std::cerr << func_name << " Init logger failed\n";
    return 1;
  }
  logger->info("IPC PROVIDER started");
  if (argc < 4) {
    logger->error("{} No parameters passed", func_name);
    return 1;
  }
  const std::string mem_name = argv[1];
  const std::string sem_param_name = argv[2];
  const std::string sem_result_name = argv[3];
  logger->debug("{} mem_name {} semaphore_param {}  semaphore_result {}",
                func_name, mem_name, sem_param_name, sem_result_name);
  if (mem_name.empty() || sem_param_name.empty() || sem_result_name.empty()) {
    logger->error("{} Invalid parameters", func_name);
    return 1;
  }
  std::unique_ptr<bip::named_semaphore> sem_param;
  std::unique_ptr<bip::named_semaphore> sem_result;
  std::unique_ptr<bip::managed_shared_memory> shared_mem;
  // find two semaphores and  shared memory
  try {
    sem_param = std::make_unique<bip::named_semaphore>(bip::open_only,
                                                       sem_param_name.c_str());
    sem_result = std::make_unique<bip::named_semaphore>(
      bip::open_only, sem_result_name.c_str());
    shared_mem = std::make_unique<bip::managed_shared_memory>(bip::open_only,
                                                              mem_name.c_str());
  } catch (const boost::interprocess::interprocess_exception &ex) {
    logger->error("{} IPC error {}", func_name, ex.what());
    return 1;
  }
  while (true) {
    boost::posix_time::ptime timeout =
      boost::posix_time::microsec_clock::universal_time() +
      boost::posix_time::seconds(pdfcsp::ipc_bridge::kMaxParamTimeout);
    logger->debug("{} waiting for params", func_name);
    bool wait_result = sem_param->timed_wait(timeout);
    if (!wait_result) {
      logger->error("{} waiting for params timeout exceeded", func_name);
      return 1;
    }
    IPCParamPair param_pair =
      shared_mem->find<ipcb::IPCParam>(pdfcsp::ipc_bridge::kParamName);
    if (param_pair.second != 1 || param_pair.first == nullptr) {
      logger->error("{} params value not found", func_name);
      return 1;
    }
    const ipcb::IPCParam &param = *param_pair.first;
    ipcb::IPCResult *result = nullptr;
    try {
      // create IPCResult
      ipcb::IpcStringAllocator string_allocator(
        shared_mem->get_segment_manager());
      ipcb::IpcByteAllocator bytes_allocator(shared_mem->get_segment_manager());
      ipcb::IpcTimeTAllocator time_allocator(shared_mem->get_segment_manager());
      result = shared_mem->find_or_construct<ipcb::IPCResult>(
        pdfcsp::ipc_bridge::kResultName)(string_allocator, bytes_allocator,
                                         time_allocator);
      if (result == nullptr) {
        logger->error("{} Provider - error allocating memory for result",
                      func_name);
        return 1;
      }
      ExecuteCommand(param, *result, sem_result);
      logger->debug("{} Sending the result", func_name);
    }
    // send all exceptions to client
    catch (const boost::interprocess::interprocess_exception &ex) {
      logger->error("{} {}", func_name, ex.what());
      if (sem_result && result != nullptr) {
        pdfcsp::ipc_bridge::FillFailResult(ex.what(), *result);
        sem_result->post();
      }
      return 1;
    } catch (const std::exception &ex) {
      logger->error("{} {}", func_name, ex.what());
      if (sem_result && result != nullptr) {
        pdfcsp::ipc_bridge::FillFailResult(ex.what(), *result);
        sem_result->post();
      }
    }
  }
  return 0;
}
