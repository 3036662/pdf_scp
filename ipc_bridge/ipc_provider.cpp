#include "ipc_param.hpp"
#include "ipc_provider_utils.hpp"
#include "ipc_result.hpp"
#include "ipc_typedefs.hpp"
#include "logger_utils.hpp"
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/interprocess/creation_tags.hpp>
#include <boost/interprocess/exceptions.hpp>
#include <boost/interprocess/interprocess_fwd.hpp>
#include <boost/interprocess/managed_shared_memory.hpp>
#include <boost/interprocess/sync/named_mutex.hpp>
#include <boost/interprocess/sync/named_semaphore.hpp>
#include <exception>
#include <iostream>
#include <memory>
#include <string>
#include <sys/types.h>

namespace ipcb = pdfcsp::ipc_bridge;

namespace bip = boost::interprocess;

// NOLINTNEXTLINE(hicpp-avoid-c-arrays,cppcoreguidelines-avoid-c-arrays,modernize-avoid-c-arrays)
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
    logger->error("{} {}", func_name, ex.what());
    return 1;
  }
  boost::posix_time::ptime timeout =
      boost::posix_time::microsec_clock::universal_time() +
      boost::posix_time::seconds(pdfcsp::ipc_bridge::kMaxParamTimeout);
  logger->debug("{} waiting for params", func_name);
  bool wait_result = sem_param->timed_wait(timeout);
  if (!wait_result) {
    logger->error("{} waiting for params timeout exceeded", func_name);
    return 1;
  }
  std::pair<ipcb::IPCParam *, bip::managed_shared_memory::size_type>
      param_pair =
          shared_mem->find<ipcb::IPCParam>(pdfcsp::ipc_bridge::kParamName);
  if (param_pair.second != 1 || param_pair.first == nullptr) {
    logger->error("{} params value not found", func_name);
    return 1;
  }
  // logger->debug("{} PARAM PATH {}", func_name, param_pair.first->file_path);
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
    // default behavior - check signature
    if (param.command.empty()) {
      pdfcsp::ipc_bridge::FillResult(param, *result);
      sem_result->post();
      return 0;
    }
    // get certificate list for current user
    if (param.command == "user_cert_list") {
      FillCertListResult(param, *result);
      sem_result->post();
      return 0;
    }
    // sign data
    if (param.command == "sign_pdf") {
      pdfcsp::ipc_bridge::FillSignResult(param, *result);
      sem_result->post();
      return 0;
    }
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
    return 1;
  }
  return 0;
}