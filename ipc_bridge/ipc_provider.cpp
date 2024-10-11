#include "ipc_param.hpp"
#include "ipc_provider_utils.hpp"
#include "ipc_result.hpp"
#include "ipc_typedefs.hpp"
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/interprocess/creation_tags.hpp>
#include <boost/interprocess/exceptions.hpp>
#include <boost/interprocess/interprocess_fwd.hpp>
#include <boost/interprocess/managed_shared_memory.hpp>
#include <boost/interprocess/sync/named_mutex.hpp>
#include <boost/interprocess/sync/named_semaphore.hpp>
#include <iostream>
#include <memory>
#include <string>

namespace ipcb = pdfcsp::ipc_bridge;

namespace bip = boost::interprocess;

// NOLINTNEXTLINE(hicpp-avoid-c-arrays,cppcoreguidelines-avoid-c-arrays,modernize-avoid-c-arrays)
int main(int argc, char *argv[]) {
  std::cout << "IPC PROVIDER\n";
  if (argc < 4) {
    std::cerr << "No parameters passed\n";
    return 1;
  }
  const std::string mem_name = argv[1];
  const std::string sem_param_name = argv[2];
  const std::string sem_result_name = argv[3];
  std::cout << mem_name << " " << sem_param_name << " " << sem_result_name
            << "\n";
  if (mem_name.empty() || sem_param_name.empty() || sem_result_name.empty()) {
    std::cerr << "Invalid parameters\n";
    return 1;
  }

  std::unique_ptr<bip::named_semaphore> sem_param;
  std::unique_ptr<bip::named_semaphore> sem_result;
  std::unique_ptr<bip::managed_shared_memory> shared_mem;
  try {
    sem_param = std::make_unique<bip::named_semaphore>(bip::open_only,
                                                       sem_param_name.c_str());
    sem_result = std::make_unique<bip::named_semaphore>(
        bip::open_only, sem_result_name.c_str());
    shared_mem = std::make_unique<bip::managed_shared_memory>(bip::open_only,
                                                              mem_name.c_str());
  } catch (const boost::interprocess::interprocess_exception &ex) {
    std::cerr << "[IPCProvider][Exception]" << ex.what();
    return 1;
  }
  boost::posix_time::ptime timeout =
      boost::posix_time::microsec_clock::universal_time() +
      boost::posix_time::seconds(pdfcsp::ipc_bridge::kMaxParamTimeout);
  std::cout << "[Provider] waiting for params\n";
  bool wait_result = sem_param->timed_wait(timeout);
  if (!wait_result) {
    std::cerr << "[IPCProvider] waiting for params timeout exceeded\n";
    return 1;
  }
  std::pair<ipcb::IPCParam *, bip::managed_shared_memory::size_type>
      param_pair =
          shared_mem->find<ipcb::IPCParam>(pdfcsp::ipc_bridge::kParamName);
  if (param_pair.second != 1 || param_pair.first == nullptr) {
    std::cerr << "[IPCProvider] params value not found";
    return 1;
  }
  std::cout << "PARAM PATH" << param_pair.first->file_path << "\n";
  const ipcb::IPCParam &param = *param_pair.first;
  try {
    // create IPCResult
    ipcb::IpcStringAllocator string_allocator(
        shared_mem->get_segment_manager());
    ipcb::IpcByteAllocator bytes_allocator(shared_mem->get_segment_manager());
    ipcb::IpcTimeTAllocator time_allocator(shared_mem->get_segment_manager());
    ipcb::IPCResult *result = shared_mem->find_or_construct<ipcb::IPCResult>(
        pdfcsp::ipc_bridge::kResultName)(string_allocator, bytes_allocator,
                                         time_allocator);
    if (result == nullptr) {
      std::cerr << "[Provider] Provider - error allocating memory for result";
      return 1;
    }
    pdfcsp::ipc_bridge::FillResult(param, *result);
    sem_result->post();
  } catch (const boost::interprocess::interprocess_exception &ex) {
    std::cerr << "[IPCProvider][Exception]" << ex.what();
    return 1;
  }

  return 0;
}