#include "ipc_bridge/ipc_client.hpp"
#include "bridge_obj_storage.hpp"
#include "ipc_param.hpp"
#include "ipc_result.hpp"
#include "ipc_typedefs.hpp"
#include "pod_structs.hpp"
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/interprocess/interprocess_fwd.hpp>
#include <boost/interprocess/shared_memory_object.hpp>
#include <boost/interprocess/sync/named_semaphore.hpp>
#include <cerrno>
#include <csignal>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <iostream>
#include <iterator>
#include <memory>
#include <random>
#include <string>
#include <unistd.h>

namespace pdfcsp::ipc_bridge {

IpcClient::IpcClient(const c_bridge::CPodParam &params)
    : pid_(getpid()), pid_str_(std::to_string(pid_)),
      mem_name_(kSharedMemoryName + pid_str_),
      sem_param_name_(kParamSemaphoreName + pid_str_),
      sem_result_name_(kResultSemaphoreName + pid_str_) {

  using LCG = std::linear_congruential_engine<uint32_t, 48271, 0, 2147483647>;
  LCG lcg(std::random_device{}());
  const std::string rand_str = std::to_string(lcg());
  sem_param_name_ += rand_str;
  sem_result_name_ += rand_str;
  mem_name_ += rand_str;
  CleanUp();
  sem_param_ = std::make_unique<bip::named_semaphore>(
      bip::open_or_create, sem_param_name_.c_str(), 0);
  sem_result_ = std::make_unique<bip::named_semaphore>(
      bip::open_or_create, sem_result_name_.c_str(), 0);
  shared_mem_ = std::make_unique<bip::managed_shared_memory>(
      bip::open_or_create, mem_name_.c_str(), 500000);
  std::cout << "CREATED ipc objects\n";
  // NOLINTBEGIN(cppcoreguidelines-prefer-member-initializer)
  string_allocator_ =
      std::make_unique<IpcStringAllocator>(shared_mem_->get_segment_manager());
  bytes_allocator_ =
      std::make_unique<IpcByteAllocator>(shared_mem_->get_segment_manager());
  uint64_allocator_ =
      std::make_unique<IpcUint64Allocator>(shared_mem_->get_segment_manager());
  // NOLINTEND(cppcoreguidelines-prefer-member-initializer)

  IPCParam *p_param = shared_mem_->construct<IPCParam>(kParamName)(
      *string_allocator_, *bytes_allocator_, *uint64_allocator_);
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
  // run the Provider
  const pid_t pid = fork();
  const std::string exec_name = std::string(IPC_EXEC_DIR) + IPC_PROV_EXEC_NAME;
  std::cout << "IPC EXE FILE = " << exec_name << "\n";
  if (pid == 0) {
    const int res =
        execl(exec_name.c_str(), exec_name.c_str(), mem_name_.c_str(),
              sem_param_name_.c_str(), sem_result_name_.c_str(), nullptr);
    if (res == -1) {
      std::cerr << "err " << strerror(errno); // NOLINT
      std::cerr << "[IpcClient] run ipcProvider failed\n";
    }
    return nullptr;
  }
  std::cout << "Parent process (PID: " << getpid()
            << ") created child with PID: " << pid << "\n";
  const boost::posix_time::ptime timeout =
      boost::posix_time::microsec_clock::universal_time() +
      boost::posix_time::seconds(kMaxResultTimeout);
  // wait for result
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
          result_pair = shared_mem_->find<IPCResult>(kResultName);
      if (result_pair.second == 1 && result_pair.first != nullptr) {
        c_bridge::CPodResult *result = CreatePodResult(*result_pair.first);
        shared_mem_->destroy<IPCParam>(kParamName);
        shared_mem_->destroy<IPCResult>(kResultName);
        return result;
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
  std::copy(ipc_res.hashing_oid.cbegin(), ipc_res.hashing_oid.cend(),
            std::back_inserter(storage.hashing_oid));
  std::copy(ipc_res.times_collection.cbegin(), ipc_res.times_collection.cend(),
            std::back_inserter(storage.times_collection));
  std::copy(ipc_res.x_times_collection.cbegin(),
            ipc_res.x_times_collection.cend(),
            std::back_inserter(storage.x_times_collection));
  std::copy(ipc_res.encrypted_digest.cbegin(), ipc_res.encrypted_digest.cend(),
            std::back_inserter(storage.encrypted_digest));
  std::copy(ipc_res.cert_issuer_dname.cbegin(),
            ipc_res.cert_issuer_dname.cend(),
            std::back_inserter(storage.cert_issuer));
  std::copy(ipc_res.cert_subject_dname.cbegin(),
            ipc_res.cert_subject_dname.cend(),
            std::back_inserter(storage.cert_subject));
  std::copy(ipc_res.cert_public_key.cbegin(), ipc_res.cert_public_key.cend(),
            std::back_inserter(storage.cert_public_key));
  std::copy(ipc_res.cert_serial.cbegin(), ipc_res.cert_serial.cend(),
            std::back_inserter(storage.cert_serial));
  std::copy(ipc_res.cert_der_encoded.cbegin(), ipc_res.cert_der_encoded.cend(),
            std::back_inserter(storage.cert_der_encoded));
  std::copy(ipc_res.issuer_common_name.cbegin(),
            ipc_res.issuer_common_name.cend(),
            std::back_inserter(storage.issuer_common_name));
  std::copy(ipc_res.issuer_email.cbegin(), ipc_res.issuer_email.cend(),
            std::back_inserter(storage.issuer_email));
  std::copy(ipc_res.issuer_organization.cbegin(),
            ipc_res.issuer_organization.cend(),
            std::back_inserter(storage.issuer_organization));

  std::copy(ipc_res.subj_common_name.cbegin(), ipc_res.subj_common_name.cend(),
            std::back_inserter(storage.subj_common_name));
  std::copy(ipc_res.subj_email.cbegin(), ipc_res.subj_email.cend(),
            std::back_inserter(storage.subj_email));
  std::copy(ipc_res.subj_organization.cbegin(),
            ipc_res.subj_organization.cend(),
            std::back_inserter(storage.subj_organization));
  std::copy(ipc_res.signers_chain_json.cbegin(),
            ipc_res.signers_chain_json.cend(),
            std::back_inserter(storage.cert_chain_json));
  std::copy(ipc_res.tsp_json_info.cbegin(), ipc_res.tsp_json_info.cend(),
            std::back_inserter(storage.tsp_json_info));
  std::copy(ipc_res.signers_cert_ocsp_json_info.cbegin(),
            ipc_res.signers_cert_ocsp_json_info.cend(),
            std::back_inserter(storage.signers_cert_ocsp_json_info));

  res->bres = ipc_res.bres;
  res->cades_type = ipc_res.cades_type;
  res->cades_t_str = storage.cades_t_str.c_str();
  res->hashing_oid = storage.hashing_oid.c_str();
  res->encrypted_digest = storage.encrypted_digest.data();
  res->encrypted_digest_size = storage.encrypted_digest.size();
  res->times_collection = storage.times_collection.data();
  res->times_collection_size = storage.times_collection.size();
  res->x_times_collection = storage.x_times_collection.data();
  res->x_times_collection_size = storage.x_times_collection.size();
  res->cert_issuer_dname = storage.cert_issuer.c_str();
  res->cert_subject_dname = storage.cert_subject.c_str();

  res->issuer_common_name = storage.issuer_common_name.c_str();
  res->issuer_email = storage.issuer_email.c_str();
  res->issuer_organization = storage.issuer_organization.c_str();
  res->subj_common_name = storage.subj_common_name.c_str();
  res->subj_email = storage.subj_email.c_str();
  res->subj_organization = storage.subj_organization.c_str();
  res->cert_chain_json = storage.cert_chain_json.c_str();
  res->tsp_json_info = storage.tsp_json_info.c_str();
  res->signers_cert_ocsp_json_info =
      storage.signers_cert_ocsp_json_info.c_str();

  res->cert_public_key = storage.cert_public_key.data();
  res->cert_public_key_size = storage.cert_public_key.size();
  res->cert_serial = storage.cert_serial.data();
  res->cert_serial_size = storage.cert_serial.size();
  res->cert_der_encoded = storage.cert_der_encoded.data();
  res->cert_der_encoded_size = storage.cert_der_encoded.size();
  res->signers_time = ipc_res.signers_time;
  res->cert_not_before = ipc_res.cert_not_before;
  res->cert_not_after = ipc_res.cert_not_after;
  res->signers_cert_version = ipc_res.signers_cert_version;
  res->signers_cert_key_usage = ipc_res.signers_cert_key_usage;
  return res;
}

// NOLINTEND(cppcoreguidelines-owning-memory)

} // namespace pdfcsp::ipc_bridge