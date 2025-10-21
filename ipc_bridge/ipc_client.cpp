/* File: ipc_client.cpp
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

#include "ipc_bridge/ipc_client.hpp"

#include <unistd.h>

#include <array>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/interprocess/exceptions.hpp>
#include <boost/interprocess/interprocess_fwd.hpp>
#include <boost/interprocess/shared_memory_object.hpp>
#include <boost/interprocess/sync/named_semaphore.hpp>
#include <cerrno>
#include <charconv>
#include <csignal>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <exception>
#include <iterator>
#include <memory>
#include <random>
#include <stdexcept>
#include <string>
#include <tuple>

#include "bridge_obj_storage.hpp"
#include "ipc_param.hpp"
#include "ipc_result.hpp"
#include "ipc_typedefs.hpp"
#include "logger_utils.hpp"
#include "pod_structs.hpp"

namespace pdfcsp::ipc_bridge {

/**
 * @brief Construct a new Ipc Client object
 * @param params @see c_bridge::CPodParam params
 */
IpcClient::IpcClient()
  : pid_(getpid()),
    pid_str_(std::to_string(pid_)),
    mem_name_(kSharedMemoryName + pid_str_),
    sem_param_name_(kParamSemaphoreName + pid_str_),
    sem_result_name_(kResultSemaphoreName + pid_str_),
    logger_{logger::InitLog()} {
  // create random postfix string for semaphores and memory
  using LCG = std::linear_congruential_engine<uint32_t, 48271, 0, 2147483647>;
  LCG lcg(std::random_device{}());
  constexpr uint32_t kMaxRandValue = 10000000;
  std::uniform_int_distribution<uint32_t> dist(0, kMaxRandValue);
  const uint32_t random_value = dist(lcg);
  std::array<char, 10> buff{};
  const auto res_to_char =
    std::to_chars(buff.data(), buff.data() + buff.size(), random_value, 10);
  if (res_to_char.ec != std::errc()) {
    throw std::runtime_error("[IpcClient] Integer to char conversion failed");
  }
  const std::string rand_str = std::string(buff.data(), res_to_char.ptr);
  sem_param_name_ += rand_str;
  sem_result_name_ += rand_str;
  mem_name_ += rand_str;
  CleanUp();
  // create a shared memory object and semaphores
  sem_param_ = std::make_unique<bip::named_semaphore>(
    bip::open_or_create, sem_param_name_.c_str(), 0);
  sem_result_ = std::make_unique<bip::named_semaphore>(
    bip::open_or_create, sem_result_name_.c_str(), 0);
  shared_mem_ = std::make_unique<bip::managed_shared_memory>(
    bip::open_or_create, mem_name_.c_str(), 500000);
  // create allocator for shared memory objects
  string_allocator_ =
    std::make_unique<IpcStringAllocator>(shared_mem_->get_segment_manager());
  bytes_allocator_ =
    std::make_unique<IpcByteAllocator>(shared_mem_->get_segment_manager());
  uint64_allocator_ =
    std::make_unique<IpcUint64Allocator>(shared_mem_->get_segment_manager());
  if (!logger_) {
    throw std::runtime_error("[IpcClient] Init logger failed");
  }
}

IpcClient::~IpcClient() { CleanUp(); }

[[nodiscard]] bool IpcClient::PostOneTask(const CPodParam& task) {
  constexpr const char* func_name = "[IpcClient::PostOneTask]";
  // fill the IPCParam with parameters
  IPCParam* p_shared_param = nullptr;
  try {
    p_shared_param = shared_mem_->construct<IPCParam>(kParamName)(
      *string_allocator_, *bytes_allocator_, *uint64_allocator_);
  } catch (const boost::interprocess::interprocess_exception& ex) {
    logger_->error("{} error: {}", func_name, ex.what());
    return false;
  }
  if (p_shared_param == nullptr) {
    logger_->error("{} post task failed", func_name);
    return false;
  }
  // copy command
  if (task.command != nullptr && task.command_size != 0) {
    std::copy(task.command, task.command + task.command_size,
              std::back_inserter(p_shared_param->command));
  }
  // copy byteranges
  if (task.byte_range_arr != nullptr && task.byte_ranges_size != 0) {
    std::copy(task.byte_range_arr, task.byte_range_arr + task.byte_ranges_size,
              std::back_inserter(p_shared_param->byte_range_arr));
  }
  // copy raw signature data
  if (task.raw_signature_data != nullptr && task.raw_signature_size != 0) {
    std::copy(task.raw_signature_data,
              task.raw_signature_data + task.raw_signature_size,
              std::back_inserter(p_shared_param->raw_signature_data));
  }
  // copy file path
  if (task.file_path != nullptr && task.file_path_size != 0) {
    p_shared_param->file_path = task.file_path;
  }
  // params for creating signature
  if (task.cert_subject != nullptr) {
    p_shared_param->cert_subject = task.cert_subject;
  }
  if (task.cert_serial != nullptr) {
    p_shared_param->cert_serial = task.cert_serial;
  }
  if (task.cades_type != nullptr) {
    p_shared_param->cades_type = task.cades_type;
  }
  if (task.tsp_link != nullptr) {
    p_shared_param->tsp_link = task.tsp_link;
  }
  // file path for checking separate signature file
  if (task.sig_file_path != nullptr && task.sig_file_path_size != 0) {
    p_shared_param->sig_file_path = task.sig_file_path;
  }
  p_shared_param->create_attached = task.create_attached;
  p_shared_param->create_base_64_encoded = task.create_base_64_encoded;
  // parameters structure is ready
  sem_param_->post();
  return true;
}

void IpcClient::PostExitCommand() {
  CPodParam params;
  params.command = "EXIT";
  params.command_size = 4;
  logger_->debug("Sending exit to the IPC Provider");
  std::ignore = PostOneTask(params);
}

void IpcClient::CleanUp() {
  // NOLINTBEGIN(cert-err33-c)
  bip::shared_memory_object::remove(mem_name_.c_str());
  bip::named_semaphore::remove(sem_param_name_.c_str());
  bip::named_semaphore::remove(sem_result_name_.c_str());
  // NOLINTEND(cert-err33-c)
}

// NOLINTBEGIN(cppcoreguidelines-pro-type-vararg,hicpp-vararg,-warnings-as-errors)

bool IpcClient::RunProvider() {
  constexpr const char* func_name = "[IpcClient::RunProvider] ";
  // run the Provider
  child_pid_ = fork();
  if (child_pid_ == -1) {
    logger_->error("{} err {}", func_name, strerror(errno));  // NOLINT
    return false;
  }
  const std::string exec_name = std::string(IPC_EXEC_DIR) + IPC_PROV_EXEC_NAME;
  logger_->info("{} IPC EXE FILE = {}", func_name, exec_name);
  if (child_pid_ == 0) {
    execl(exec_name.c_str(), exec_name.c_str(), mem_name_.c_str(),
          sem_param_name_.c_str(), sem_result_name_.c_str(), nullptr);
    logger_->error("{} err {}", func_name, strerror(errno));  // NOLINT
    logger_->error("{} run ipcProvider failed", func_name);
    std::terminate();
  }
  logger_->info("{} Parent process (PID: {} ) created child with PID {}",
                func_name, std::to_string(getpid()),
                std::to_string(child_pid_));
  return true;
}

bool IpcClient::KillProvider() {
  logger_->info("[IpcClient] Sent SIGTERM to provider");
  return kill(child_pid_, SIGTERM) == 0;
}

void IpcClient::RestartProvider(bool last_task) {
  constexpr const char* func_name = "[IpcClient::RestartProvider]";
  if (!KillProvider()) {
    logger_->error("{} Failed to send SIGTERM to child process", func_name);
  }
  // start the Provided to run next task
  if (!last_task) {
    const bool run_again_result = RunProvider();
    logger_->debug("{} Start the provider: {}", func_name,
                   run_again_result ? "OK" : "FAILED");
  }
}

CPodResult* IpcClient::CreateTimeOutResult() {
  auto result = new c_bridge::CPodResult{};           // NOLINT
  result->p_stor = new c_bridge::BridgeObjStorage{};  // NOLINT
  result->p_stor->err_string = "TIMEOUT";
  result->common_execution_status = false;
  result->err_string = result->p_stor->err_string.c_str();
  return result;
}

/**
 * @brief executes altcspIpcProvider
 * @return c_bridge::TaskBatchResult
 * @warning caller must call delete CPodResult*
 */
TaskBatchResult IpcClient::CallProvider(const TaskBatch& tasks) {
  const char* func_name = "[IpcClient]";
  TaskBatchResult res;
  if (tasks.params_size == 0 || tasks.params == nullptr) {
    logger_->warn("{} called with empty task list", func_name);
    return res;
  }
  // Run the provider
  if (!RunProvider()) {
    logger_->error("{} run provider failed", func_name);
    return res;
  }
  // Create an empty array of results
  res.results = new CPodResult*[tasks.params_size]();  // NOLINT
  res.results_size = tasks.params_size;
  // for each task in tasks
  for (uint64_t task_index = 0; task_index < tasks.params_size; ++task_index) {
    logger_->debug("{} starting task {}", func_name, task_index);
    // The IPC timeout
    const boost::posix_time::ptime timeout =
      boost::posix_time::microsec_clock::universal_time() +
      boost::posix_time::seconds(kMaxResultTimeout);
    if (!PostOneTask(*tasks.params[task_index])) {
      res.results[task_index] = nullptr;
      continue;
    }
    // wait for result
    const bool wait_result = sem_result_->timed_wait(timeout);
    // if no result
    if (!wait_result) {
      logger_->error("{} Timeout exceeded", func_name);
      RestartProvider(task_index + 1 < tasks.params_size);
      res.results[task_index] = nullptr;
      continue;
    }
    // a result posted by provider
    try {
      logger_->info("{} client reading result", func_name);
      // find the result in the shared memory
      const IPCResultPair result_pair =
        shared_mem_->find<IPCResult>(kResultName);
      const bool result_found =
        result_pair.second == 1 && result_pair.first != nullptr;
      if (result_found) {
        res.results[task_index] = CreatePodResult(*result_pair.first);
        if (!result_pair.first->common_execution_status) {
          logger_->error("{} error: {}", func_name,
                         result_pair.first->err_string.c_str());
        }
        shared_mem_->destroy<IPCParam>(kParamName);
        shared_mem_->destroy<IPCResult>(kResultName);
        continue;
      }
      // if result not found
      shared_mem_->destroy<IPCParam>(kParamName);
      logger_->error("{} result not found", func_name);
      res.results[task_index] = nullptr;
    } catch (const boost::interprocess::interprocess_exception& ex) {
      logger_->error("{} {}", func_name, ex.what());
      res.results[task_index] = nullptr;
    }
  }
  PostExitCommand();
  return res;
}

// NOLINTEND(cppcoreguidelines-pro-type-vararg,hicpp-vararg,-warnings-as-errors)

// NOLINTBEGIN(cppcoreguidelines-owning-memory)

/// @brief convert the IPCResult to usual c_bridge::CPodResult
c_bridge::CPodResult* IpcClient::CreatePodResult(const IPCResult& ipc_res) {
  auto* res = new c_bridge::CPodResult{};
  res->p_stor = new c_bridge::BridgeObjStorage;
  c_bridge::BridgeObjStorage& storage = *res->p_stor;
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
  std::copy(ipc_res.user_certificate_list_json.cbegin(),
            ipc_res.user_certificate_list_json.cend(),
            std::back_inserter(storage.user_certificate_list_json));
  // signature create result
  std::copy(ipc_res.signature_raw.cbegin(), ipc_res.signature_raw.cend(),
            std::back_inserter(storage.raw_signature));
  // err sring
  std::copy(ipc_res.err_string.cbegin(), ipc_res.err_string.cend(),
            std::back_inserter(storage.err_string));
  res->common_execution_status = ipc_res.common_execution_status;
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
  res->user_certificate_list_json = storage.user_certificate_list_json.c_str();
  res->cert_public_key = storage.cert_public_key.data();
  res->cert_public_key_size = storage.cert_public_key.size();
  res->cert_serial = storage.cert_serial.data();
  res->cert_serial_size = storage.cert_serial.size();
  res->cert_der_encoded = storage.cert_der_encoded.data();
  res->cert_der_encoded_size = storage.cert_der_encoded.size();
  res->raw_signature = storage.raw_signature.data();
  res->raw_signature_size = storage.raw_signature.size();
  res->err_string = storage.err_string.c_str();
  res->signers_time = ipc_res.signers_time;
  res->cert_not_before = ipc_res.cert_not_before;
  res->cert_not_after = ipc_res.cert_not_after;
  res->signers_cert_version = ipc_res.signers_cert_version;
  res->signers_cert_key_usage = ipc_res.signers_cert_key_usage;
  res->current_signer_index = ipc_res.current_signer_index;
  res->total_signers = ipc_res.total_signers;
  res->message_is_attached = ipc_res.message_is_attached;
  return res;
}

// NOLINTEND(cppcoreguidelines-owning-memory)

}  // namespace pdfcsp::ipc_bridge