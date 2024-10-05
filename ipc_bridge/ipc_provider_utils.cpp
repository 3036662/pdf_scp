#include "ipc_provider_utils.hpp"
#include "altcsp.hpp"
#include "check_result.hpp"
#include <algorithm>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <stdexcept>

namespace pdfcsp::ipc_bridge {

using RangesVector = std::vector<std::pair<uint64_t, uint64_t>>;

void FillResult(const IPCParam &params, IPCResult &res) {
  if (params.byte_range_arr.empty() || params.raw_signature_data.empty() ||
      params.file_path.empty()) {
    throw std::invalid_argument(
        "[IPCProvider][FillResult] error,empty arguments");
  }
  // create a byterange
  if (params.byte_range_arr.size() % 2 != 0) {
    throw std::runtime_error(
        "[IPCProvider][FillResult] ByteRanges array size is not even\n");
  }
  RangesVector byteranges;
  for (uint64_t i = 0; i < params.byte_range_arr.size(); i += 2) {
    byteranges.emplace_back(params.byte_range_arr[i],
                            params.byte_range_arr[i + 1]);
  }
  // read a signature data
  csp::BytesVector raw_sig;
  std::copy(params.raw_signature_data.cbegin(),
            params.raw_signature_data.cend(), std::back_inserter(raw_sig));
  // read file
  std::string file_path;
  std::copy(params.file_path.cbegin(), params.file_path.cend(),
            std::back_inserter(file_path));
  auto raw_data = FileToVector(file_path, byteranges);
  if (!raw_data) {
    throw std::runtime_error("[IPCProvider] Error reading data from " +
                             file_path);
  }
  // get the CheckResult
  csp::Csp csp;
  const csp::PtrMsg msg = csp.OpenDetached(raw_sig);
  const csp::checks::CheckResult check_result =
      msg->ComprehensiveCheck(raw_data.value(), 0, true);
  // // fill the IPCResult
  res.bres = check_result.bres;
  res.cades_type = check_result.cades_type;
  std::copy(check_result.cades_t_str.cbegin(), check_result.cades_t_str.cend(),
            std::back_inserter(res.cades_t_str));
  std::copy(check_result.hashing_oid.cbegin(), check_result.hashing_oid.cend(),
            std::back_inserter(res.hashing_oid));
  std::copy(check_result.encrypted_digest.cbegin(),
            check_result.encrypted_digest.cend(),
            std::back_inserter(res.encrypted_digest));
  std::copy(check_result.times_collection.cbegin(),
            check_result.times_collection.cend(),
            std::back_inserter(res.times_collection));
  std::copy(check_result.x_times_collection.cbegin(),
            check_result.x_times_collection.cend(),
            std::back_inserter(res.x_times_collection));
  const std::string cert_issuer_str =
      check_result.cert_issuer.DistinguishedName();
  std::copy(cert_issuer_str.cbegin(), cert_issuer_str.cend(),
            std::back_inserter(res.cert_issuer_dname));
  const std::string cert_subject_str =
      check_result.cert_subject.DistinguishedName();
  std::copy(cert_subject_str.cbegin(), cert_subject_str.cend(),
            std::back_inserter(res.cert_subject_dname));
  std::copy(check_result.cert_public_key.cbegin(),
            check_result.cert_public_key.cend(),
            std::back_inserter(res.cert_public_key));
  std::copy(check_result.cert_serial.cbegin(), check_result.cert_serial.cend(),
            std::back_inserter(res.cert_serial));
  res.signers_time = check_result.signers_time;
  res.cert_not_before = check_result.cert_not_before;
  res.cert_not_after = check_result.cert_not_after;
}

std::optional<std::vector<unsigned char>> FileToVector(
    const std::string &path,
    const std::vector<std::pair<uint64_t, uint64_t>> &byteranges) noexcept {
  namespace fs = std::filesystem;
  if (path.empty() || !fs::exists(path)) {
    return std::nullopt;
  }
  std::ifstream file(path, std::ios_base::binary);
  if (!file.is_open()) {
    return std::nullopt;
  }
  std::vector<unsigned char> res;
  uint64_t buff_size = 0;
  for (const auto &range : byteranges) {
    buff_size += range.second;
  }
  try {
    res.reserve(buff_size);
    for (const auto &brange : byteranges) {
      if (brange.first >
          static_cast<uint64_t>(std::numeric_limits<int64_t>::max())) {
        throw std::runtime_error(
            "[FileToVector] byterange offset is > max_int64\n");
      }

      file.seekg(static_cast<int64_t>(brange.first));
      if (!file) {
        throw std::exception();
      }
      for (uint64_t i = 0; i < brange.second; ++i) {
        char symbol = 0;
        file.get(symbol);
        if (!file) {
          throw std::exception();
        }
        res.push_back(symbol);
      }
    }
  } catch ([[maybe_unused]] const std::exception &ex) {
    std::cerr << ex.what() << "\n";
    file.close();
    return std::nullopt;
  }
  file.close();
  return res;
}

} // namespace pdfcsp::ipc_bridge