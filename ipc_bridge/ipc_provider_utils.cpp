/* File: ipc_provider_utils.cpp
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

#include "ipc_provider_utils.hpp"

#include <algorithm>
#include <boost/json/serialize.hpp>
#include <ctime>
#include <exception>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <stdexcept>
#include <string>

#include "altcsp.hpp"
#include "bool_results.hpp"
#include "check_result.hpp"
#include "common/common_defs.hpp"
#include "ipc_bridge/ipc_result.hpp"
#include "typedefs.hpp"
#include "utils_cert.hpp"

namespace pdfcsp::ipc_bridge {

using RangesVector = std::vector<std::pair<uint64_t, uint64_t>>;

/**
 * @brief Fill all results for message check
 * @param params (IPCParam)
 * @param res (IPCResult)
 */
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
  auto logger = logger::InitLog();
  if (logger) {
    logger->info(check_result.Str());
  }
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
  std::copy(check_result.cert_der_encoded.cbegin(),
            check_result.cert_der_encoded.cend(),
            std::back_inserter(res.cert_der_encoded));

  if (check_result.cert_issuer.commonName.has_value()) {
    std::copy(check_result.cert_issuer.commonName.value().cbegin(),
              check_result.cert_issuer.commonName.value().cend(),
              std::back_inserter(res.issuer_common_name));
  }
  if (check_result.cert_issuer.emailAddress.has_value()) {
    std::copy(check_result.cert_issuer.emailAddress.value().cbegin(),
              check_result.cert_issuer.emailAddress.value().cend(),
              std::back_inserter(res.issuer_email));
  }
  if (check_result.cert_issuer.organizationName.has_value()) {
    std::copy(check_result.cert_issuer.organizationName.value().cbegin(),
              check_result.cert_issuer.organizationName.value().cend(),
              std::back_inserter(res.issuer_organization));
  }

  if (check_result.cert_subject.commonName.has_value()) {
    std::copy(check_result.cert_subject.commonName.value().cbegin(),
              check_result.cert_subject.commonName.value().cend(),
              std::back_inserter(res.subj_common_name));
  }
  if (check_result.cert_subject.emailAddress.has_value()) {
    std::copy(check_result.cert_subject.emailAddress.value().cbegin(),
              check_result.cert_subject.emailAddress.value().cend(),
              std::back_inserter(res.subj_email));
  }
  if (check_result.cert_subject.organizationName.has_value()) {
    std::copy(check_result.cert_subject.organizationName.value().cbegin(),
              check_result.cert_subject.organizationName.value().cend(),
              std::back_inserter(res.subj_organization));
  }
  // signer's certificate chain
  std::copy(check_result.signers_chain_json.cbegin(),
            check_result.signers_chain_json.cend(),
            std::back_inserter(res.signers_chain_json));
  // TSP json info
  std::copy(check_result.tsp_json_info.cbegin(),
            check_result.tsp_json_info.cend(),
            std::back_inserter(res.tsp_json_info));
  // OCSP json info
  std::copy(check_result.signers_cert_ocsp_json_info.cbegin(),
            check_result.signers_cert_ocsp_json_info.cend(),
            std::back_inserter(res.signers_cert_ocsp_json_info));

  res.signers_time = check_result.signers_time;
  res.cert_not_before = check_result.cert_not_before;
  res.cert_not_after = check_result.cert_not_after;
  res.signers_cert_version = check_result.signers_cert_version;
  res.signers_cert_key_usage = check_result.signers_cert_key_usage;
  res.common_execution_status = true;
}

/**
 * @brief Fill only user_certifitate_list_json
 * @param params (IPCParam.command should be "user_cert_list")
 * @param res (IPCResult)
 */
void FillCertListResult(const IPCParam &, IPCResult &res) {
  csp::Csp csp;
  auto certlist = csp.GetCertList();
  auto result_json = csp::utils::cert::CertListToJSONArray(certlist);
  if (result_json && !result_json->empty()) {
    const std::string result = boost::json::serialize(*result_json);
    std::copy(result.cbegin(), result.cend(),
              std::back_inserter(res.user_certifitate_list_json));
  }
  res.common_execution_status = true;
}

/**
 * @brief Fill all results for signature creation
 * @param params (IPCParam)
 * @param res (IPCResult)
 */
void FillSignResult(const IPCParam &params, IPCResult &res) {
  // create ByteRange
  if (params.byte_range_arr.size() % 2 != 0) {
    throw std::runtime_error(
      "[IPCProvider][FillSignResult] ByteRanges array size is not even\n");
  }
  RangesVector byteranges;
  for (uint64_t i = 0; i < params.byte_range_arr.size(); i += 2) {
    byteranges.emplace_back(params.byte_range_arr[i],
                            params.byte_range_arr[i + 1]);
  }
  // read file
  std::string file_path;
  std::copy(params.file_path.cbegin(), params.file_path.cend(),
            std::back_inserter(file_path));
  auto data_for_hashing = FileToVector(file_path, byteranges);
  if (!data_for_hashing) {
    throw std::runtime_error("[IPCProvider] Error reading data from " +
                             file_path);
  }
  // cert subject
  std::string cert_subject;
  std::copy(params.cert_subject.cbegin(), params.cert_subject.cend(),
            std::back_inserter(cert_subject));
  // cert serial
  std::string cert_serial;
  std::copy(params.cert_serial.cbegin(), params.cert_serial.cend(),
            std::back_inserter(cert_serial));
  //  cades type string
  std::string cades_type_str;
  std::copy(params.cades_type.cbegin(), params.cades_type.cend(),
            std::back_inserter(cades_type_str));
  // tsp url
  std::wstring tsp_url;
  {
    std::string tsp_url_temp;
    std::copy(params.tsp_link.cbegin(), params.tsp_link.cend(),
              std::back_inserter(tsp_url_temp));
    std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
    tsp_url = converter.from_bytes(tsp_url_temp);
  }
  // parse string cades type
  csp::CadesType cades_type = csp::CadesType::kUnknown;
  if (cades_type_str == "CADES_BES") {
    cades_type = csp::CadesType::kCadesBes;
  } else if (cades_type_str == "CADES_T") {
    cades_type = csp::CadesType::kCadesT;
  } else if (cades_type_str == "CADES_XLT1") {
    cades_type = csp::CadesType::kCadesXLong1;
  }
  // create signature
  try {
    csp::Csp csp;
    auto raw_signature = csp.SignData(cert_serial, cert_subject, cades_type,
                                      data_for_hashing.value(), tsp_url);

    res.signature_raw.reserve(raw_signature.size());
    std::copy(raw_signature.cbegin(), raw_signature.cend(),
              std::back_inserter(res.signature_raw));
    res.common_execution_status = true;
  } catch (const std::exception &ex) {
    auto logger = logger::InitLog();
    if (logger) {
      logger->error("[FillSignResult] error: {}", ex.what());
    }
    res.signature_raw.clear();
    res.common_execution_status = false;
    if (std::string(ex.what()) ==
        "Csp::SignData CadesSignHash error 800b0101") {
      res.err_string = kErrExpiredCert;
    } else if (std::string(ex.what()) ==
               "Csp::SignData CadesSignHash error c2100100") {
      res.err_string = kErrMayBeTspInvalid;
    } else if (std::string(ex.what()) ==
               "Csp::SignData CadesSignHash error 800b010a") {
      res.err_string = kErrCertChaining;

    } else {
      res.err_string = ex.what();
    }
  }
}

/**
 * @brief Fill the result with no data and execution_status=false
 * @param params (IPCParam)
 * @param res (IPCResult)
 */
void FillFailResult(const std::string &error_string, IPCResult &res) {
  res.bres = csp::checks::BoolResults{};
  res.cades_type = csp::CadesType::kUnknown;
  res.cades_t_str.clear();
  res.hashing_oid.clear();
  res.encrypted_digest.clear();
  res.times_collection.clear();
  res.x_times_collection.clear();
  res.cert_issuer_dname.clear();
  res.cert_subject_dname.clear();
  res.cert_public_key.clear();
  res.cert_serial.clear();
  res.cert_der_encoded.clear();
  res.issuer_common_name.clear();
  res.issuer_email.clear();
  res.issuer_organization.clear();
  res.subj_common_name.clear();
  res.subj_email.clear();
  res.subj_organization.clear();
  res.signers_chain_json.clear();
  res.tsp_json_info.clear();
  res.signers_cert_ocsp_json_info.clear();
  res.user_certifitate_list_json.clear();
  res.signature_raw.clear();
  std::copy(error_string.cbegin(), error_string.cend(),
            std::back_inserter(res.err_string));
  res.common_execution_status = false;
}

/// @brief copy file content to vector
std::optional<std::vector<unsigned char>> FileToVector(
  const std::string &path,
  const std::vector<std::pair<uint64_t, uint64_t>> &byteranges) noexcept {
  namespace fs = std::filesystem;
  if (path.empty() || !fs::exists(path) || !fs::is_regular_file(path)) {
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
    auto logger = logger::InitLog();
    if (logger) {
      logger->error(ex.what());
    }
    file.close();
    return std::nullopt;
  }
  file.close();
  return res;
}

}  // namespace pdfcsp::ipc_bridge
