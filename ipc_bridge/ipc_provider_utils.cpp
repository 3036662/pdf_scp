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
#include <cstdint>
#include <ctime>
#include <exception>
#include <filesystem>
#include <fstream>
#include <ios>
#include <iterator>
#include <limits>
#include <optional>
#include <stdexcept>
#include <string>

#include "altcsp.hpp"
#include "bool_results.hpp"
#include "check_result.hpp"
#include "common_defs.hpp"
#include "common_utils.hpp"
#include "ipc_bridge/ipc_result.hpp"
#include "typedefs.hpp"
#include "utils.hpp"
#include "utils_cert.hpp"

namespace {

pdfcsp::csp::CadesType ParseCadesType(const std::string &cades_type_str) {
  pdfcsp::csp::CadesType res = pdfcsp::csp::CadesType::kUnknown;
  if (cades_type_str == "CADES_BES") {
    res = pdfcsp::csp::CadesType::kCadesBes;
  } else if (cades_type_str == "CADES_T") {
    res = pdfcsp::csp::CadesType::kCadesT;
  } else if (cades_type_str == "CADES_XLT1") {
    res = pdfcsp::csp::CadesType::kCadesXLong1;
  }
  return res;
}

/// @brief copy csp::checks::CheckResult to IPCResult
/// @param [in] check_result
/// @param [out] IPCResult
void CheckResultToIpcResult(
  const pdfcsp::csp::checks::CheckResult &check_result,
  pdfcsp::ipc_bridge::IPCResult &res) {
  // fill the IPCResult
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
  if (check_result.total_signers > 1) {
    res.err_string = "TOO_MUCH_SIGNERS";
  }
  res.current_signer_index = check_result.current_signer_index;
  res.total_signers = check_result.total_signers;
}

pdfcsp::csp::BytesVector ReadAnDecodeSigFile(
  const pdfcsp::ipc_bridge::IPCParam &params) {
  // read a signature data
  pdfcsp::csp::BytesVector raw_sig;
  std::string sig_file_path;
  std::copy(params.sig_file_path.cbegin(), params.sig_file_path.cend(),
            std::back_inserter(sig_file_path));
  std::optional<pdfcsp::csp::BytesVector> opt_sig_data;
  // just copy from params
  if (!params.raw_signature_data.empty()) {
    // TODO(Oleg) handle a base64 encoded data
    std::copy(params.raw_signature_data.cbegin(),
              params.raw_signature_data.cend(), std::back_inserter(raw_sig));
  }
  // read from file
  else {
    if (pdfcsp::csp::Csp::IsBase64Encoded(sig_file_path)) {
      opt_sig_data = pdfcsp::csp::DecodeBase64CMS(sig_file_path);
    } else {
      opt_sig_data = pdfcsp::utils::FileToVector(sig_file_path);
    }
    if (!opt_sig_data) {
      throw std::runtime_error("[IPCProvider] Error reading data from " +
                               sig_file_path);
    }
    raw_sig = std::move(opt_sig_data.value());
  }
  return raw_sig;
}

}  // namespace

namespace pdfcsp::ipc_bridge {

using RangesVector = std::vector<std::pair<uint64_t, uint64_t>>;

/**
 * @brief Fill all results for detached message check (PDF with byteranges)
 * @param params (IPCParam)
 * @param res (IPCResult)
 */
void CheckDetachedWithByteRanges(const IPCParam &params, IPCResult &res) {
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
  auto logger = logger::InitLog();
  if (logger) {
    logger->info(check_result.Str());
  }
  CheckResultToIpcResult(check_result, res);
}

/**
 * @brief Fill all results for detached message check
 * @param params (IPCParam)
 * @param [out] res (IPCResult)
 * @details params.sig_file_path or params.raw_signature_data must be set
 * @details params.file_path must be set
 * @details if using raw_signature_data it must be ASN1 encoded
 */
void CheckSimpleDetached(const IPCParam &params, IPCResult &res) {
  if ((params.raw_signature_data.empty() && params.sig_file_path.empty()) ||
      params.file_path.empty()) {
    throw std::invalid_argument(
      "[IPCProvider][CheckSimpleDetached] error,empty arguments");
  }
  auto raw_sig = ReadAnDecodeSigFile(params);
  // read file
  std::string file_path;
  std::copy(params.file_path.cbegin(), params.file_path.cend(),
            std::back_inserter(file_path));
  auto raw_data = pdfcsp::utils::FileToVector(file_path);
  if (!raw_data) {
    throw std::runtime_error("[IPCProvider] Error reading data from " +
                             file_path);
  }
  // get the CheckResult
  csp::Csp csp;
  const csp::PtrMsg msg = csp.OpenDetached(raw_sig);
  const csp::checks::CheckResult check_result =
    msg->ComprehensiveCheck(raw_data.value(), 0, true);
  auto logger = logger::InitLog();
  if (logger) {
    logger->info(check_result.Str());
  }
  CheckResultToIpcResult(check_result, res);
}

void CheckSimpleAttached(const IPCParam &params, IPCResult &res) {
  if (params.raw_signature_data.empty() && params.sig_file_path.empty()) {
    throw std::invalid_argument(
      "[IPCProvider][CheckSimpleAttached] error,empty arguments");
  }
  auto raw_sig = ReadAnDecodeSigFile(params);
  csp::Csp csp;
  const csp::PtrMsg msg = csp.OpenAttached(raw_sig);
  const csp::checks::CheckResult check_result =
    msg->ComprehensiveCheckAttached(0, true);
  auto logger = logger::InitLog();
  if (logger) {
    logger->info(check_result.Str());
  }
  CheckResultToIpcResult(check_result, res);
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
  csp::CadesType cades_type = ParseCadesType(cades_type_str);
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

/**
 * @brief Check if the message is attached
 * @param params (IPCParam)
 * @param res (IPCResult)
 * @details fills only message_is_attached,common_execution_status
 * @throws std::runtime_error propagated from csp::Csp::IsAttached
 */
void FillCheckIfAttached(const IPCParam &params, IPCResult &res) {
  try {
    const std::string filename = params.sig_file_path.c_str();
    res.message_is_attached = csp::Csp::IsAttached(filename);
    res.common_execution_status = true;
  } catch (const std::exception &ex) {
    res.err_string = ex.what();
    std::cerr << "[FillCheckIfAttached] error " << ex.what() << "\n";
    throw;
  }
}

/**
 * @brief Extracts the attached file
 *
 * @param params.sig_file_path  - path to an attached signature
 * @param params.file_path  - path to a destination file
 * @return res.common_execution_status == true on success
 */
void ExtractFileFromAttached(const IPCParam &params, IPCResult &res) {
  constexpr const char *func_name = "[ExtractFileFromAttached] ";
  try {
    if (params.file_path.empty()) {
      throw std::invalid_argument("Empty Desination");
    }
    if (params.sig_file_path.empty()) {
      throw std::invalid_argument("Empty signature path");
    }
    const std::string filename = params.sig_file_path.c_str();
    std::optional<csp::BytesVector> sig_data;
    if (csp::Csp::IsBase64Encoded(filename)) {
      sig_data = (csp::DecodeBase64CMS(filename));
    } else {
      sig_data = utils::FileToVector(filename);
    }
    if (!sig_data) {
      throw std::runtime_error("Read file failed");
    }
    csp::Csp csp;
    const auto message = csp.OpenAttached(sig_data.value());
    if (!message) {
      throw std::runtime_error("Decode message failed");
    }
    auto file_data = message->GetContentFromAttached();
    if (file_data.empty()) {
      throw std::runtime_error("Empty data extracted");
    }
    std::ofstream file(params.file_path.c_str(), std::ios_base::binary);
    if (!file.is_open()) {
      throw std::runtime_error("Create file error");
    }
    if (file_data.size() > std::numeric_limits<int64_t>::max()) {
      throw std::runtime_error("File data is too big");
    }
    file.write(reinterpret_cast<const char *>(file_data.data()),  // NOLINT
               static_cast<int64_t>(file_data.size()));
    file.close();
    res.common_execution_status = true;
  } catch (const std::exception &ex) {
    res.err_string = ex.what();
    std::cerr << func_name << "error " << ex.what() << "\n";
    throw;
  }
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

/**
 * @brief Create a Signature
 *
 * @param [in] params.file_path a source file
 * @param [in] params.sig_file_path a destination file
 * @param [in] params.cert_subject a ceritificate subject common name
 * @param [in] params.cert_serial a ceritificate serial (lowercase)
 * @param [in] params.cades_type  "CADES_BES" | "CADES_T" |  "CADES_XLT1"
 * @param [in] params.tsp_link TSP service URL
 * @param [in] params.create_attached attached if true
 * @param [in] params.create_base_64_encoded base64 encoded if true
 * @param [out] res.common_execution_status == true on success
 */
void CreateSignatureFile(const IPCParam &params, IPCResult &res) {
  if (params.file_path.empty() || params.sig_file_path.empty() ||
      params.cert_subject.empty() || params.cert_serial.empty() ||
      params.cades_type.empty()) {
    return;
  }
  csp::Csp csp;
  // tsp url
  std::wstring tsp_url;
  {
    std::string tsp_url_temp;
    std::copy(params.tsp_link.cbegin(), params.tsp_link.cend(),
              std::back_inserter(tsp_url_temp));
    std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
    tsp_url = converter.from_bytes(tsp_url_temp);
  }
  const bool result = csp.CreateSigFile(
    params.cert_serial.c_str(), params.cert_subject.c_str(),
    params.create_attached ? csp::MessageType::kAttached
                           : csp::MessageType::kDetached,
    ParseCadesType(params.cades_type.c_str()), params.file_path.c_str(), params.sig_file_path.c_str(),
    tsp_url,
    params.create_base_64_encoded ? csp::MessageEncoding::kBase64
                                  : csp::MessageEncoding::kAsn1);
  res.common_execution_status = result;
}

}  // namespace pdfcsp::ipc_bridge
