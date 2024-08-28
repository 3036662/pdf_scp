
#include "c_interface.hpp"
#include "check_result.hpp"
#include "csp.hpp"
#include "obj_storage.hpp"
#include "structs.hpp"
#include <algorithm>
#include <cstdint>
#include <ctime>
#include <exception>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <vector>

namespace pdfcsp::poppler {

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

PodResult *GetSigInfo(PodParam params) {
  if (params.byte_range_arr == nullptr || params.byte_ranges_size == 0 ||
      params.raw_signature_data == nullptr || params.raw_signature_size == 0 ||
      params.file_path == nullptr || params.file_path_size == 0) {
    return nullptr;
  }
  // create a byterange
  if (params.byte_ranges_size % 2 != 0) {
    std::cerr << "[pfdcsp] ByteRanges array size is not even\n";
  }
  RangesVector byteranges;
  for (uint64_t i = 0; i < params.byte_ranges_size; i += 2) {
    byteranges.emplace_back(params.byte_range_arr[i],
                            params.byte_range_arr[i + 1]);
  }
  // read a signature data
  const BytesVector raw_sig(params.raw_signature_data,
                            params.raw_signature_data +
                                params.raw_signature_size);
  // read a raw data
  const std::string file(params.file_path, params.file_path_size);
  auto raw_data = FileToVector(file, byteranges);
  if (!raw_data || raw_data->empty()) {
    std::cerr << "[pdfcsp] Empty data read from file " << file << "\n";
    return nullptr;
  }
  csp::checks::CheckResult check_res;
  try {
    csp::Csp csp;
    const csp::PtrMsg msg = csp.OpenDetached(raw_sig);
    const csp::checks::CheckResult check_result = check_res =
        msg->ComprehensiveCheck(raw_data.value(), 0, true);
  } catch (const std::exception &ex) {
    std::cerr << ex.what() << "\n";
    return nullptr;
  }
  // NOLINTBEGIN(cppcoreguidelines-owning-memory)
  //  TODO(Oleg) create a pod result from checkResult
  auto *pres = new PodResult;
  pres->p_stor = new ObjStorage();
  ObjStorage &storage = *pres->p_stor;
  // NOLINTEND(cppcoreguidelines-owning-memory)
  // signature status
  if (check_res.check_summary) {
    pres->signature_val_status = SigStatus::Valid;
  } else if (!check_res.data_hash_ok) {
    pres->signature_val_status = SigStatus::DigestMismatch;
  } else {
    pres->signature_val_status = SigStatus::Invalid;
  }
  // cert status
  if (check_res.certificate_ok) {
    pres->certificate_val_status = CertStatus::Trusted;
  } else if (!check_res.certificate_time_ok) {
    pres->certificate_val_status = CertStatus::Expired;
  } else if (!check_res.certificate_chain_ok) {
    pres->certificate_val_status = CertStatus::UntrustedIssuer;
  } else if (!check_res.certificate_ocsp_ok &&
             !check_res.certificate_ocsp_check_failed &&
             check_res.ocsp_online_used) {
    pres->certificate_val_status = CertStatus::Revoked;
  } else {
    pres->certificate_val_status = CertStatus::GenericError;
  }
  // cert_info
  // common name
  storage.issuer_common_name = check_res.cert_issuer.commonName.value_or("");
  pres->issuer_common_name = storage.issuer_common_name.c_str();
  // email
  storage.issuer_email = check_res.cert_issuer.emailAddress.value_or("");
  pres->issuer_email = storage.issuer_email.c_str();
  // organization
  storage.issuer_organization =
      check_res.cert_issuer.organizationName.value_or("");
  pres->issuer_organization = storage.issuer_organization.c_str();
  // distinguished name
  storage.issuer_distinguished_name = check_res.cert_issuer.DistinguishedName();
  pres->issuer_distinguished_name = storage.issuer_distinguished_name.c_str();
  // subject
  storage.subj_common_name = check_res.cert_subject.commonName.value_or("");
  pres->subj_common_name = storage.subj_common_name.c_str();
  storage.subj_distinguished_name = check_res.cert_subject.DistinguishedName();
  pres->subj_distinguished_name = storage.subj_distinguished_name.c_str();
  storage.subj_email = check_res.cert_subject.emailAddress.value_or("");
  pres->subj_email = storage.subj_email.c_str();
  storage.subj_organization =
      check_res.cert_subject.organizationName.value_or("");
  pres->subj_organization = storage.subj_organization.c_str();
  // public key
  storage.public_key = check_res.cert_public_key;
  pres->public_key = storage.public_key.data();
  pres->public_key_size = storage.public_key.size();
  pres->public_key_type = PublicKeyType::OTHERKEY;
  // notBefore and not After
  pres->not_before = check_res.cert_not_before;
  pres->not_after = check_res.cert_not_after;
  // cert serial
  storage.cert_serial = check_res.cert_serial;
  pres->cert_serial = storage.cert_serial.data();
  pres->cert_serial_size = storage.cert_serial.size();
  // cert_der
  // TODO(Oleg) skipped, find out if he is needed or not
  // cert_nick
  // TODO(Oleg) skipped, find out if he is needed or not
  // ku_extensions skipped, find out what exactly should be passed
  // key location
  // cert-version and self-signed skipped
  pres->key_location = KeyLocation::Unknown;
  // signers_name
  pres->signers_name = storage.subj_common_name.c_str();
  pres->signer_subject_dn = storage.subj_distinguished_name.c_str();
  // hash algo
  pres->hash_algorithm = check_res.hashing_oid == "1.2.643.7.1.1.2.2"
                             ? HashAlgorithm::GOST_R3411_12_256
                             : HashAlgorithm::Unknown;
  // signing time
  {
    std::vector<time_t> tmp;
    std::copy(check_res.times_collection.cbegin(),
              check_res.times_collection.cend(), std::back_inserter(tmp));
    std::copy(check_res.x_times_collection.cbegin(),
              check_res.x_times_collection.cend(), std::back_inserter(tmp));
    auto max_el = std::max_element(tmp.cbegin(), tmp.cend());
    if (max_el != tmp.cend()) {
      pres->signing_time = *max_el;
    } else {
      pres->signing_time = check_res.signers_time;
    }
  }
  // signature
  storage.signature = check_res.encrypted_digest;
  pres->signature = storage.signature.data();
  pres->signature_size = storage.signature.size();
  return pres;
}

void FreeResult(PodResult *p_res) {
  // NOLINTBEGIN(cppcoreguidelines-owning-memory)
  delete (p_res->p_stor);
  delete (p_res);
  // NOLINTEND(cppcoreguidelines-owning-memory)
}

} // namespace pdfcsp::poppler