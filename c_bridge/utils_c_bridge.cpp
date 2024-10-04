#include "utils_c_bridge.hpp"
#include "bridge_obj_storage.hpp"
#include "pod_structs.hpp"
#include <cstdint>
#include <exception>
#include <filesystem>
#include <fstream>
#include <iostream>

namespace pdfcsp::c_bridge::utils {

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

// NOLINTBEGIN(cppcoreguidelines-owning-memory)
CPodResult *
PodResultFromResult(const csp::checks::CheckResult &cppres) noexcept {
  CPodResult *pres = nullptr;
  try {
    pres = new CPodResult{};
    pres->p_stor = new BrigeObjStorage();
  } catch (const std::exception &ex) {
    delete pres->p_stor;
    delete pres;
    return nullptr;
  }
  CPodResult &res = *pres;
  res.bres = cppres.bres;

  // res.cades_type = static_cast<CadesType>(cppres.cades_type);
  res.cades_type = static_cast<pdfcsp::csp::CadesType>(cppres.cades_type);
  // cades type string
  res.p_stor->cades_t_str = cppres.cades_t_str;
  res.cades_t_str = res.p_stor->cades_t_str.c_str();
  // hashing oid string
  res.p_stor->hashing_oid = cppres.hashing_oid;
  res.hashing_oid = res.p_stor->hashing_oid.c_str();
  // encrypted digest value
  res.p_stor->encrypted_digest = cppres.encrypted_digest;
  res.encrypted_digest = res.p_stor->encrypted_digest.data();
  res.encrypted_digest_size = res.p_stor->encrypted_digest.size();
  // arrays of time_t
  res.p_stor->times_collection = cppres.times_collection;
  res.times_collection = res.p_stor->times_collection.data();
  res.times_collection_size = res.p_stor->times_collection.size();
  res.p_stor->x_times_collection = cppres.x_times_collection;
  res.x_times_collection = res.p_stor->x_times_collection.data();
  res.x_times_collection_size = res.p_stor->x_times_collection.size();
  // issuer string
  res.p_stor->cert_issuer = cppres.cert_issuer.DistinguishedName();
  res.cert_issuer_dname = res.p_stor->cert_issuer.c_str();
  // subject string
  res.p_stor->cert_subject = cppres.cert_subject.DistinguishedName();
  res.cert_subject_dname = res.p_stor->cert_subject.c_str();
  // public key
  res.p_stor->cert_public_key = cppres.cert_public_key;
  res.cert_public_key = res.p_stor->cert_public_key.data();
  res.cert_public_key_size = res.p_stor->cert_public_key.size();
  // certificate serial
  res.p_stor->cert_serial = cppres.cert_serial;
  res.cert_serial = res.p_stor->cert_serial.data();
  res.cert_serial_size = res.p_stor->cert_serial.size();
  // time_t vals
  res.signers_time = cppres.signers_time;
  res.cert_not_before = cppres.cert_not_before;
  res.cert_not_after = cppres.cert_not_after;
  return pres;
}

// NOLINTEND(cppcoreguidelines-owning-memory)

} // namespace pdfcsp::c_bridge::utils