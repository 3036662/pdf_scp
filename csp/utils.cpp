#include "utils.hpp"
#include "cades.h"
#include "message.hpp"
#include "resolve_symbols.hpp"
#include <cstdint>
#include <exception>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <limits>
#include <memory>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <vector>

namespace pdfcsp::csp {

std::vector<unsigned char> CreateBuffer(size_t size) {
  std::vector<unsigned char> res;
  if (size > res.max_size()) {
    throw std::logic_error("Can't reserve a buffer, size > max_size");
  }
  res.reserve(size + 1);
  return res;
}

std::optional<std::vector<unsigned char>>
IntBlobToVec(const CRYPT_INTEGER_BLOB *p_blob) noexcept {
  if (p_blob == nullptr || p_blob->cbData <= 0 || p_blob->cbData > 0x7FFFFFFF) {
    return std::nullopt;
  }
  std::vector<unsigned char> res;
  const DWORD index_last = p_blob->cbData - 1;
  for (int64_t i = static_cast<int>(index_last); i >= 0; --i) {
    // NOLINTNEXTLINE (cppcoreguidelines-pro-bounds-pointer-arithmetic)
    res.push_back(p_blob->pbData[i]);
  }
  if (res.empty()) {
    return std::nullopt;
  }
  return res;
}

std::string
VecBytesStringRepresentation(const std::vector<unsigned char> &vec) noexcept {
  std::stringstream builder;
  for (const auto symbol : vec) {
    builder << std::hex << static_cast<int>(symbol);
  }
  return builder.str();
}

// throw exception if FALSE
void ResCheck(BOOL res, const std::string &msg,
              const PtrSymbolResolver &symbols) {
  if (res != TRUE) {
    std::stringstream string_builder;
    string_builder << msg << " error " << std::hex
                   << symbols->dl_GetLastError();
    throw std::runtime_error(string_builder.str());
  }
}

[[nodiscard]] std::optional<std::string>
NameBlobToString(CERT_NAME_BLOB *ptr_name_blob,
                 const PtrSymbolResolver &symbols) noexcept {
  if (ptr_name_blob == nullptr || !symbols) {
    return std::nullopt;
  }
  const DWORD dw_size = symbols->dl_CertNameToStrA(
      X509_ASN_ENCODING, ptr_name_blob, CERT_X500_NAME_STR, nullptr, 0);
  // std::cout << "DECODED numb=" << dw_size << "\n";
  if (dw_size == 0 || dw_size > std::numeric_limits<unsigned int>::max()) {
    return std::nullopt;
  }
  try {
    auto tmp_buff = CreateBuffer(dw_size);
    // NOLINTNEXTLINE (cppcoreguidelines-pro-type-reinterpret-cast)
    char *ptr_buff_raw = reinterpret_cast<char *>(tmp_buff.data());
    const DWORD resSize = symbols->dl_CertNameToStrA(
        X509_ASN_ENCODING, ptr_name_blob, CERT_X500_NAME_STR, ptr_buff_raw,
        dw_size); // NOLINT
    if (resSize == 0) {
      return std::nullopt;
    }
    std::string buff;
    // NOLINTNEXTLINE (cppcoreguidelines-pro-bounds-pointer-arithmetic)
    std::copy(tmp_buff.data(), tmp_buff.data() + resSize - 1,
              std::back_inserter(buff));
    tmp_buff.clear();
    return buff;
  } catch (const std::exception &) {
    return std::nullopt;
  }
  return std::nullopt;
}

// read file to vector
std::optional<std::vector<unsigned char>>
FileToVector(const std::string &path) noexcept {
  namespace fs = std::filesystem;
  if (path.empty() || !fs::exists(path)) {
    return std::nullopt;
  }
  std::ifstream file(path, std::ios_base::binary);
  if (!file.is_open()) {
    return std::nullopt;
  }
  std::vector<unsigned char> res;
  try {
    std::vector<unsigned char> tmp((std::istream_iterator<unsigned char>(file)),
                                   std::istream_iterator<unsigned char>());
    res = std::move(tmp);
  } catch ([[maybe_unused]] const std::exception &ex) {
    file.close();
    return std::nullopt;
  }
  file.close();
  return res;
}

/**
 * @brief Get the CSP Provider Type
 * @param hashing_algo
 * @return unsigned long aka HCRYPTPROV
 * @throws runtime_error for an unknown algorithm
 */
uint64_t GetProviderType(const std::string &hashing_algo) {
  if (hashing_algo == szOID_CP_GOST_R3411_12_256) {
    return PROV_GOST_2012_256;
  }
  throw std::runtime_error("[GetProviderType] Unknown hashing algorithm");
}

/**
 * @brief Get the Hash Calc Type object
 * @param hashing_algo
 * @return unsigned int aka ALG_ID
 * @throws runtime_error for an unknown algo
 */
unsigned int GetHashCalcType(const std::string &hashing_algo) {
  if (hashing_algo == szOID_CP_GOST_R3411_12_256) {
    return CALG_GR3411_2012_256;
  }
  throw std::runtime_error("[GetHashCalcType] Unknown hashing algorithm");
}

/**
 * @brief Convert CadesType enum to int constant like CADES_BES, etc.
 * @param type
 * @return int
 * @throws runtime_error if type is unknown
 */
int InternalCadesTypeToCspType(CadesType type) {
  switch (type) {
  case CadesType::kUnknown:
    throw std::runtime_error("Unknowdn cades type");
    break;
  case CadesType::kCadesBes:
    return CADES_BES;
    break;
  case CadesType::kCadesT:
    return CADES_T;
    break;
  case CadesType::kCadesXLong1:
    return CADES_X_LONG_TYPE_1;
    break;
  case CadesType::kPkcs7:
    return PKCS7_TYPE;
    break;
  }
  return 0;
}

} // namespace pdfcsp::csp