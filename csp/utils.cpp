#include "utils.hpp"
#include "CSP_WinCrypt.h"
#include "asn1.hpp"
#include "cades.h"
#include "cms.hpp"
#include "resolve_symbols.hpp"
#include "typedefs.hpp"
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <exception>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <limits>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <utility>
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

void PrintBytes(const BytesVector &val) noexcept {
  for (const auto &symbol : val) {
    std::cout << std::hex << std::setw(2) << static_cast<int>(symbol) << " ";
  }
  std::cout << "\n";
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

// TODO(Oleg) consider implementing a low-level function to decode asn name
// string, because of errors in dl_CertNameToStrA
[[nodiscard]] std::optional<std::string>
NameBlobToString(CERT_NAME_BLOB *ptr_name_blob,
                 const PtrSymbolResolver &symbols) noexcept {
  if (ptr_name_blob == nullptr || !symbols) {
    return std::nullopt;
  }
  const DWORD dw_size = symbols->dl_CertNameToStrA(
      X509_ASN_ENCODING, ptr_name_blob, CERT_X500_NAME_STR, nullptr, 0);
  if (dw_size == 0 || dw_size > std::numeric_limits<unsigned int>::max()) {
    return std::nullopt;
  }
  try {
    auto tmp_buff = CreateBuffer(dw_size);
    tmp_buff.resize(dw_size, 0x00);
    //  NOLINTNEXTLINE (cppcoreguidelines-pro-type-reinterpret-cast)
    char *ptr_buff_raw = reinterpret_cast<char *>(tmp_buff.data());
    const DWORD resSize =
        symbols->dl_CertNameToStrA(X509_ASN_ENCODING, ptr_name_blob,
                                   CERT_X500_NAME_STR, ptr_buff_raw, dw_size);
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

[[nodiscard]] std::optional<std::string>
NameRawToString(BytesVector data, const PtrSymbolResolver &symbols) noexcept {
  CERT_NAME_BLOB blob{};
  blob.cbData = data.size();
  blob.pbData = data.data();
  return NameBlobToString(&blob, symbols);
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
  if (hashing_algo == szOID_CP_GOST_R3411_12_256 || hashing_algo == "SHA1") {
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
  if (hashing_algo == "SHA1") {
    return CALG_SHA1;
  }
  throw std::runtime_error("[GetHashCalcType] Unknown hashing algorithm");
}

/**
 * @brief Parse a GeneralizedTime (20240716145051Z)
 * @return ParsedTime
 * @throws runtime_error
 */
ParsedTime GeneralizedTimeToTimeT(const std::string &val) {
  std::tm time = {};
  std::istringstream strs(val);
  strs >> std::get_time(&time, "%Y%m%d%H%M%S");
  if (strs.fail()) {
    throw std::runtime_error("Failed to parse date and time");
  };
  const std::time_t time_stamp = mktime(&time);
  if (time_stamp == std::numeric_limits<int64_t>::max()) {
    throw std::runtime_error("Failed to parse date and time");
  }
  return {time_stamp, time.tm_gmtoff};
}

/**
 * @brief Convert FILETIME to time_t
 * @return std::time_t
 */
std::time_t FileTimeToTimeT(const FILETIME &val) noexcept {
  // Convert FILETIME to ULARGE_INTEGER
  const uint64_t filetime_as_int =
      ((static_cast<uint64_t>(val.dwHighDateTime) << 32) | val.dwLowDateTime);
  const uint64_t epoch_diff = 11644473600ULL; // epoch diff
  return static_cast<std::time_t>((filetime_as_int / 10000000ULL) - epoch_diff);
}

/**
 * @brief replace (draft) for dl_CertNameToStrA and NameBlobToStr
 * @details CertNameToStr gives valgrind errors
 * @param ptr_data pointer to data
 * @param size of data
 * @return std::optional<std::string>
 */
[[nodiscard]] std::optional<std::string>
NameBlobToStringEx(const unsigned char *ptr_data, size_t size) noexcept {
  if (ptr_data == nullptr || size == 0) {
    return std::nullopt;
  }
  try {
    const asn::AsnObj obj(ptr_data, size);
    if (obj.Size() == 0) {
      return std::nullopt;
    }
    asn::RelativeDistinguishedName seq;
    for (const auto &child : obj.Childs()) {
      seq.emplace_back(child.at(0));
    }
    std::string res;
    // TODO(Oleg) parse OIDs OGRN,INN, etc.
    for (const auto &val : seq) {
      res += val.val;
      res += ", ";
    }
    if (res.size() > 2) {
      res.erase(res.size() - 2, 2);
    }
    return res;
  } catch (const std::exception &ex) {
    std::cerr << "[NameBlobToStringEx] " << ex.what() << "\n";
    return std::nullopt;
  }
  return std::nullopt;
}

} // namespace pdfcsp::csp