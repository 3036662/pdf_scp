#pragma once

#include "asn1.hpp"
#include "common_defs.hpp"
#include "resolve_symbols.hpp"
#include "typedefs.hpp"
#include <cstdint>
#include <ctime>
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Winvalid-utf8"
#include <CSP_WinCrypt.h> /// NOLINT
#pragma GCC diagnostic pop

#include <optional>
#include <string>
#include <vector>

namespace pdfcsp::csp {

/**
 * @brief Create a Buffer object
 *
 * @param size
 * @return std::vector<unsigned char>
 * @throws logic_error if size>max_size
 */
std::vector<unsigned char> CreateBuffer(size_t size);

/**
 * @brief Copy little-endian blob to flat vector
 *
 * @param p_blob
 * @return std::optional<std::vector<unsigned char>>
 */
std::optional<std::vector<unsigned char>>
IntBlobToVec(const CRYPT_INTEGER_BLOB *p_blob) noexcept;

// throw exception if FALSE
void ResCheck(BOOL res, const std::string &msg,
              const PtrSymbolResolver &symbols);

std::string
VecBytesStringRepresentation(const std::vector<unsigned char> &vec) noexcept;

void PrintBytes(const BytesVector &val) noexcept;

// TODO(Oleg) consider implementing a low-level function to decode asn name
// string, because of errors in dl_CertNameToStrA
[[nodiscard]] std::optional<std::string>
NameBlobToString(CERT_NAME_BLOB *ptr_name_blob,
                 const PtrSymbolResolver &symbols) noexcept;

[[nodiscard]] std::optional<std::string>
NameRawToString(BytesVector data, const PtrSymbolResolver &symbols) noexcept;

std::optional<std::vector<unsigned char>>
FileToVector(const std::string &path) noexcept;

/**
 * @brief Get the CSP Provider Type
 * @param hashing_algo
 * @return unsigned long aka HCRYPTPROV
 * @throws runtime_error for an unknown algorithm
 */
uint64_t GetProviderType(const std::string &hashing_algo);

/**
 * @brief Get the Hash Calc Type object
 * @param hashing_algo
 * @return unsigned int aka ALG_ID
 * @throws runtime_error for an unknown algo
 */
unsigned int GetHashCalcType(const std::string &hashing_algo);

struct ParsedTime {
  time_t time;
  int64_t gmt_offset;
};

/**
 * @brief Parse a GeneralizedTime (20240716145051Z)
 * @return ParsedTime
 * @throws runtime_error
 */
ParsedTime GeneralizedTimeToTimeT(const std::string &val);

/**
 * @brief Parse a UTCTime (220625210000Z)
 * @return ParsedTime
 * @throws runtime_error
 */
ParsedTime UTCTimeToTimeT(std::string val);

/**
 * @brief Convert FILETIME to time_t
 * @return std::time_t
 */
std::time_t FileTimeToTimeT(const FILETIME &val) noexcept;

/**
 * @brief Converts time_t to FILETIME
 * @param val time_t
 * @return FILETIME
 */
FILETIME TimetToFileTime(time_t val) noexcept;

std::string TimeTToString(time_t time) noexcept;

/**
 * @brief replace (draft) for dl_CertNameToStrA and NameBlobToStr
 * @details CertNameToStr gives valgrind errors
 * @param ptr_data pointer to data
 * @param size of data
 * @return std::optional<std::string>
 */
[[nodiscard]] std::optional<std::string>
NameBlobToStringEx(const unsigned char *ptr_data, size_t size) noexcept;

std::optional<std::string> NameBlobToStringEx(const asn::AsnObj &obj) noexcept;

bool IsHashAlgoSupported(const std::string &oid) noexcept;

} // namespace pdfcsp::csp