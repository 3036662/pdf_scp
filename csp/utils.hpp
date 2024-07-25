#pragma once

#include "message.hpp"
#include "resolve_symbols.hpp"
#include <sstream>
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

// TODO(Oleg) consider implementing a low-level function to decode asn name
// string, because of errors in dl_CertNameToStrA
[[nodiscard]] std::optional<std::string>
NameBlobToString(CERT_NAME_BLOB *ptr_name_blob,
                 const PtrSymbolResolver &symbols) noexcept;

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

/**
 * @brief Convert CadesType enum to int constant like CADES_BES, etc.
 * @param type
 * @return int
 * @throws runtime_error if type is unknown
 */
int InternalCadesTypeToCspType(CadesType type);

/**
 * @brief Find index of CONTENT object in a root signature ASN object
 *
 * @param sig_obj Root signature ASN obj
 * @return uint64_t the index of "content"
 * @throw runtime_error on fail
 */
uint64_t FindSigContentIndex(const AsnObj &sig_obj);

/**
 * @brief Find a SignerInfos node index in a SignedData node
 * @param signed_data ASN obj
 * @return uint64_t index of SignerInfos
 * @throws runtime_error on fail
 */
uint64_t FindSignerInfosIndex(const AsnObj &signed_data);

} // namespace pdfcsp::csp