#pragma once

// #include "CSP_WinDef.h"
// #pragma GCC diagnostic push
// #pragma GCC diagnostic ignored "-Winvalid-utf8"
// #include "CSP_WinCrypt.h"
// #pragma GCC diagnostic pop

#include "resolve_symbols.hpp"
#include "typedefs.hpp"
#include <bitset>
#include <cstddef>
#include <cstdint>
#include <vector>
namespace pdfcsp::csp {

enum class AsnTag : uint8_t {
  kSequenceOf,
  kSequence,
  kOid,
  kOctetString,
  kInteger,
  kUtf8String,
  kBitString,
  kNull,
  kSet,
  kSetOff,
  kPrintableString,
  kIA5String,
  kUTCTime,
  kGeneralizedTime,
  kUnknown
};
enum class AsnTagType : uint8_t {
  kUniversal,
  kApplication,
  kContentSpecific,
  kPrivate,
  kUnknown
};

/**
 * @brief ASN1 header
 * @throws runtime error on fail
 */
struct AsnHeader {
  AsnTagType tag_type = AsnTagType::kUnknown;
  AsnTag asn_tag = AsnTag::kUnknown;
  bool constructed = false;
  std::bitset<8> tag;
  uint length = 0;
  uint bytes_raw = 0;
  std::string tag_str;

  explicit AsnHeader(const unsigned char *ptr_data);

  [[nodiscard]] std::string TypeStr() const noexcept;
  [[nodiscard]] std::string ConstructedStr() const noexcept;
  [[nodiscard]] std::string TagStr() const noexcept { return tag_str; }
};

/**
 * @brief Decode an ASN object
 * @throws runtime_error on fail
 */
class AsnObj {
public:
  [[nodiscard]] AsnTag get_asn_type() const noexcept { return asn_type_; }
  [[nodiscard]] bool IsFlat() const noexcept { return is_flat_; }
  [[nodiscard]] std::size_t Size() const noexcept { return obj_vector_.size(); }

  explicit AsnObj(const unsigned char *ptr_asn, size_t size,
                  PtrSymbolResolver symbols);

private:
  // only for recursive calls
  explicit AsnObj(const unsigned char *ptr_asn, size_t size);
  [[maybe_unused]] uint64_t
  DecodeSequenceOfAny(const unsigned char *data_to_decode,
                      size_t size_to_parse);
  [[maybe_unused]] uint64_t DecodeOid(const unsigned char *data_to_decode,
                                      size_t size_to_parse);

  [[maybe_unused]] uint64_t DecodeOctetStr(const unsigned char *data_to_decode,
                                           size_t size_to_parse);

  AsnTag asn_type_ = AsnTag::kUnknown;
  bool is_flat_ = false;
  std::vector<AsnObj> obj_vector_;
  BytesVector flat_data_;
  PtrSymbolResolver symbols_;
  // unsigned int recursion_level_ = 0;
};

} // namespace pdfcsp::csp