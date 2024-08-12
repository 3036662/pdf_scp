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
#include <optional>
#include <vector>
namespace pdfcsp::csp::asn {

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
  kNumericString,
  kEnumerated,
  kUnknown
};
enum class AsnTagType : uint8_t {
  kUniversal,
  kApplication,
  kContentSpecific,
  kPrivate,
  kUnknown
};

// ----------------------------------------
/**
 * @brief ASN1 header
 * @throws runtime error on fail
 */
struct AsnHeader {
  AsnTagType tag_type = AsnTagType::kUnknown;
  AsnTag asn_tag = AsnTag::kUnknown;
  bool constructed = false;
  std::bitset<8> tag;
  uint content_length = 0;
  uint sizeof_header = 0;
  std::string tag_str;
  bool stream_encoded = false;
  BytesVector raw_header;

  AsnHeader() = default;
  explicit AsnHeader(const unsigned char *ptr_data, uint64_t data_size);

  [[nodiscard]] std::string TypeStr() const noexcept;
  [[nodiscard]] std::string ConstructedStr() const noexcept;
  [[nodiscard]] std::string TagStr() const noexcept { return tag_str; }
};

// ----------------------------------------

/**
 * @brief Decode an ASN object
 * @throws runtime_error on fail
 */
class AsnObj {
public:
  [[nodiscard]] const AsnHeader &get_asn_header() const noexcept {
    return asn_header_;
  }

  [[nodiscard]] AsnTag GetAsnTag() const noexcept {
    return asn_header_.asn_tag;
  }

  /// @brief is an object flat
  [[nodiscard]] bool IsFlat() const noexcept {
    return !asn_header_.constructed ||
           asn_header_.asn_tag == AsnTag::kOctetString;
  }

  /// @brief Get the number of children.
  [[nodiscard]] std::size_t ChildsCount() const noexcept {
    return obj_vector_.size();
  }

  /// @brief Get the underlying vector of  child objects.
  [[nodiscard]] const std::vector<AsnObj> &GetChilds() const noexcept {
    return obj_vector_;
  }

  /// @throws std::out_of_range
  [[nodiscard]] const AsnObj &at(unsigned int index) const {
    return obj_vector_.at(index);
  }

  /// @brief Get string data
  [[nodiscard]] std::optional<std::string> GetStringData() const noexcept {
    return string_data_;
  }

  /// @brief Get Decoded string data
  [[nodiscard]] std::optional<std::string>
  GetDecodedStringData() const noexcept {
    return string_decoded_;
  }

  /// @brief Get the data vector
  [[nodiscard]] const BytesVector &GetData() const noexcept {
    return flat_data_;
  }

  /// @brief unparse object to byte array
  [[nodiscard]] BytesVector Unparse() const noexcept;

  /**
   * @brief Construct a new Asn Obj object
   *
   * @param ptr_asn  a pointer to raw ASN1-encoded data
   * @param size size of data
   * @param symbols SymbolResolver
   */
  explicit AsnObj(const unsigned char *ptr_asn, size_t size);
  AsnObj() = default;

private:
  /**
   * @brief This constructor is supposed to be called only for recursive
   * construct of children   *
   * @param ptr_asn pointer to a  raw data
   * @param size size to parse
   * @param recursion_level
   * @param symbols
   * @throws std::runtime error
   */
  explicit AsnObj(const unsigned char *ptr_asn, size_t size,
                  size_t recursion_level);
  /// @brief decode any raw ASN1
  [[maybe_unused]] uint64_t DecodeAny(const unsigned char *data_to_decode,
                                      size_t size_to_parse);
  /// @brief decode an object identifier
  [[maybe_unused]] uint64_t DecodeOid(const unsigned char *data_to_decode,
                                      size_t size_to_parse);

  /// @brief return sizeof(Header) + sizeof(Data)
  [[nodiscard]] uint64_t FullSize() const noexcept;

  AsnHeader asn_header_;
  std::vector<AsnObj> obj_vector_;
  BytesVector flat_data_;
  std::optional<std::string> string_data_;
  std::optional<std::string> string_decoded_;
  size_t recursion_level_ = 0;
};

} // namespace pdfcsp::csp::asn