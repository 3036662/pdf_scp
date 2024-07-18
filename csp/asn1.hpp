#pragma once

// #include "CSP_WinDef.h"
// #pragma GCC diagnostic push
// #pragma GCC diagnostic ignored "-Winvalid-utf8"
// #include "CSP_WinCrypt.h"
// #pragma GCC diagnostic pop

#include "resolve_symbols.hpp"
#include "typedefs.hpp"
#include <cstddef>
#include <cstdint>
#include <vector>
namespace pdfcsp::csp {

enum class AsnType : uint8_t { kSequenceOfAny, kUnknown };

/**
 * @brief Decode an ASN object
 * @throws runtime_error on fail
 */
class AsnObj {
public:
  [[nodiscard]] AsnType get_asn_type() const noexcept { return asn_type_; }
  [[nodiscard]] bool IsFlat() const noexcept { return is_flat_; }
  [[nodiscard]] std::size_t Size() const noexcept { return obj_vector_.size(); }

  explicit AsnObj(const unsigned char *ptr_asn, size_t size,
                  PtrSymbolResolver symbols);

private:
  // only for recursive calls
  explicit AsnObj(const unsigned char *ptr_asn, size_t size);
  void ResolveType(const unsigned char *ptr_asn, size_t size);
  [[maybe_unused]] uint64_t
  DecodeSequenceOfAny(const unsigned char *data_to_decode, size_t size);
  [[maybe_unused]] uint64_t DecodeOid(const unsigned char *data_to_decode,
                                      size_t size_to_parse);

  [[maybe_unused]] uint64_t DecodeOctetStr(const unsigned char *data_to_decode,
                                           size_t size_to_parse);

  AsnType asn_type_ = AsnType::kUnknown;
  bool is_flat_ = false;
  std::vector<AsnObj> obj_vector_;
  BytesVector flat_data_;
  PtrSymbolResolver symbols_;
  // unsigned int recursion_level_ = 0;
};

} // namespace pdfcsp::csp