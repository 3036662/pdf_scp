#include "asn1.hpp"

#include "resolve_symbols.hpp"
#include "utils.hpp"
#include <bitset>
#include <cstddef>
#include <cstdint>
#include <ios>
#include <iostream>
#include <iterator>
#include <limits>
#include <memory>
#include <stdexcept>
#include <string>

namespace pdfcsp::csp {

// NOLINTBEGIN(cppcoreguidelines-pro-bounds-pointer-arithmetic)
AsnObj::AsnObj(const unsigned char *ptr_asn, size_t size,
               PtrSymbolResolver symbols)
    : symbols_(std::move(symbols)) {
  std::cout << "ASN obj construct\n";
  if (!symbols_) {
    throw std::runtime_error("invalid symbol resolver ptr");
  }
  ResolveType(ptr_asn, size);
}

// only for recursive calls
/// NOLINTNEXTLINE(misc-no-recursion)
AsnObj::AsnObj(const unsigned char *ptr_asn, size_t size) {
  std::cout << "Recursive call to constructor\n";
  ResolveType(ptr_asn, size);
}

/// NOLINTNEXTLINE(misc-no-recursion)
void AsnObj::ResolveType(const unsigned char *ptr_asn, size_t size) {
  if (ptr_asn == nullptr) {
    throw std::runtime_error("pointer to ASN onj == nullptr");
  }
  if (size == 0) {
    throw std::runtime_error("ASN object size = 0");
  }
  const unsigned char type_byte = ptr_asn[0];
  // resolve type
  switch (type_byte) { // NOLINT(hicpp-multiway-paths-covered)
  case 0x30:
    std::cout << "ASN SEQ_ANY was found\n";
    asn_type_ = AsnType::kSequenceOfAny;
    is_flat_ = false;
    DecodeSequenceOfAny(ptr_asn, size);
    break;
  default:
    asn_type_ = AsnType::kUnknown;
    std::cout << "Unknown Type found,HEX:\n";
    for (uint i = 0; i < size; ++i) {
      // std::cout << std::hex << static_cast<int>(ptr_asn[i]) << " ";
      std::cout << ptr_asn[i];
    }
    std::cout << "\n";
    break;
  }
}
// NOLINTEND(cppcoreguidelines-pro-bounds-pointer-arithmetic)
// NOLINTBEGIN

uint64_t AsnObj::DecodeSequenceOfAny(const unsigned char *data_to_decode,
                                     size_t size_to_parse) {
  if (size_to_parse == 0) {
    return 0;
  }
  std::cout << "data to parse size = " << size_to_parse << "\n";
  unsigned int bytes_parsed = 0;
  // get flags and tag
  std::bitset<8> byte0 = data_to_decode[0];
  bool bit8 = byte0.test(7);
  bool bit7 = byte0.test(6);
  bool bit6 = byte0.test(5);
  std::cout << "bits87=" << bit8 << bit7 << "\n";
  if (!bit8 && !bit7) {
    std::cout << "Universal obj\n";
  } else if (!bit8 && bit7) {
    std::cout << "Application\n";
  } else if (bit8 && !bit7) {
    std::cout << "Content specific\n";
  } else if (bit7 && bit8) {
    std::cout << "Private\n";
  }
  if (bit6) {
    std::cout << "The type is constructed\n";
  }
  std::cout << "first byte = " << byte0 << "\n";
  std::bitset<8> tag = byte0;
  tag.set(7, false);
  tag.set(6, false);
  tag.set(5, false);
  std::cout << "tag =" << tag << "\n";
  std::cout << "tag =" << tag.to_ulong() << "\n";
  ++bytes_parsed;
  // get length
  unsigned char byte2 = data_to_decode[1];
  uint64_t length = 0;
  if (byte2 < 128) {
    std::cout << "Short form length\n";
    length = byte2;
  } else {
    std::cout << "Long form length\n";
    // std::cout << std::bitset<8>(byte2) << "\n";
    unsigned char bytes_for_length = byte2 ^ 0b10000000;
    bytes_parsed += bytes_for_length;
    std::cout << std::bitset<8>(bytes_for_length) << "\n";
    std::cout << "bytes for length =" << std::to_string(bytes_for_length)
              << "\n";
    for (int i = 0; i < bytes_for_length; ++i) {
      unsigned char val = data_to_decode[i + 2];
      length |= val;
      if (i != bytes_for_length - 1) {
        length <<= 8;
      }
    }
  }
  ++bytes_parsed;
  std::cout << "Bytes parsed = " << bytes_parsed << "\n";
  std::cout << "length =" << std::to_string(length) << "\n";

  unsigned long it_number = 0;
  while (bytes_parsed < size_to_parse && it_number < 10) {
    ++it_number;
    // OBJECT IDENTIFIER
    if (tag == 6) {
      std::cout << "Found OBJECT IDENTIFIER\n";
      std::cout << "----------------------------\n";
      bytes_parsed += DecodeOid(data_to_decode + bytes_parsed, length);
    }
    // OCTET STRING
    if (tag == 4) {
      std::cout << "Found OCTET_STRING\n";
      bytes_parsed += DecodeOctetStr(data_to_decode + bytes_parsed, length);
    }
    if (tag == 2) {
      std::cout << "Found INTEGER\n";
      bytes_parsed += length;
    }
    if (tag == 16 || tag == 28) {
      std::cout << "Found a sequence\n";
      std::cout << "recursive call to parse " << length << "bytes\n";
      std::cout << "----------------------------\n";
      bytes_parsed +=
          DecodeSequenceOfAny(data_to_decode + bytes_parsed, length);
    }
    std::cout << "bytes parsed = " << bytes_parsed << "\n";
    std::cout << "next iteration" << "\n";
  }

  return bytes_parsed;
}

// OBJECT IDENTIFIER
uint64_t AsnObj::DecodeOid(const unsigned char *data_to_decode,
                           size_t size_to_parse) {
  std::cout << "start oid parse\n";
  std::string res;
  if (size_to_parse == 0) {
    return 0;
  }
  std::cout << "data to parse size = " << size_to_parse << "\n";
  unsigned int bytes_parsed = 0;
  // get first
  std::bitset<8> val2 = data_to_decode[0];
  for (int i = 4; i < 8; ++i) {
    val2.reset(i);
  }
  std::bitset<8> val1 = data_to_decode[0];
  val1 >>= 4;
  unsigned char first = val1.to_ulong() * 40 + val2.to_ulong();
  res.push_back(first);
  ++bytes_parsed;
  for (size_t i = 1; i < size_to_parse; ++i) {
    res.push_back(data_to_decode[i]);
    ++bytes_parsed;
  }
  // std::cout << "parsed bytes numb=" << bytes_parsed << "\n";
  std::cout << "return from oid parse\n";
  return bytes_parsed;
}

uint64_t AsnObj::DecodeOctetStr(const unsigned char *data_to_decode,
                                size_t size_to_parse) {
  if (size_to_parse == 0) {
    return 0;
  }
  unsigned int bytes_parsed = 0;
  std::cout << "String content:\n";
  for (uint i = 0; i < size_to_parse; ++i) {
    std::cout << data_to_decode[i];
    ++bytes_parsed;
  }
  std::cout << "\n";

  CERT_NAME_BLOB blob;
  blob.cbData = size_to_parse;
  blob.pbData = const_cast<BYTE *>(data_to_decode);
  auto buf = NameBlobToString(&blob);
  std::cout << buf.value_or("FAIL") << "\n";
  return bytes_parsed;
}

// NOLINTEND

} // namespace pdfcsp::csp