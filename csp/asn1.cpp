#include "asn1.hpp"
#include "resolve_symbols.hpp"
#include "utils.hpp"
#include <bitset>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <ios>
#include <iostream>
#include <limits>
#include <optional>
#include <stdexcept>
#include <string>
#include <sys/types.h>

namespace pdfcsp::csp {

// NOLINTBEGIN (cppcoreguidelines-pro-bounds-pointer-arithmetic)

AsnHeader::AsnHeader(const unsigned char *ptr_data) {
  if (ptr_data == nullptr) {
    throw std::invalid_argument("AsnHeader data ptr = 0");
  }
  std::bitset<8> byte0 = ptr_data[0];
  const bool bit8 = byte0.test(7);
  const bool bit7 = byte0.test(6);
  const bool bit6 = byte0.test(5);
  if (!bit8 && !bit7) {
    tag_type = AsnTagType::kUniversal;
  } else if (!bit8 && bit7) {
    tag_type = AsnTagType::kApplication;
  } else if (bit8 && !bit7) {
    tag_type = AsnTagType::kContentSpecific;
  } else if (bit7 && bit8) {
    tag_type = AsnTagType::kPrivate;
  } else {
    tag_type = AsnTagType::kUnknown;
  }
  if (bit6) {
    constructed = true;
  }
  byte0.set(7, false);
  byte0.set(6, false);
  byte0.set(5, false);
  tag = byte0.to_ulong();
  switch (byte0.to_ulong()) {
  case 2:
    asn_tag = AsnTag::kInteger;
    tag_str = "INTEGER";
    break;
  case 3:
    asn_tag = AsnTag::kBitString;
    tag_str = "BIT STRING";
    break;
  case 4:
    asn_tag = AsnTag::kOctetString;
    tag_str = "OCTET STRING";
    break;
  case 5:
    asn_tag = AsnTag::kNull;
    tag_str = "NULL";
    break;
  case 6:
    asn_tag = AsnTag::kOid;
    tag_str = "OBJECT IDENTIFIER";
    break;
  case 12:
    asn_tag = AsnTag::kUtf8String;
    tag_str = "UTF8 STRING";
    break;
  case 16:
    asn_tag = AsnTag::kSequence;
    tag_str = "SEQUENCE";
    break;
  case 17:
    asn_tag = AsnTag::kSet;
    tag_str = "SET";
    break;
  case 19:
    asn_tag = AsnTag::kPrintableString;
    tag_str = "PRINTABLE STRING";
    break;
  case 22:
    asn_tag = AsnTag::kIA5String;
    tag_str = "IA5 STRING";
    break;
  case 23:
    asn_tag = AsnTag::kUTCTime;
    tag_str = "UTC TIME";
    break;
  case 24:
    asn_tag = AsnTag::kGeneralizedTime;
    tag_str = "GENERALIZED TIME";
    break;
  default:
    asn_tag = AsnTag::kUnknown;
    tag_str = "UNKNOWN";
    break;
  }
  bytes_raw = 1;
  // length
  unsigned char byte1 = ptr_data[1];
  length = 0;
  if (byte1 < 128) {
    length = byte1;
  } else {
    const unsigned char bytes_for_length = byte1 ^ 0b10000000;
    bytes_raw += bytes_for_length;
    for (int i = 0; i < bytes_for_length; ++i) {
      unsigned char val = ptr_data[i + 2];
      length |= val;
      if (i != bytes_for_length - 1) {
        length <<= 8;
      }
    }
  }
  ++bytes_raw;
}

std::string AsnHeader::TypeStr() const noexcept {
  switch (tag_type) {
  case (AsnTagType::kUniversal):
    return "Universal obj";
    break;
  case (AsnTagType::kApplication):
    return "Application";
    break;
  case (AsnTagType::kContentSpecific):
    return "Content specific";
    break;
  case (AsnTagType::kPrivate):
    return "Private";
    break;
  case (AsnTagType::kUnknown):
    return "Unknown tag type";
    break;
  }
  return "";
}

std::string AsnHeader::ConstructedStr() const noexcept {
  return constructed ? "Constructed" : "Flat";
}

AsnObj::AsnObj(const unsigned char *ptr_asn, size_t size,
               PtrSymbolResolver symbols)
    : symbols_(std::move(symbols)) {
  if (size < 2 || size >= std::numeric_limits<size_t>::max()) {
    throw std::invalid_argument("invalig arg size");
  }
  std::cout << "ASN obj construct\n";
  if (!symbols_) {
    throw std::runtime_error("invalid symbol resolver ptr");
  }
  if (ptr_asn == nullptr) {
    throw std::runtime_error("invalid data ptr");
  }
  DecodeSequenceOfAny(ptr_asn, size);
}

// only for recursive calls
/// NOLINTNEXTLINE(misc-no-recursion)
AsnObj::AsnObj(const unsigned char *ptr_asn, size_t size) {
  std::cout << "Recursive call to constructor\n";
  DecodeSequenceOfAny(ptr_asn, size);
}

/// NOLINTNEXTLINE(misc-no-recursion)
uint64_t AsnObj::DecodeSequenceOfAny(const unsigned char *data_to_decode,
                                     size_t size_to_parse) {
  if (size_to_parse < 2) {
    return 0;
  }
  if (data_to_decode == nullptr) {
    throw std::runtime_error("ptr to data = nullptr ");
  }
  std::cout << "data to parse size = " << size_to_parse << "\n";
  unsigned int bytes_parsed = 0;
  // Parse the header
  AsnHeader header(data_to_decode);
  if (header.tag_type == AsnTagType::kUnknown ||
      header.asn_tag == AsnTag::kUnknown || header.length == 0 ||
      header.length > size_to_parse) {
    throw std::runtime_error("invalid asn1 header");
  }
  std::cout << header.TypeStr() << "\n"
            << header.ConstructedStr() << "\n"
            << header.TagStr() << "\n"
            << std::hex << static_cast<int>((data_to_decode + bytes_parsed)[0])
            << " " << std::hex
            << static_cast<int>((data_to_decode + bytes_parsed)[1]) << std::dec
            << "\n";
  bytes_parsed = header.bytes_raw;
  if (header.length > size_to_parse - header.bytes_raw) {
    throw std::runtime_error("ASN length is out of bounds");
  }
  std::cout << "Bytes parsed = " << bytes_parsed << "\n"
            << "length =" << std::to_string(header.length) << "\n\n";
  uint64_t it_number = 0;
  while (bytes_parsed < size_to_parse && it_number < 10) {
    if (header.length > size_to_parse - bytes_parsed) {
      throw std::runtime_error("data length coded to ASN1 is out of bounds");
    }
    ++it_number;
    std::cout << "Found type " << header.TagStr()
              << " of size =" << header.length << "\n";
    switch (header.asn_tag) {
    case AsnTag::kOid:
      bytes_parsed += DecodeOid(data_to_decode + bytes_parsed, header.length);
      break;
    case AsnTag::kOctetString:
      bytes_parsed +=
          DecodeOctetStr(data_to_decode + bytes_parsed, header.length);
      break;
    case AsnTag::kInteger:
      // TODO(Oleg) parse integer
      std::cout << "Parsing not implemented for type " << header.TagStr()
                << "\n";
      for (uint i = 0; i < header.length; ++i) {
        std::cout << std::hex
                  << static_cast<int>((data_to_decode + bytes_parsed)[i])
                  << " ";
      }
      std::cout << std::dec << "\n";
      bytes_parsed += header.length;
      break;
    case AsnTag::kSequence:
      bytes_parsed +=
          DecodeSequenceOfAny(data_to_decode + bytes_parsed, header.length);
      break;
    default:
      std::cout << "Parsing not implemented for type " << header.TagStr()
                << "\n";
      bytes_parsed += header.length;
      break;
    }
    std::cout << "bytes parsed = " << bytes_parsed << "\n"
              << "total bytes to parse = " << size_to_parse
              << "\nnext iteration" << "\n\n";
    // parse next header
    if (bytes_parsed < size_to_parse) {
      std::cout << "Read next header\n";
      header = AsnHeader(data_to_decode + bytes_parsed);
      std::cout << std::hex
                << static_cast<int>((data_to_decode + bytes_parsed)[0]) << " "
                << std::hex
                << static_cast<int>((data_to_decode + bytes_parsed)[1])
                << std::dec << "\n";
      bytes_parsed += header.bytes_raw;
      std::cout << header.TypeStr() << "\n"
                << header.ConstructedStr() << "\n"
                << header.TagStr() << "\n";
    }
  }
  std::cout << "return from DecodeSequenceOfAny\n----\n";
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
  if (data_to_decode == nullptr) {
    throw std::invalid_argument("OID data ptr = 0");
  }
  std::cout << "data to parse oid size = " << size_to_parse << "\n";
  unsigned int bytes_parsed = 0;
  const unsigned char byte0 = data_to_decode[0];
  // get first
  const unsigned char val1 = byte0 / 40;
  // get second
  const unsigned char val2 = byte0 % 40;
  const char devider = '.';
  ++bytes_parsed;
  res.append(std::to_string(val1));
  res.push_back(devider);
  res.append(std::to_string(val2));
  res.push_back(devider);
  uint iter_counter = 0;
  while (bytes_parsed < size_to_parse && iter_counter < 100) {
    ++iter_counter;
    // find the rest
    uint octet_number = 0;
    for (unsigned int i = 0; i < size_to_parse - bytes_parsed; ++i) {
      unsigned char oct = (data_to_decode + bytes_parsed)[i];
      ++octet_number;
      if (oct < 128) {
        break;
      }
    }
    if (octet_number > 8) {
      throw std::runtime_error("oid part is to long");
    }
    // get val of next octet sequence
    uint64_t val = 0;
    for (uint i = 0; i < octet_number; ++i) {
      int weight = octet_number - i - 1;
      std::bitset<8> oct = (data_to_decode + bytes_parsed)[i];
      oct.reset(7);
      // val = val + current octet ^ weight;
      val += oct.to_ulong() * std::pow<uint>(128, weight);
    }
    bytes_parsed += octet_number;
    res.append(std::to_string(val));
    res.push_back('.');
  }
  res.pop_back();
  std::cout << "parsing oid result = " << res << "\n";
  std::cout << "return from oid parse\n";
  std::cout << "--------------------------\n";
  return bytes_parsed;
}

// NOLINTBEGIN(functionStatic)
uint64_t AsnObj::DecodeOctetStr(const unsigned char *data_to_decode,
                                size_t size_to_parse) {
  if (size_to_parse == 0) {
    return 0;
  }
  std::cout << "string size to parse=" << size_to_parse << "\n";
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
  auto buf = NameBlobToString(&blob, symbols_);
  std::cout << buf.value_or("FAIL") << "\n";
  return bytes_parsed;
}
// NOLINTEND(functionStatic)
// NOLINTEND (cppcoreguidelines-pro-bounds-pointer-arithmetic)

} // namespace pdfcsp::csp