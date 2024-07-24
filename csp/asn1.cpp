#include "asn1.hpp"
#include "resolve_symbols.hpp"
#include "typedefs.hpp"
#include "utils.hpp"
#include <bitset>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <ios>
#include <iostream>
#include <iterator>
#include <limits>
#include <optional>
#include <stdexcept>
#include <string>
#include <sys/types.h>

namespace pdfcsp::csp {

// NOLINTBEGIN (cppcoreguidelines-pro-bounds-pointer-arithmetic)

// ----------------------------------------
// AsnHeader

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
  sizeof_header = 1;
  // length
  unsigned char byte1 = ptr_data[1];
  content_length = 0;
  if (byte1 < 128) {
    content_length = byte1;
  } else {
    const unsigned char bytes_for_length = byte1 ^ 0b10000000;
    sizeof_header += bytes_for_length;
    for (int i = 0; i < bytes_for_length; ++i) {
      unsigned char val = ptr_data[i + 2];
      content_length |= val;
      if (i != bytes_for_length - 1) {
        content_length <<= 8;
      }
    }
  }
  ++sizeof_header;
  // save a raw header bytes
  std::copy(ptr_data, ptr_data + sizeof_header, std::back_inserter(raw_header));
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

//-----------------------------------------------
// AsnObj

uint64_t AsnObj::FullSize() const noexcept {
  return asn_header_.sizeof_header + asn_header_.content_length;
}

AsnObj::AsnObj(const unsigned char *ptr_asn, size_t size,
               PtrSymbolResolver symbols)
    : asn_header_(), symbols_(std::move(symbols)) {
  if (size < 2 || size >= std::numeric_limits<size_t>::max()) {
    throw std::invalid_argument("invalig arg size");
  }
  if (!symbols_) {
    throw std::runtime_error("invalid symbol resolver ptr");
  }
  if (ptr_asn == nullptr) {
    throw std::runtime_error("invalid data ptr");
  }
  DecodeAny(ptr_asn, size);
}

// only for recursive calls
/// NOLINTNEXTLINE(misc-no-recursion)
AsnObj::AsnObj(const unsigned char *ptr_asn, size_t size,
               size_t recursion_level, const PtrSymbolResolver &symbols)
    : symbols_(symbols), recursion_level_(recursion_level) {
  if (recursion_level_ > 100) {
    throw std::runtime_error("Maximal recursion depth wath reached");
  }
  DecodeAny(ptr_asn, size);
}

uint64_t AsnObj::DecodeAny(const unsigned char *data_to_decode,
                           size_t size_to_parse) {
  if (size_to_parse < 2) {
    return 0;
  }
  if (data_to_decode == nullptr) {
    throw std::runtime_error("ptr to data = nullptr ");
  }
  unsigned int bytes_parsed = 0;
  // Parse the header
  asn_header_ = AsnHeader(data_to_decode);
  if (asn_header_.tag_type == AsnTagType::kUnknown ||
      /*asn_header_.asn_tag == AsnTag::kUnknown ||*/
      (asn_header_.content_length == 0 &&
       asn_header_.asn_tag != AsnTag::kNull) ||
      asn_header_.content_length + asn_header_.sizeof_header > size_to_parse) {
    throw std::runtime_error("invalid asn1 header");
  }
  bytes_parsed = asn_header_.sizeof_header;
  if (size_to_parse < FullSize()) {
    throw std::runtime_error("ASN length is out of bounds");
  }
  // if SEQUENCE
  if (asn_header_.asn_tag == AsnTag::kSequence ||
      (asn_header_.asn_tag == AsnTag::kUnknown && asn_header_.constructed) ||
      asn_header_.asn_tag == AsnTag::kSet) {
    uint64_t it_number = 0;
    while (bytes_parsed < FullSize()) {
      if (bytes_parsed < size_to_parse && size_to_parse - bytes_parsed < 2) {
        throw std::runtime_error("the data is to short");
      }
      ++it_number;
      if (it_number >= 100) {
        throw std::runtime_error("iteration number maximum was reached");
      }
      // read the next header
      AsnHeader header_next(data_to_decode + bytes_parsed);
      if (header_next.content_length + header_next.sizeof_header >
          size_to_parse - bytes_parsed) {
        throw std::runtime_error("data length coded to ASN1 is out of bounds");
      }
      // Costruct a new object
      auto obj = AsnObj(data_to_decode + bytes_parsed,
                        header_next.content_length + header_next.sizeof_header,
                        recursion_level_ + 1, symbols_);
      bytes_parsed += obj.FullSize();
      obj_vector_.push_back(std::move(obj));
    }
  } else {
    unsigned int bytes_parsed_in_switch = 0;
    switch (asn_header_.asn_tag) {
    case AsnTag::kOid:
      bytes_parsed_in_switch +=
          DecodeOid(data_to_decode + bytes_parsed, asn_header_.content_length);
      break;
    case AsnTag::kOctetString:
      bytes_parsed_in_switch += DecodeOctetStr(data_to_decode + bytes_parsed,
                                               asn_header_.content_length);
      break;
    case AsnTag::kInteger:
      bytes_parsed_in_switch += asn_header_.content_length;
      break;
    case AsnTag::kNull:
      break;
    // if parsing is not impemented - just copy data
    default:
      bytes_parsed_in_switch += asn_header_.content_length;
      break;
    } // switch
    // copy raw data to flat_data_
    if (asn_header_.asn_tag != AsnTag::kNull) {
      std::copy(data_to_decode + bytes_parsed,
                data_to_decode + bytes_parsed + asn_header_.content_length,
                std::back_inserter(flat_data_));
    }
    bytes_parsed += bytes_parsed_in_switch;
    if (bytes_parsed != FullSize()) {
      throw std::runtime_error("Flat object is not compeletelly parsed");
    }
  } // else
  return bytes_parsed;
}

// Parse OBJECT IDENTIFIER
uint64_t AsnObj::DecodeOid(const unsigned char *data_to_decode,
                           size_t size_to_parse) {
  std::string res;
  if (size_to_parse == 0) {
    return 0;
  }
  if (data_to_decode == nullptr) {
    throw std::invalid_argument("OID data ptr = 0");
  }
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
  string_data_ = std::move(res);
  return bytes_parsed;
}

uint64_t AsnObj::DecodeOctetStr(const unsigned char *data_to_decode,
                                size_t size_to_parse) {
  if (size_to_parse == 0) {
    return 0;
  }
  unsigned int bytes_parsed = 0;
  string_data_ = std::string(data_to_decode, data_to_decode + size_to_parse);
  CERT_NAME_BLOB blob;
  blob.cbData = size_to_parse;
  blob.pbData = const_cast<BYTE *>(data_to_decode);
  string_decoded_ = NameBlobToString(&blob, symbols_);
  bytes_parsed = string_data_.value_or("").size();
  return bytes_parsed;
}

[[nodiscard]] BytesVector AsnObj::Unparse() const noexcept {
  BytesVector res;
  // copy the header
  std::copy(asn_header_.raw_header.cbegin(), asn_header_.raw_header.cend(),
            std::back_inserter(res));
  // if SEQUENCE call unparse for each child
  if (asn_header_.asn_tag == AsnTag::kSequence ||
      (asn_header_.asn_tag == AsnTag::kUnknown && asn_header_.constructed) ||
      asn_header_.asn_tag == AsnTag::kSet) {
    for (const auto &obj : obj_vector_) {
      auto tmp = obj.Unparse();
      std::copy(tmp.cbegin(), tmp.cend(), std::back_inserter(res));
    }
  } else {
    std::copy(flat_data_.cbegin(), flat_data_.cend(), std::back_inserter(res));
  }
  return res;
}

// NOLINTEND (cppcoreguidelines-pro-bounds-pointer-arithmetic)

} // namespace pdfcsp::csp
