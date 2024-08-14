#include "asn1.hpp"
#include "typedefs.hpp"
#include <algorithm>
#include <bitset>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <limits>
#include <optional>
#include <stdexcept>
#include <string>
#include <sys/types.h>

namespace pdfcsp::csp::asn {

// ----------------------------------------
// AsnHeader

AsnHeader::AsnHeader(const unsigned char *ptr_data, uint64_t data_size) {
  if (ptr_data == nullptr) {
    throw std::invalid_argument("AsnHeader data ptr = 0");
  }
  if (data_size == 0) {
    throw std::runtime_error("[AsnHeader] Data size can't be 0");
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
  case 10:
    asn_tag = AsnTag::kEnumerated;
    tag_str = "ENUMERATED";
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
  case 18:
    asn_tag = AsnTag::kNumericString;
    tag_str = "NUMERIC STRING";
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
  const unsigned char byte1 = ptr_data[1];
  content_length = 0;
  if (byte1 < 128) {
    content_length = byte1;
  } else if (byte1 == 0x80) {
    stream_encoded = true;
    // size is unknown, so as maximum it can be = data_size
    content_length = data_size - 2;
  } else {
    const unsigned char bytes_for_length = byte1 ^ 0b10000000;
    sizeof_header += bytes_for_length;
    for (int i = 0; i < bytes_for_length; ++i) {
      const unsigned char val = ptr_data[i + 2];
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

AsnObj::AsnObj(const unsigned char *ptr_asn, size_t size) {
  if (size < 2 || size >= std::numeric_limits<size_t>::max()) {
    throw std::invalid_argument("invalig arg size");
  }
  if (ptr_asn == nullptr) {
    throw std::runtime_error("invalid data ptr");
  }
  DecodeAny(ptr_asn, size);
}

// only for recursive calls
AsnObj::AsnObj(const unsigned char *ptr_asn, size_t size,
               size_t recursion_level)
    : recursion_level_(recursion_level) {
  if (recursion_level_ > 100) {
    throw std::runtime_error("Maximal recursion depth wath reached");
  }
  DecodeAny(ptr_asn, size);
}

/// @brief decode any raw ASN1
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
  asn_header_ = AsnHeader(data_to_decode, size_to_parse);
  const bool unknown_tag_type = asn_header_.tag_type == AsnTagType::kUnknown;
  const bool content_spec_unknown =
      asn_header_.tag_type == AsnTagType::kContentSpecific &&
      asn_header_.asn_tag == AsnTag::kUnknown;
  const bool empty_not_null = asn_header_.content_length == 0 &&
                              (asn_header_.asn_tag != AsnTag::kNull &&
                               asn_header_.asn_tag != AsnTag::kSequence &&
                               asn_header_.asn_tag != AsnTag::kSet);
  const bool wrong_size =
      asn_header_.content_length + asn_header_.sizeof_header > size_to_parse;
  if (unknown_tag_type || (empty_not_null && !content_spec_unknown) ||
      wrong_size) {
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
    DecodeSequence(size_to_parse, data_to_decode, bytes_parsed);
  } else {
    DecodeFlat(data_to_decode, bytes_parsed);
  }
  return bytes_parsed;
}

/**
 * @brief Decode a constructed object (SEQUENCE)
 * @param size_to_parse [in]
 * @param data_to_decode [in]
 * @param bytes_parsed [out]
 */
void AsnObj::DecodeSequence(unsigned int size_to_parse,
                            const unsigned char *data_to_decode,
                            unsigned int &bytes_parsed) {
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
    const AsnHeader header_next(data_to_decode + bytes_parsed,
                                size_to_parse - bytes_parsed);
    if (header_next.content_length + header_next.sizeof_header >
        size_to_parse - bytes_parsed) {
      throw std::runtime_error("data length coded to ASN1 is out of bounds");
    }
    // Costruct a new object
    auto obj = AsnObj(data_to_decode + bytes_parsed,
                      header_next.content_length + header_next.sizeof_header,
                      recursion_level_ + 1);
    bytes_parsed += obj.FullSize();
    if (obj.asn_header_.stream_encoded) {
      bytes_parsed += 2;
    }
    obj_vector_.push_back(std::move(obj));
    // If the size is unknown, check; maybe the end is already found.
    if (bytes_parsed < FullSize() && asn_header_.stream_encoded &&
        size_to_parse >= 2 + bytes_parsed &&
        (data_to_decode + bytes_parsed)[0] == 0x00 &&
        (data_to_decode + bytes_parsed)[1] == 0x00) {
      // no we know the actual  size
      asn_header_.content_length = bytes_parsed - asn_header_.sizeof_header;
      break;
    }
  }
}

/**
 * @brief Decode a flat object
 * @param data_to_decode [in]
 * @param bytes_parsed [out]
 */
void AsnObj::DecodeFlat(const unsigned char *data_to_decode,
                        unsigned int &bytes_parsed) {
  unsigned int bytes_parsed_in_switch = 0;
  // If the size is unknown, look for the size.
  if (asn_header_.stream_encoded) {
    uint zeroes_found = 0;
    for (uint64_t i = 0; i < asn_header_.content_length; ++i) {
      if ((data_to_decode + bytes_parsed)[i] == 0x00) {
        ++zeroes_found;
      } else {
        zeroes_found = 0;
      }
      if (zeroes_found == 2) {
        asn_header_.content_length = i;
        break;
      }
    }
    if (zeroes_found != 2) {
      throw std::runtime_error("Determine the size of a flat object...failed");
    }
  }
  switch (asn_header_.asn_tag) {
  case AsnTag::kOid:
    bytes_parsed_in_switch +=
        DecodeOid(data_to_decode + bytes_parsed, asn_header_.content_length);
    break;
  case AsnTag::kOctetString:
  case AsnTag::kInteger:
    bytes_parsed_in_switch += asn_header_.content_length;
    break;
  case AsnTag::kNull:
    break;
  case AsnTag::kGeneralizedTime: {
    std::string tmp;
    std::copy(data_to_decode + bytes_parsed,
              data_to_decode + bytes_parsed + asn_header_.content_length,
              std::back_inserter(tmp));
    string_data_ = std::move(tmp);
    bytes_parsed_in_switch += asn_header_.content_length;
    break;
  }
  //  If parsing is not implemented, just copy the data
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
      const unsigned char oct = (data_to_decode + bytes_parsed)[i];
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
      const uint weight = octet_number - i - 1;
      std::bitset<8> oct = (data_to_decode + bytes_parsed)[i];
      oct.reset(7);
      // val = val + current octet ^ weight;
      val += oct.to_ulong() * static_cast<uint64_t>(std::pow(128U, weight));
    }
    bytes_parsed += octet_number;
    res.append(std::to_string(val));
    res.push_back('.');
  }
  res.pop_back();
  string_data_ = std::move(res);
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
  if (asn_header_.stream_encoded) {
    res.push_back(0x00);
    res.push_back(0x00);
  }
  return res;
}

/**
 * @brief Parses itself as another type
 * @param tag type of object to create
 * @return AsnObj new constructed AsnObj
 * @throws runtime_exception
 */
AsnObj AsnObj::ParseAs(enum AsnTag tag) const {
  BytesVector unparsed = Unparse();
  if (unparsed.empty()) {
    throw std::runtime_error("[AsnObj::ParseAs] empty unparsed object data");
  }
  unparsed[0] = TagToFirstByteForHeader(tag);
  return AsnObj(unparsed.data(), unparsed.size());
};

/**
 * @brief Returns choice number
 * @return uint
 * @throws runtime_exception
 */
uint AsnObj::ParseChoiceNumber() const {
  if (asn_header_.tag_type != AsnTagType::kContentSpecific) {
    throw std::runtime_error("invalid CHOICE structure");
  }
  auto bits = asn_header_.tag;
  bits.reset(7);
  bits.reset(6);
  bits.reset(5);
  return bits.to_ulong();
}

unsigned char TagToFirstByteForHeader(enum AsnTag tag) {
  switch (tag) {
  case AsnTag::kSequenceOf:
  case AsnTag::kSequence:
    return 0x30;
    break;
  case AsnTag::kOid:
    return 0x06;
    break;
  case AsnTag::kOctetString:
    return 0x04;
    break;
  case AsnTag::kInteger:
    return 0x02;
    break;
  case AsnTag::kUtf8String:
    return 0x0C;
    break;
  case AsnTag::kBitString:
    return 0x03;
    break;
  case AsnTag::kNull:
    return 0x05;
    break;
  case AsnTag::kSetOff:
  case AsnTag::kSet:
    return 0x31;
    break;
  case AsnTag::kPrintableString:
    return 0x13;
    break;
  case AsnTag::kIA5String:
    return 0x16;
    break;
  case AsnTag::kUTCTime:
    return 0x17;
    break;
  case AsnTag::kGeneralizedTime:
    return 0x18;
  case AsnTag::kNumericString:
    return 0x12;
    break;
  case AsnTag::kEnumerated:
    return 0x0A;
    break;
  default:
    throw std::runtime_error("[TagToFirstByteForHeader] unknown tag");
  }
}

} // namespace pdfcsp::csp::asn
