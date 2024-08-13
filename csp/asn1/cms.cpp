
#include "cms.hpp"
#include "asn1.hpp"
#include "asn_tsp.hpp"
#include "oids.hpp"
#include "typedefs.hpp"
#include "utils.hpp"
#include "utils_cert.hpp"
#include <algorithm>
#include <iostream>
#include <stdexcept>
#include <sys/types.h>
#include <type_traits>

namespace pdfcsp::csp::asn {

AlgorithmIdentifier::AlgorithmIdentifier(const AsnObj &obj) {
  const std::string func_name = "[AlgorithmIdentifier] ";
  if (obj.AsnTag() != AsnTag::kSequence || obj.Size() < 1) {
    throw std::runtime_error(func_name + "invalid ASN structure");
  }
  algorithm = obj.at(0).StringData().value_or("");
  if (algorithm.empty()) {
    throw std::runtime_error("[SignedData] algorithm id is empty");
  }
  if (obj.Size() == 2) {
    parameters = obj.at(1).Data();
  }
}

template <typename CONTENT_T>
SignedData<CONTENT_T>::SignedData(const AsnObj &asn_obj) {
  constexpr const char *const expl =
      "[SignedData] invalid SignedData ASN structure";
  // version
  if (asn_obj.at(0).AsnTag() != AsnTag::kInteger) {
    throw std::runtime_error(expl);
  }
  version = static_cast<uint>(asn_obj.at(0).Data()[0]);
  // algorithm IDs
  const auto &algo_set = asn_obj.at(1);
  if (algo_set.IsFlat() || algo_set.Size() == 0) {
    throw std::runtime_error(expl);
  }
  for (const auto &algo : algo_set.Childs()) {
    digestAlgorithms.emplace_back(algo);
  }
  // EncapsulatedContentInfo encapContentInfo
  const AsnObj &content_info = asn_obj.at(2);
  encapContentInfo = EncapsulatedContentInfo<CONTENT_T>(content_info);
  // TODO(Oleg)
  //  certificates
  //  crtls
  //  signers info
}

template <typename CONTENT>
EncapsulatedContentInfo<CONTENT>::EncapsulatedContentInfo(
    const AsnObj &asn_obj) {
  constexpr const char *const expl =
      "Invalid EncapsulatedContentInfo ASN structure";
  const std::string func_name = "[EncapsulatedContentInfo] ";
  if (asn_obj.AsnTag() != AsnTag::kSequence || asn_obj.Size() < 2) {
    throw std::runtime_error(func_name + expl);
  }
  // eContentType
  std::string cont_oid = asn_obj.at(0).StringData().value_or("");
  if (cont_oid.empty()) {
    throw std::runtime_error(func_name + "empty algorithm OID");
  }
  eContentType = std::move(cont_oid);
  if (eContentType != kOID_tSTInfo && std::is_same_v<CONTENT, TSTInfo>) {
    throw std::runtime_error(func_name +
                             " Content OID does not match content type");
  }
  // eContent
  const AsnObj &content = asn_obj.at(1);
  eContent = CONTENT(content);
}

// explicit instantination
template struct SignedData<TSTInfo>;

AttributeTypeAndValue::AttributeTypeAndValue(const AsnObj &obj) {
  if (obj.Size() != 2 || obj.at(0).AsnTag() != AsnTag::kOid) {
    throw std::runtime_error("invalid AttributeTypeAndValue structure");
  }
  oid = obj.at(0).StringData().value_or("");
  if (oid.empty()) {
    throw std::runtime_error("[AttributeTypeAndValue] empty OID");
  }
  auto str_data = obj.at(1).Data();
  val = std::string(str_data.cbegin(), str_data.cend());
}

IssuerSerial::IssuerSerial(const AsnObj &obj) {
  if (obj.Size() < 2 || obj.Size() > 3) {
    throw std::runtime_error("invalid IssuerSerial structure");
  }
  // issuer - field 0
  for (const auto &field : obj.at(0).Childs()) {
    BytesVector unparsed = field.Unparse();
    AsnTag tag = AsnTag::kUnknown;
    // determine a data type
    switch (ParseChoiceNumber(field)) {
    case 0: // AnotherName
    case 4: // Name
      unparsed[0] = 0x30;
      tag = AsnTag::kSequence;
      break;
    case 1: // IA5String
    case 2: // IA5String
    case 6: // IA5String
      unparsed[0] = 0x16;
      tag = AsnTag::kIA5String;
      break;
    case 7: // OCTET STRING
      unparsed[0] = 0x04;
      tag = AsnTag::kOctetString;
      break;
    case 8: // OBJECT IDENTIFIER
      unparsed[0] = 0x06;
      tag = AsnTag::kOid;
      break;
    default: // EDIPartyName
      tag = AsnTag::kUnknown;
      break;
    }
    switch (tag) {
    case AsnTag::kSequence: { // Name (RDNSequence)
      const AsnObj tmp_obj(unparsed.data(), unparsed.size());
      auto unparsed_child = tmp_obj.at(0).Unparse();
      auto decoded_issuer =
          NameBlobToStringEx(unparsed_child.data(), unparsed_child.size());
      if (!decoded_issuer) {
        throw std::runtime_error("[IssuerSerial] can't decode issuer field");
      }
      issuer = decoded_issuer.value();
    } break;
    // TODO(Oleg) test this cases
    case AsnTag::kIA5String:
    case AsnTag::kOctetString: {
      const AsnObj tmp_obj(unparsed.data(), unparsed.size());
      issuer = std::string(tmp_obj.Data().cbegin(), tmp_obj.Data().cend());
    } break;
    case AsnTag::kOid: {
      const AsnObj tmp_obj(unparsed.data(), unparsed.size());
      auto decode_res = tmp_obj.StringData();
      if (!decode_res) {
        throw std::runtime_error("[IssuerSerial] decode OID failed");
      }
      issuer = decode_res.value();
    } break;
    default:
      throw std::runtime_error(
          "[IssuerSerial] Unsupported type for issuer field");
    }
  }
  // serial
  serial = obj.at(1).Data();
  // issuerUID
  if (obj.Size() == 3) {
    issuerUID = obj.at(2).Data();
  }
}

/**
 * @brief Returns choice number
 * @param AsnObj (CHOICE)
 * @return uint
 */
uint ParseChoiceNumber(const AsnObj &obj) {
  if (obj.Header().tag_type != AsnTagType::kContentSpecific) {
    throw std::runtime_error("invalid CHOICE structure");
  }
  auto bits = obj.Header().tag;
  bits.reset(7);
  bits.reset(6);
  bits.reset(5);
  return bits.to_ulong();
}

} // namespace pdfcsp::csp::asn