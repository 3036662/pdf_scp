#include "revoc_refs.hpp"
#include "asn1.hpp"
#include "cert_refs.hpp"
#include "cms.hpp"
#include "typedefs.hpp"
#include "utils_cert.hpp"
#include <stdexcept>

namespace pdfcsp::csp::asn {

/**
 * @brief Returns parsed revocation refs
 * @param obj - AsnObj, with revocation refs to parse
 * @return CompleteRevocationRefs
 */
CompleteRevocationRefs ParseRevocRefs(const AsnObj &obj) {
  CompleteRevocationRefs res;
  if (obj.Size() == 0) {
    return res;
  }
  for (const auto &ref : obj.Childs()) {
    if (ref.Header().content_length > 0) {
      res.emplace_back(ref);
    }
  }
  return res;
}

/**
 * @brief Construct a new Crl Ocsp Ref:: Crl Ocsp Ref object
 * @param obj
 */
CrlOcspRef::CrlOcspRef(const AsnObj &obj) {
  for (const AsnObj &child : obj.Childs()) {
    const uint choice = ParseChoiceNumber(child);
    BytesVector unparsed_child = child.Unparse();
    if (unparsed_child.empty()) {
      throw std::runtime_error("empty CrlOcspRef object");
    }
    if (choice != 1) {
      throw std::runtime_error("unsupported type of CrlOcspRef");
    }
    // create a vector of OcspListID and put it to ocspids field
    unparsed_child[0] = 0x30; // SEQENCE
    OcspListID res;
    auto ocsp_list_asn = AsnObj(unparsed_child.data(), unparsed_child.size());
    if (ocsp_list_asn.Size() == 0 || ocsp_list_asn.at(0).Size() == 0) {
      throw std::runtime_error("empty CrlOcspRef sequence");
    }
    for (const auto &resp_id_asn : ocsp_list_asn.at(0).Childs()) {
      res.emplace_back(resp_id_asn.at(0));
    }
    ocspids = std::move(res);
  }
}

OcspResponsesID::OcspResponsesID(const AsnObj &obj) {
  if (obj.Size() == 0 || obj.Size() > 2 || obj.at(0).Size() == 0) {
    throw std::runtime_error(
        "[OcspResponsesID] invalid OcspResponsesID structure");
  }
  // ocspIdentifier
  const AsnObj &ocsp_identifier_asn = obj.at(0);
  ocspIdentifier = OcspIdentifier(ocsp_identifier_asn);
  // ocspRepHash
  ocspRepHash = OtherHash(OtherHashAlgAndValue(obj.at(1)));
  if (!ocspRepHash) {
    throw std::runtime_error("[OcspResponsesID] parse ocspRepHash failed");
  }
}

OcspIdentifier::OcspIdentifier(const AsnObj &obj) {
  if (obj.Size() != 2) {
    throw std::runtime_error("[OcspIdentifier] invalid structure");
  }
  // parse field 0 - choice ResponderID
  BytesVector choice_unparsed = obj.at(0).Unparse();
  if (choice_unparsed.empty()) {
    throw std::runtime_error("[OcspIdentifier] empty ResponderId");
  }
  switch (ParseChoiceNumber(obj.at(0))) {
  case 1: // Name
  {
    choice_unparsed[0] = 0x30; // SEQUENCE
    ocspResponderID_name =
        NameBlobToStringEx(choice_unparsed.data(), choice_unparsed.size());
    if (!ocspResponderID_name) {
      throw std::runtime_error(
          "[OcspIdentifier] can't decode ocspResponderID_name");
    }
    break;
  }
  case 2: // KeyHash - OCTET_STRING
  {
    choice_unparsed[0] = 0x24;
    const AsnObj tmp(choice_unparsed.data(), choice_unparsed.size());
    ocspResponderID_hash = tmp.Data();
  } break;
  default:
    throw std::runtime_error("[OcspIdentifier] unsupported ResponderID type");
  }
  // parse field 1 - producedAt
  auto time_produced = obj.at(1).StringData();
  if (!time_produced) {
    throw std::runtime_error("[OcspIdentifier] decode producedAt time failed");
  }
  producedAt = time_produced.value();
}

} // namespace pdfcsp::csp::asn