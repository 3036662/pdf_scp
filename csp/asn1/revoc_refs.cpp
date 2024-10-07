#include "revoc_refs.hpp"
#include "asn1.hpp"
#include "cert_refs.hpp"
#include "cms.hpp"
#include "typedefs.hpp"
#include "utils.hpp"
#include <d_name.hpp>
#include <iostream>
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

CrlIdentifier::CrlIdentifier(const AsnObj &obj) {
  constexpr const char *const expl = "[CrlIdentifier] invalid structure";
  if (obj.Size() < 2 || obj.Size() > 3) {
    throw std::runtime_error(expl);
  }
  {
    auto unparsed = obj.at(0).Unparse();
    crlissuer =
        NameBlobToStringEx(unparsed.data(), unparsed.size()).value_or("");
  }
  crlIssuedTime = obj.at(1).StringData().value_or("");
  if (obj.Size() == 3) {
    crlNumber = obj.at(2).Data();
  }
}

CrlValidatedID::CrlValidatedID(const AsnObj &obj) {
  constexpr const char *const expl =
      "[CrlValidatedID] Invalid CrlValidatedID structure";
  if (obj.Size() == 0 || obj.Size() > 2) {
    throw std::runtime_error(expl);
  }
  // crlHash
  if (obj.at(0).Size() == 2) {
    crlHash = OtherHashAlgAndValue(obj.at(0));
  } else if (obj.at(0).Size() == 1) {
    crlHash = obj.at(0).Data();
  } else {
    throw std::runtime_error(expl);
  }
  // crlIdentifier
  if (obj.Size() == 2) {
    crlIdentifier = CrlIdentifier(obj.at(1));
  }
}

/**
 * @brief Construct a new Crl Ocsp Ref:: Crl Ocsp Ref object
 * @param obj
 */
CrlOcspRef::CrlOcspRef(const AsnObj &obj) {
  for (const AsnObj &child : obj.Childs()) {
    const uint choice = child.ParseChoiceNumber();
    switch (choice) {
    case 0: {
      const AsnObj crl_list_asn = child.ParseAs(AsnTag::kSequence);
      // CRLListID res;
      if (crl_list_asn.Size() == 0 || crl_list_asn.at(0).Size() == 0) {
        throw std::runtime_error("invalid CrlOcspRef struct");
      }
      CRLListID res;
      for (const auto &crl_id_asn : crl_list_asn.at(0).at(0).Childs()) {
        res.emplace_back(crl_id_asn);
      }
      crlids = std::move(res);
      break;
    }
    case 1: {
      const AsnObj ocsp_list_asn = child.ParseAs(AsnTag::kSequence);
      OcspListID res;
      if (ocsp_list_asn.Size() == 0 || ocsp_list_asn.at(0).Size() == 0) {
        throw std::runtime_error("empty CrlOcspRef sequence");
      }
      for (const auto &resp_id_asn : ocsp_list_asn.at(0).Childs()) {
        res.emplace_back(resp_id_asn.at(0));
      }
      ocspids = std::move(res);
      break;
    }
    default:
      throw std::runtime_error("unsupported type of CrlOcspRef");
    }
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

  switch (obj.at(0).ParseChoiceNumber()) {
  case 1: // Name
  {
    ocspResponderID_name =
        DName(obj.at(0).ParseAs(AsnTag::kSequence).at(0)).DistinguishedName();
    if (!ocspResponderID_name) {
      throw std::runtime_error(
          "[OcspIdentifier] can't decode ocspResponderID_name");
    }
    break;
  }
  case 2: // KeyHash
  {
    const AsnObj tmp = obj.at(0).ParseAs(AsnTag::kSequence);
    ocspResponderID_hash = tmp.at(0).Data();
    break;
  }
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