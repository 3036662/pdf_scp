
#include "cms.hpp"
#include "asn1.hpp"
#include "asn_tsp.hpp"
#include "oids.hpp"
#include "typedefs.hpp"
#include "utils.hpp"
#include "utils_cert.hpp"
#include <algorithm>
#include <cstdint>
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

    // determine a data type
    switch (field.ParseChoiceNumber()) {
    case 0: // AnotherName
    case 4: // Name
    {
      BytesVector unparsed = field.ParseAs(AsnTag::kSequence).at(0).Unparse();
      auto decoded_issuer =
          NameBlobToStringEx(unparsed.data(), unparsed.size());
      if (!decoded_issuer) {
        throw std::runtime_error("[IssuerSerial] can't decode issuer field");
      }
      issuer = decoded_issuer.value();
      break;
    }
    case 1: // IA5String
    case 2: // IA5String
    case 6: // IA5String
    {
      const AsnObj tmp = field.ParseAs(AsnTag::kIA5String);
      issuer = std::string(tmp.Data().cbegin(), tmp.Data().cend());
      break;
    }
    case 7: // OCTET STRING
    {
      const AsnObj tmp = field.ParseAs(AsnTag::kOctetString);
      issuer = std::string(tmp.Data().cbegin(), tmp.Data().cend());
      break;
    }
    case 8: // OBJECT IDENTIFIER
    {
      const AsnObj tmp = field.ParseAs(AsnTag::kOid);
      auto decode_res = tmp.StringData();
      if (!decode_res) {
        throw std::runtime_error("[IssuerSerial] decode OID failed");
      }
      issuer = decode_res.value();
      break;
    }
    default: // EDIPartyName
      throw std::runtime_error(
          "[IssuerSerial] Unsupported type for issuer field");
    }
    // TODO(Oleg) implement EDIPartyName parsing
    // serial
    serial = obj.at(1).Data();
    // issuerUID
    if (obj.Size() == 3) {
      issuerUID = obj.at(2).Data();
    }
  }
}

CertificateList::CertificateList(const AsnObj &obj) {
  constexpr const char *const expl = "Invalid CertificateList structure";
  if (obj.Size() != 3) {
    throw std::runtime_error(expl);
  }
  // tbsCertList
  tbsCertList = TBSCertList(obj.at(0));
  signatureAlgorithm = AlgorithmIdentifier(obj.at(1));
  signatureValue = obj.at(2).Data();
  der_encoded = obj.Unparse();
}

TBSCertList::TBSCertList(const AsnObj &obj) {
  constexpr const char *const expl = "Invalid TBSCertList structure";
  if (obj.Size() < 3 || obj.Size() > 7) {
    throw std::runtime_error(expl);
  }
  // obj.PrintInfo();
  uint64_t curr_field = 0;
  if (obj.at(curr_field).AsnTag() == AsnTag::kInteger &&
      !obj.at(curr_field).Data().empty()) {
    version = static_cast<Version>(obj.at(curr_field).Data()[0]);
    ++curr_field;
  }
  // signature algo
  signature = AlgorithmIdentifier(obj.at(curr_field));
  ++curr_field;
  // issuer name
  issuer = NameBlobToStringEx(obj.at(curr_field)).value_or("");
  if (issuer.empty()) {
    throw std::runtime_error("[TBSCertList] an empty issuer");
  }
  ++curr_field;
  // thisUpdate
  if (obj.at(curr_field).AsnTag() != AsnTag::kUTCTime &&
      obj.at(curr_field).AsnTag() != AsnTag::kGeneralizedTime) {
    throw std::runtime_error(expl);
  }
  thisUpdate = obj.at(curr_field).StringData().value_or("");
  if (issuer.empty()) {
    throw std::runtime_error("[TBSCertList] an empty thisUpdate field");
  }
  ++curr_field;
  // nextUpdate [OPTIONAL]
  if (obj.at(curr_field).AsnTag() == AsnTag::kUTCTime ||
      obj.at(curr_field).AsnTag() == AsnTag::kGeneralizedTime) {
    nextUpdate = obj.at(curr_field).StringData().value_or("");
    ++curr_field;
  }
  // revokedCertificates
  if (obj.at(curr_field).AsnTag() == AsnTag::kSequence &&
      obj.at(curr_field).Size() > 0) {
    std::vector<RevocedCert> res;
    for (const auto &cert_asn : obj.at(curr_field).Childs()) {
      res.emplace_back(cert_asn);
    }
    revokedCertificates = std::move(res);
    ++curr_field;
  }
  // crlExtensions
  if (curr_field < obj.Size() && obj.at(curr_field).ParseChoiceNumber() == 0 &&
      obj.at(curr_field).Size() > 0) {
    Extensions res;
    if (obj.at(curr_field).Size() > 0) {
      for (const auto &ext : obj.at(curr_field).at(0).Childs()) {
        res.emplace_back(ext);
      }
    }
    crlExtensions = std::move(res);
  }
  der_encoded = obj.Unparse();
}

RevocedCert::RevocedCert(const AsnObj &obj) {
  // obj.PrintInfo();
  constexpr const char *const expl = "Invalid RevocedCert structure";
  if (obj.Size() < 2 || obj.Size() > 3) {
    throw std::runtime_error(expl);
  }
  // CertificateSerialNumber
  userCertificate = obj.at(0).Data();
  if (userCertificate.empty()) {
    throw std::runtime_error("[RevocedCert] empty certificate serial");
  }
  if (obj.at(1).AsnTag() != AsnTag::kUTCTime &&
      obj.at(1).AsnTag() != AsnTag::kGeneralizedTime) {
    throw std::runtime_error(expl);
  }
  // revocationDate
  revocationDate = obj.at(1).StringData().value_or("");
  if (revocationDate.empty()) {
    throw std::runtime_error("[RevocedCert] Empty revocation date");
  }
  // crlEntryExtensions
  if (obj.Size() == 3) {
    Extensions res;
    for (const auto &ext : obj.at(2).Childs()) {
      res.emplace_back(ext);
    }
    crlEntryExtensions = std::move(res);
  }
}

Extension::Extension(const AsnObj &obj) {
  constexpr const char *const expl = "[Extension] invalid structure";
  // extnID
  if (obj.Size() < 2 || obj.Size() > 3) {
    // obj.PrintInfo();
    throw std::runtime_error(expl);
  }
  if (obj.at(0).AsnTag() != AsnTag::kOid) {
    throw std::runtime_error(expl);
  }
  extnID = obj.at(0).StringData().value_or("");
  if (extnID.empty()) {
    throw std::runtime_error("[Extension] empty OID");
  }
  // critical
  uint curr_field = 1;
  if (obj.at(curr_field).AsnTag() == AsnTag::kBoolean &&
      !obj.at(curr_field).Data().empty()) {
    critical = static_cast<bool>(obj.at(curr_field).Data()[0]);
    ++curr_field;
  }
  // extnValue
  if (curr_field < obj.Size() &&
      obj.at(curr_field).AsnTag() == AsnTag::kOctetString) {
    extnValue = obj.at(curr_field).Data();
  }
}

} // namespace pdfcsp::csp::asn
