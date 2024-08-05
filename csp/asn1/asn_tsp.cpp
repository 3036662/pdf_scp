#include "asn_tsp.hpp"
#include "asn1.hpp"
#include "cms.hpp"
#include "oids.hpp"
#include "resolve_symbols.hpp"
#include <iostream>
#include <memory>
#include <stdexcept>

namespace pdfcsp::csp::asn {

Accuracy::Accuracy(const AsnObj &obj) {
  if (obj.GetAsnTag() != AsnTag::kSequence) {
    throw std::runtime_error("[Accuracy] Invalid ASN1 type");
  }
  if (obj.ChildsCount() > 0) {
    seconds = obj.at(0).GetData();
  }
  if (obj.ChildsCount() > 1) {
    millis = obj.at(1).GetData();
  }
  if (obj.ChildsCount() > 2) {
    micros = obj.at(2).GetData();
  }
}

TspAttribute::TspAttribute(const AsnObj &asn_obj) {
  constexpr const char *const expl = "Invalid TSP attribute structure";
  // expected OID and SEQENCE
  if (asn_obj.IsFlat() || asn_obj.GetAsnTag() != AsnTag::kSequence ||
      asn_obj.ChildsCount() != 2 || asn_obj.at(0).GetAsnTag() != AsnTag::kOid ||
      asn_obj.at(0).GetStringData().value_or("") != OID_SignedData ||
      asn_obj.at(1).IsFlat()) {
    throw std::runtime_error(expl);
  }
  contentType = asn_obj.at(0).GetDecodedStringData().value_or("");
  // expected SignedData
  const AsnObj &signed_data = asn_obj.at(1).at(0);
  if (signed_data.ChildsCount() < 4 || signed_data.ChildsCount() > 6 ||
      signed_data.at(0).GetAsnTag() != AsnTag::kInteger ||
      signed_data.at(1).GetAsnTag() != AsnTag::kSet ||
      signed_data.at(2).GetAsnTag() != AsnTag::kSequence) {
    std::cout << signed_data.ChildsCount() << "\n";
    throw std::runtime_error(expl);
  }
  content = SignedData<TSTInfo>(signed_data);
}

MessageImprint::MessageImprint(const AsnObj &obj) {
  const std::string func_name = "[MessageImprint] ";
  if (obj.GetAsnTag() != AsnTag::kSequence || obj.ChildsCount() != 2) {
    throw std::runtime_error(func_name + "Invalid ASN1 structure");
  }
  hashAlgorithm = AlgorithmIdentifier(obj.at(0));
  hashedMessage = obj.at(1).GetData();
}

TSTInfo::TSTInfo(const AsnObj &obj) {
  const std::string func_name = "[TSTInfo] ";
  const AsnObj &tst_encoded = obj.at(0);
  if (tst_encoded.GetAsnTag() != AsnTag::kOctetString) {
    throw std::runtime_error(
        func_name +
        "Invalide type of TSTInfo content, OCTET string is expected");
  }
  // decode an encoded tstinfo
  const AsnObj tst(tst_encoded.GetData().data(), tst_encoded.GetData().size(),
                   std::make_shared<ResolvedSymbols>());
  if (tst.GetAsnTag() != AsnTag::kSequence || tst.ChildsCount() < 6) {
    throw std::runtime_error(func_name + "invalid tSTInfo structure");
  }
  std::cout << "obj " << tst.get_asn_header().TagStr() << "\n";
  std::cout << "childs" << tst.ChildsCount() << "\n";
  // version
  {
    const AsnObj &vers = tst.at(0);
    if (vers.GetAsnTag() != AsnTag::kInteger || vers.GetData().size() > 1) {
      throw std::runtime_error(func_name + "invalid version");
    }
    version = vers.GetData()[0];
  }
  // policy OID
  {
    const AsnObj &pol = tst.at(1);
    if (pol.GetAsnTag() != AsnTag::kOid ||
        pol.GetStringData().value_or("").empty()) {
      throw std::runtime_error(" Invalid TSAPolicyId");
    }
    policy = pol.GetStringData().value_or("");
  }
  // messageImprint
  messageImprint = MessageImprint(tst.at(2));
  // serialNumber
  serialNumber = tst.at(3).GetData();
  if (serialNumber.empty()) {
    throw std::runtime_error(func_name + "invalid TimeStampToken serial");
  }
  // genTime
  genTime = tst.at(4).GetStringData().value_or("");
  if (genTime.empty()) {
    throw std::runtime_error(func_name + "Invalid getTime");
  }
  // accuracy
  if (tst.at(5).GetAsnTag() == AsnTag::kSequence &&
      tst.at(5).ChildsCount() > 0 &&
      tst.at(5).at(0).GetAsnTag() == AsnTag::kInteger) {
    accuracy = Accuracy(tst.at(5));
  }
  // TODO(Oleg) parse ordering,nonce,tsa,extensions
}

} // namespace pdfcsp::csp::asn