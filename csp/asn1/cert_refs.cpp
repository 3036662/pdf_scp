#include "cert_refs.hpp"
#include "asn1.hpp"
#include "cms.hpp"
#include "utils.hpp"
#include <iostream>
#include <stdexcept>

namespace pdfcsp::csp::asn {

OtherHashAlgAndValue::OtherHashAlgAndValue(const AsnObj &obj) {
  if (obj.Size() != 2) {
    throw std::runtime_error("Invalid OtherHashAlgAndValue structure");
  }
  hashAlgorithm = AlgorithmIdentifier(obj.at(0));
  hashValue = obj.at(1).Data();
}

OtherCertID::OtherCertID(const AsnObj &obj) {
  if (obj.Size() < 1 || obj.Size() > 2) {
    throw std::runtime_error("Invalid OtherCertID strucure");
  }
  // parse otherCertHash
  otherCertHash.emplace<OtherHashAlgAndValue>(obj.at(0));
  if (obj.Size() > 1) {
    issuerSerial = IssuerSerial(obj.at(1));
  }
}

/**
 * @brief Returns parsed revocation references
 * @param obj - AsnObj containing revocation refs
 * @return CompleteCertificateRefs
 */
CompleteCertificateRefs ParseCertRefs(const AsnObj &obj) {
  CompleteCertificateRefs res;
  if (obj.Size() == 0) {
    return res;
  }
  for (const auto &ref : obj.Childs()) {
    res.emplace_back(ref);
  }
  return res;
}

} // namespace pdfcsp::csp::asn