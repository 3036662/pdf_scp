#pragma once

#include "asn1.hpp"
#include "cms.hpp"
#include "ocsp.hpp"
#include "typedefs.hpp"
#include <vector>
namespace pdfcsp::csp::asn {

// OtherRevVals ::= SEQUENCE {
//       OtherRevValType   OtherRevValType,
//       OtherRevVals      ANY DEFINED BY OtherRevValType }
struct OtherRevVals {
  std::string OtherRevValType; // oid
  BytesVector OtherRevVals;
};

// RevocationValues ::=  SEQUENCE {
//      crlVals           [0] SEQUENCE OF CertificateList OPTIONAL,
//      ocspVals          [1] SEQUENCE OF BasicOCSPResponse OPTIONAL,
//      otherRevVals      [2] OtherRevVals OPTIONAL
//    }
struct RevocationValues {
  std::vector<CertificateList> crlVals;
  std::vector<BasicOCSPResponse> ocspVals;
  std::optional<OtherRevVals> otherRevVals;

  RevocationValues() = default;
  explicit RevocationValues(const AsnObj &obj);
};

} // namespace pdfcsp::csp::asn