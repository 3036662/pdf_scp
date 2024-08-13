#pragma once
#include "asn1.hpp"
#include "cms.hpp"
#include "typedefs.hpp"
#include <optional>
#include <variant>
#include <vector>

namespace pdfcsp::csp::asn {

/*
OtherHash ::= CHOICE {
       sha1Hash OtherHashValue,  -- This contains a SHA-1 hash
       otherHash OtherHashAlgAndValue}

OtherHashValue ::= OCTET STRING

OtherHashAlgAndValue ::= SEQUENCE {
       hashAlgorithm     AlgorithmIdentifier,
       hashValue         OtherHashValue }

*/

using OtherHashValue = BytesVector;

struct OtherHashAlgAndValue {
  AlgorithmIdentifier hashAlgorithm;
  OtherHashValue hashValue;

  OtherHashAlgAndValue() = default;
  explicit OtherHashAlgAndValue(const AsnObj &obj);
};

using OtherHash = std::variant<OtherHashValue, OtherHashAlgAndValue>;

/* RFC5216 [5.7.3.3]

CompleteCertificateRefs ::=  SEQUENCE OF OtherCertID

OtherCertID ::= SEQUENCE {
       otherCertHash            OtherHash,
       issuerSerial             IssuerSerial OPTIONAL }
*/

struct OtherCertID {
  OtherHash otherCertHash;
  std::optional<IssuerSerial> issuerSerial;

  OtherCertID() = default;
  explicit OtherCertID(const AsnObj &obj);
};

using CompleteCertificateRefs = std::vector<OtherCertID>;

[[nodiscard]] CompleteCertificateRefs ParseCertRefs(const AsnObj &obj);

} // namespace pdfcsp::csp::asn