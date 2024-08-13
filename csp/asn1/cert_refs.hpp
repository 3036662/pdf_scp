#pragma once
#include "asn1.hpp"
#include "cms.hpp"
#include "typedefs.hpp"
#include <optional>
#include <variant>
#include <vector>

namespace pdfcsp::csp::asn {

// OtherHashValue ::= OCTET STRING
using OtherHashValue = BytesVector;

/* OtherHashAlgAndValue ::= SEQUENCE {
       hashAlgorithm     AlgorithmIdentifier,
       hashValue         OtherHashValue } */
struct OtherHashAlgAndValue {
  AlgorithmIdentifier hashAlgorithm;
  OtherHashValue hashValue;

  OtherHashAlgAndValue() = default;
  explicit OtherHashAlgAndValue(const AsnObj &obj);
};

/* OtherHash ::= CHOICE {
       sha1Hash OtherHashValue,  -- This contains a SHA-1 hash
       otherHash OtherHashAlgAndValue} */
using OtherHash = std::variant<OtherHashValue, OtherHashAlgAndValue>;

/* OtherCertID ::= SEQUENCE {
       otherCertHash            OtherHash,
       issuerSerial             IssuerSerial OPTIONAL } */
struct OtherCertID {
  OtherHash otherCertHash;
  std::optional<IssuerSerial> issuerSerial;

  OtherCertID() = default;
  explicit OtherCertID(const AsnObj &obj);
};

// CompleteCertificateRefs ::=  SEQUENCE OF OtherCertID
using CompleteCertificateRefs = std::vector<OtherCertID>;

/**
 * @brief Returns parsed revocation references
 * @param obj - AsnObj containing revocation refs
 * @return CompleteCertificateRefs 
 */
[[nodiscard]] CompleteCertificateRefs ParseCertRefs(const AsnObj &obj);

} // namespace pdfcsp::csp::asn