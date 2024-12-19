/* File: cert_refs.hpp  
Copyright (C) Basealt LLC,  2024
Author: Oleg Proskurin, <proskurinov@basealt.ru>

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with this program; if not, write to the Free Software Foundation,
Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/


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