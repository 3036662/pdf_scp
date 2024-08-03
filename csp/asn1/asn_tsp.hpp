#pragma once

#include "asn1.hpp"
namespace pdfcsp::csp::asn {

/**
 * @brief TimeStape-related sturctures
 */

/* RFC 3161 APPENDIEX C
SignatureTimeStampToken ::= TimeStampToken

TimeStampToken ::= ContentInfo

*/

/**
 * @brief Decode a Tsp Signature Attribute
 * @throws runtime_error if constructor fails
 */
struct TspAttribute {

  explicit TspAttribute(const AsnObj &asn_obj);
};

} // namespace pdfcsp::csp::asn
