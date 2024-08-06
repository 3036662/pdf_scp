#pragma once

namespace pdfcsp::csp::asn {

// RFC 3161  TSP unsigned attribute
constexpr const char *const kOID_id_aa_signatureTimeStampToken =
    "1.2.840.113549.1.9.16.2.14";
// RFC 5652
constexpr const char *const kOID_SignedData = "1.2.840.113549.1.7.2";

// RFC 3161 id-ct-TSTInfo
constexpr const char *const kOID_tSTInfo = "1.2.840.113549.1.9.16.1.4";

// RFC5280 4.2.1
// id-ce   OBJECT IDENTIFIER ::=  { joint-iso-ccitt(2) ds(5) 29 }
constexpr const char *const kOID_id_ce = "2.5.29";
//  Extended Key Usage
constexpr const char *const kOID_id_ce_extKeyUsage = "2.5.29.37";

// RFC3280
// id-pkix  OBJECT IDENTIFIER  ::=
//         { iso(1) identified-organization(3) dod(6) internet(1)
//                    security(5) mechanisms(5) pkix(7) }
constexpr const char *const kOID_id_pkix = "1.3.6.1.5.5.7";

// id-kp OBJECT IDENTIFIER ::= { id-pkix 3 }
constexpr const char *const kOID_id_kp = "1.3.6.1.5.5.7.3";

// rfc6960 id-kp-OCSPSigning OBJECT IDENTIFIER ::= { id-kp 9 }
constexpr const char *const kOID_id_kp_OCSPSigning = "1.3.6.1.5.5.7.3.9";

} // namespace pdfcsp::csp::asn