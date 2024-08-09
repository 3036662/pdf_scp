#pragma once

namespace pdfcsp::csp::asn {

// RFC 3161  TSP unsigned attribute
// Several instances of this attribute may occur with an ES
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

// rfc3161
// id-kp-timeStamping OBJECT IDENTIFIER ::= {iso(1)
//                    identified-organization(3) dod(6)
//                    internet(1) security(5) mechanisms(5) pkix(7)
//                    kp (3) timestamping (8)}
constexpr const char *const kOID_id_kp_timeStamping = "1.3.6.1.5.5.7.3.8";

// rfc5280 id-ce-keyUsage OBJECT IDENTIFIER ::=  { id-ce 15 }
constexpr const char *const kOID_id_ce_keyUsage = "2.5.29.15";

// CADES_C

// RFC 52126 [6.2.1]
// id-aa-ets-certificateRefs OBJECT IDENTIFIER ::= { iso(1) member-body(2)
// us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) id-aa(2) 21}
// Only a single instance of this attribute shall occur with an electronic
// signature
constexpr const char *const kOID_id_aa_ets_certificateRefs =
    "1.2.840.113549.1.9.16.2.21";

// RFC 52126 [6.2.2]
// id-aa-ets-revocationRefs OBJECT IDENTIFIER ::= { iso(1) member-body(2)
// us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) id-aa(2) 22}
// Only a single instance of this attribute shall occur with an electronic
// signature
constexpr const char *const kOID_id_aa_ets_revocationRefs =
    "1.2.840.113549.1.9.16.2.21";

// RFC 52126 [6.3.3]
// id-aa-ets-certValues OBJECT IDENTIFIER ::= { iso(1) member-body(2)
// us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) id-aa(2) 23}
// Only a single instance of this attribute shall occur with an electronic
// signature
constexpr const char *const kOID_id_aa_ets_certValues =
    "1.2.840.113549.1.9.16.2.23";

// RFC 52126 [6.3.4]
// id-aa-ets-revocationValues OBJECT IDENTIFIER ::= { iso(1)
// member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-9(9)
// smime(16) id-aa(2) 24}
// Only asingle instance of this attribute shall occur with an ES
constexpr const char *const kOID_id_aa_ets_revocationValues =
    "1.2.840.113549.1.9.16.2.24";

// RFC 52126 [6.3.5]
// id-aa-ets-escTimeStamp OBJECT IDENTIFIER ::= { iso(1) member-body(2)
// us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) id-aa(2) 25}
// Several instances of this attribute may occur with an electronic signature
// from different TSAs.
constexpr const char *const kOid_id_aa_ets_escTimeStamp =
    "1.2.840.113549.1.9.16.2.25";

} // namespace pdfcsp::csp::asn