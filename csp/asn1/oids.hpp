/* File: oids.hpp  
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

// rfc5280 4.2.1.9
constexpr const char *const kOID_id_ce_basicConstraints = "2.5.29.19";

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
    "1.2.840.113549.1.9.16.2.22";

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

// rfc3280#appendix-A

// id-at OBJECT IDENTIFIER ::= { joint-iso-ccitt(2) ds(5) 4 }

// id-at-name              AttributeType ::= { id-at 41 }
constexpr const char *const kOid_id_at_name = "2.5.4.41";

// id-at-surname           AttributeType ::= { id-at 4 }
constexpr const char *const kOid_id_at_surname = "2.5.4.4";

// id-at-givenName         AttributeType ::= { id-at 42 }
constexpr const char *const kOid_id_at_givenName = "2.5.4.42";

// id-at-initials          AttributeType ::= { id-at 43 }
constexpr const char *const kOid_id_at_initials = "2.5.4.43";

// id-at-generationQualifier AttributeType ::= { id-at 44 }
constexpr const char *const kOid_id_at_generationQualifier = "2.5.4.44";

// id-at-organizationalUnitName AttributeType ::= { id-at 11 }
constexpr const char *const kOid_id_at_organizationalUnitName = "2.5.4.11";

// id-at-countryName       AttributeType ::= { id-at 6 }
constexpr const char *const kOid_id_at_countryName = "2.5.4.6";

// id-at-serialNumber      AttributeType ::= { id-at 5 }
constexpr const char *const kOid_id_at_serialNumber = "2.5.4.5";

// id-at-commonName        AttributeType ::= { id-at 3 }
constexpr const char *const kOid_id_at_commonName = "2.5.4.3";

// id-at-localityName      AttributeType ::= { id-at 7 }
constexpr const char *const kOid_id_at_localityName = "2.5.4.7";

// id-at-stateOrProvinceName AttributeType ::= { id-at 8 }
constexpr const char *const kOid_id_at_stateOrProvinceName = "2.5.4.8";

// id_at_streeAddress  AttributeType ::= { id-at 9 }
constexpr const char *const kOid_id_at_streetAddress = "2.5.4.9";

// id-at-organizationName  AttributeType ::= { id-at 10 }
constexpr const char *const kOid_id_at_organizationName = "2.5.4.10";

// id-at-title             AttributeType ::= { id-at 12 }
constexpr const char *const kOid_id_at_title = "2.5.4.12";

// id-at-dnQualifier       AttributeType ::= { id-at 46 }
constexpr const char *const kOid_id_at_dnQualifier = "2.5.4.46";

// id-at-pseudonym         AttributeType ::= { id-at 65 }
constexpr const char *const kOid_id_at_pseudonym = "2.5.4.65";

// id-domainComponent      AttributeType ::=
//                          { 0 9 2342 19200300 100 1 25 }

// pkcs-9 OBJECT IDENTIFIER ::=
//       { iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) 9 }

// id-emailAddress          AttributeType ::= { pkcs-9 1 }
constexpr const char *const kOid_id_emailAddress = "1.2.840.113549.1.9.1";

// id inn 1.2.643.100.4 || 1.2.643.3.131.1.1
constexpr const char *const kOid_id_inn = "1.2.643.100.4";
constexpr const char *const kOid_id_inn2 = "1.2.643.3.131.1.1";
constexpr const char *const kOid_id_snils = "1.2.643.100.3";

// id ogrn 1.2.643.100.1
constexpr const char *const kOid_id_ogrn = "1.2.643.100.1";

// id-ce-subjectAltName OBJECT IDENTIFIER ::=  { id-ce 17 }

// rfcrfc3852
// id-signingTime OBJECT IDENTIFIER ::= { iso(1) member-body(2)
//          us(840) rsadsi(113549) pkcs(1) pkcs9(9) 5 }
constexpr const char *const kOid_id_signingTime = "1.2.840.113549.1.9.5";

} // namespace pdfcsp::csp::asn