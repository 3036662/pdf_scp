/* File: revoc_refs.hpp
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
#include <optional>
#include <vector>

#include "asn1.hpp"
#include "cert_refs.hpp"
#include "typedefs.hpp"

namespace pdfcsp::csp::asn {

/* CrlIdentifier ::= SEQUENCE {
    crlissuer                 Name,
    crlIssuedTime             UTCTime,
    crlNumber                 INTEGER OPTIONAL } */
struct CrlIdentifier {
  std::string crlissuer;
  std::string crlIssuedTime;
  std::optional<BytesVector> crlNumber;
  explicit CrlIdentifier(const AsnObj &obj);
};

/* CrlValidatedID ::=  SEQUENCE {
     crlHash                   OtherHash,
     crlIdentifier             CrlIdentifier OPTIONAL } */
struct CrlValidatedID {
  OtherHash crlHash;
  std::optional<CrlIdentifier> crlIdentifier;
  explicit CrlValidatedID(const AsnObj &obj);
};

/* CRLListID ::=  SEQUENCE {
    crls        SEQUENCE OF CrlValidatedID }*/
using CRLListID = std::vector<CrlValidatedID>;

/*
  ResponderID ::= CHOICE {
      byName               [1] Name,
      byKey                [2] KeyHash }

  KeyHash ::= OCTET STRING

  OcspIdentifier ::= SEQUENCE {
  ocspResponderID    ResponderID,
      -- As in OCSP response data
   producedAt         GeneralizedTime
   -- As in OCSP response data
} */
struct OcspIdentifier {
  std::optional<std::string> ocspResponderID_name;
  std::optional<BytesVector> ocspResponderID_hash;
  std::string producedAt;

  OcspIdentifier() = default;
  explicit OcspIdentifier(const AsnObj &obj);
};

/* OcspResponsesID ::=  SEQUENCE {
    ocspIdentifier              OcspIdentifier,
    ocspRepHash                 OtherHash    OPTIONAL } */
struct OcspResponsesID {
  OcspIdentifier ocspIdentifier;
  std::optional<OtherHash> ocspRepHash;

  OcspResponsesID() = default;
  explicit OcspResponsesID(const AsnObj &obj);
};

/* OcspListID ::=  SEQUENCE {
    ocspResponses        SEQUENCE OF OcspResponsesID } */
using OcspListID = std::vector<OcspResponsesID>;

/* OtherRevRefs ::= SEQUENCE {
       otherRevRefType   OtherRevRefType,
       otherRevRefs      ANY DEFINED BY otherRevRefType
    } */
struct OtherRevRefs {
  std::string OtherRevRefType;  // oid
  BytesVector otherRevRefs;
};

/* CrlOcspRef ::= SEQUENCE {
      crlids      [0]   CRLListID    OPTIONAL,
      ocspids     [1]   OcspListID   OPTIONAL,
      otherRev    [2]   OtherRevRefs OPTIONAL
   } */
struct CrlOcspRef {
  std::optional<CRLListID> crlids;
  std::optional<OcspListID> ocspids;
  std::optional<OtherRevRefs> otherRev;

  CrlOcspRef() = default;
  explicit CrlOcspRef(const AsnObj &obj);
};

// CompleteRevocationRefs ::=  SEQUENCE OF CrlOcspRef
using CompleteRevocationRefs = std::vector<CrlOcspRef>;

/**
 * @brief Returns parsed revocation refs
 * @param obj - AsnObj, with revocation refs to parse
 * @return CompleteRevocationRefs
 */
CompleteRevocationRefs ParseRevocRefs(const AsnObj &obj);

/*
RevocationValues ::=  SEQUENCE {
      crlVals          [0] SEQUENCE OF CertificateList OPTIONAL,
      ocspVals         [1] SEQUENCE OF BasicOCSPResponse OPTIONAL,
      otherRevVals     [2] OtherRevVals OPTIONAL }

OtherRevVals ::= SEQUENCE {
      OtherRevValType   OtherRevValType,
      OtherRevVals      ANY DEFINED BY OtherRevValType }
*/

}  // namespace pdfcsp::csp::asn