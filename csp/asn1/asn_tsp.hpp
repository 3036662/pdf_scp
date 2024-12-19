/* File: asn_tsp.hpp
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
namespace pdfcsp::csp::asn {

/**
 * @brief TimeStape-related sturctures
 */

/* RFC 3161
Accuracy ::= SEQUENCE {
         seconds        INTEGER              OPTIONAL,
         millis     [0] INTEGER  (1..999)    OPTIONAL,
         micros     [1] INTEGER  (1..999)    OPTIONAL  } */
struct Accuracy {
  std::optional<BytesVector> seconds;
  std::optional<BytesVector> millis;
  std::optional<BytesVector> micros;

  Accuracy() = default;
  explicit Accuracy(const AsnObj &obj);
};

/* MessageImprint ::= SEQUENCE  {
        hashAlgorithm                AlgorithmIdentifier,
        hashedMessage                OCTET STRING  }
*/
struct MessageImprint {
  AlgorithmIdentifier hashAlgorithm;
  BytesVector hashedMessage;

  MessageImprint() = default;
  explicit MessageImprint(const AsnObj &obj);
};

/*
TSTInfo ::= SEQUENCE  {
   version                      INTEGER  { v1(1) },
   policy                       TSAPolicyId,
   messageImprint               MessageImprint,
     -- MUST have the same value as the similar field in
     -- TimeStampReq
   serialNumber                 INTEGER,
    -- The serialNumber field is an integer assigned by the TSA to each
       TimeStampToken.
    -- Time-Stamping users MUST be ready to accommodate integers
    -- up to 160 bits.
   genTime                      GeneralizedTime,
   accuracy                     Accuracy                 OPTIONAL,
   ordering                     BOOLEAN             DEFAULT FALSE,
   nonce                        INTEGER                  OPTIONAL,
     -- MUST be present if the similar field was present
     -- in TimeStampReq.  In that case it MUST have the same value.
   tsa                          [0] GeneralName          OPTIONAL, (CHOICE)
   extensions                   [1] IMPLICIT Extensions   OPTIONAL  } (SEQ)

*/
struct TSTInfo {
  uint version = 0;
  std::string policy;  // OID
  MessageImprint messageImprint;
  BytesVector serialNumber;
  std::string genTime;
  std::optional<Accuracy> accuracy;
  bool ordering = false;
  std::optional<BytesVector> nonce;
  std::optional<BytesVector> tsa;
  std::optional<Extension> extensions;

  TSTInfo() = default;
  explicit TSTInfo(const AsnObj &obj);
};

/**
 * @brief Decode a Tsp Signature Attribute
 * @throws runtime_error if constructor fails
 */
struct TspAttribute : ContentInfo<SignedData<TSTInfo>> {
  explicit TspAttribute(const AsnObj &asn_obj);
};

/* RFC 3161 APPENDIEX C
SignatureTimeStampToken ::= TimeStampToken
TimeStampToken ::= ContentInfo
*/

/*
TSAPolicyId ::= OBJECT IDENTIFIER
*/

}  // namespace pdfcsp::csp::asn
