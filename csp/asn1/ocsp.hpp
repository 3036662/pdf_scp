#pragma once
#include "asn1.hpp"
#include "certificate_id.hpp"
#include "typedefs.hpp"
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace pdfcsp::csp::asn {

/**
 * @brief Helper structures for parsing an OCSP response
 * @details rfc2560m /rfc6960 -  X.509 Internet Public Key Infrastructure Online
 */


/*
rfc6960
CertID          ::=     SEQUENCE {
       hashAlgorithm       AlgorithmIdentifier,
       issuerNameHash      OCTET STRING, -- Hash of issuer's DN
       issuerKeyHash       OCTET STRING, -- Hash of issuer's public key
       serialNumber        CertificateSerialNumber }
*/
struct CertID {
  std::string hashAlgorithm;
  BytesVector issuerNameHash;
  BytesVector issuerKeyHash;
  BytesVector serialNumber;

  CertID() = default;
  explicit CertID(const AsnObj &asn_cert_id);
};

enum class CertStatus : uint8_t { kGood, kRevoked, kUnknown };

/*
   SingleResponse ::= SEQUENCE {
      certID                       CertID,
      certStatus                   CertStatus,
      thisUpdate                   GeneralizedTime,
      nextUpdate         [0]       EXPLICIT GeneralizedTime OPTIONAL,
      singleExtensions   [1]       EXPLICIT Extensions OPTIONAL }
*/
struct SingleResponse {
  CertID certID;
  CertStatus certStatus = CertStatus::kUnknown;
  std::string thisUpdate;
  std::string nextUpdate;
  BytesVector singleExtensions;
  SingleResponse() = default;
  explicit SingleResponse(const AsnObj &asn_single_resp);
};


/*
   ResponseData ::= SEQUENCE {
      version              [0] EXPLICIT Version DEFAULT v1,
      responderID              ResponderID,
      producedAt               GeneralizedTime,
      responses                SEQUENCE OF SingleResponse,
      responseExtensions   [1] EXPLICIT Extensions OPTIONAL }
*/
struct ResponseData {
  uint8_t version = 0;
  std::optional<BytesVector> responderID_hash;
  std::optional<BytesVector> responderID_name;
  BytesVector producedAt; // generalizedTime
  std::vector<SingleResponse> responses;
  BytesVector responseExtensions;

  ResponseData() = default;
  explicit ResponseData(const AsnObj &asn_response_data);
};

/*
   BasicOCSPResponse       ::= SEQUENCE {
      tbsResponseData      ResponseData,
      signatureAlgorithm   AlgorithmIdentifier,
      signature            BIT STRING,
      certs                [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL }
*/
struct BasicOCSPResponse {
  ResponseData tbsResponseData;
  BytesVector resp_data_der_encoded; // for hash
  std::string signatureAlgorithm;
  BytesVector signature;
  BytesVector certs;

  BasicOCSPResponse() = default;
  explicit BasicOCSPResponse(const AsnObj &asn_basic_response);
};

/*
  ResponseBytes ::=       SEQUENCE {
       responseType   OBJECT IDENTIFIER,
       response       OCTET STRING }
*/
struct ResponseBytes {
  std::string oid; // response type
  BasicOCSPResponse response;

  ResponseBytes() = default;
  explicit ResponseBytes(const AsnObj &asn_response_bytes);
};

/*
OCSPResponseStatus ::= ENUMERATED {
       successful            (0),  --Response has valid confirmations
       malformedRequest      (1),  --Illegal confirmation request
       internalError         (2),  --Internal error in issuer
       tryLater              (3),  --Try again later
                                   --(4) is not used
       sigRequired           (5),  --Must sign the request
       unauthorized          (6)   --Request unauthorized
   }
*/
enum class OCSPResponseStatus : uint8_t {
  kSuccessful = 0,
  kMalformedRequest = 1,
  kInternalError = 2,
  kTryLater = 3,
  kSigReuired = 5,
  kUnauthorized = 7,
  kUnknown
};

/*
   OCSPResponse ::= SEQUENCE {
      responseStatus         OCSPResponseStatus,
      responseBytes          [0] EXPLICIT ResponseBytes OPTIONAL }
*/
struct OCSPResponse {
  OCSPResponseStatus responseStatus = OCSPResponseStatus::kUnknown;
  ResponseBytes responseBytes;

  explicit OCSPResponse(const AsnObj &response_root);
};

} // namespace pdfcsp::csp::asn