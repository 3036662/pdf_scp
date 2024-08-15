#include "ocsp.hpp"
#include "asn1.hpp"
#include "resolve_symbols.hpp"
#include "utils.hpp"
#include <iostream>
#include <memory>
#include <stdexcept>

namespace pdfcsp::csp::asn {

/*
  rfc2560

   1. The certificate identified in a received response corresponds to
   that which was identified in the corresponding request;

   2. The signature on the response is valid;

   3. The identity of the signer matches the intended recipient of the
   request.

   4. The signer is currently authorized to sign the response.

   5. The time at which the status being indicated is known to be
   correct (thisUpdate) is sufficiently recent.

   6. When available, the time at or before which newer information will
   be available about the status of the certificate (nextUpdate) is
   greater than the current time.

*/

OCSPResponse::OCSPResponse(const AsnObj &response_root) {
  // status
  if (response_root.at(0).Header().asn_tag != AsnTag::kEnumerated ||
      response_root.at(0).Data().size() != 1) {
    throw std::runtime_error("invalid resonse status");
  }
  responseStatus = OCSPResponseStatus(response_root.at(0).Data()[0]);
  // responseBytes
  responseBytes = ResponseBytes(response_root.at(1).at(0));
}

ResponseBytes::ResponseBytes(const AsnObj &asn_response_bytes) {
  if (asn_response_bytes.Size() != 2 ||
      asn_response_bytes.at(0).Header().asn_tag != AsnTag::kOid ||
      asn_response_bytes.at(1).Header().asn_tag != AsnTag::kOctetString) {
    throw std::runtime_error("invalid ResponseBytes structure");
  }
  oid = asn_response_bytes.at(0).StringData().value_or("");
  if (oid != szOID_PKIX_OCSP_BASIC_SIGNED_RESPONSE) {
    throw std::runtime_error("[ResponseBytes] unknown response type OID");
  }
  // parse octet string to asn_basic response
  const AsnObj asn_basic_response(asn_response_bytes.at(1).Data().data(),
                                  asn_response_bytes.at(1).Data().size());
  response = BasicOCSPResponse(asn_basic_response);
}

BasicOCSPResponse::BasicOCSPResponse(const AsnObj &asn_basic_response)
    : der_encoded(asn_basic_response.Unparse()) {
  if (asn_basic_response.Size() < 3 ||
      asn_basic_response.at(0).Header().asn_tag != AsnTag::kSequence ||
      asn_basic_response.at(1).Header().asn_tag != AsnTag::kSequence ||
      asn_basic_response.at(2).Header().asn_tag != AsnTag::kBitString ||
      asn_basic_response.Size() > 4) {
    throw std::runtime_error("Invalid BasicOCSPResponse structure");
  }
  // [0] element is ResponseData
  tbsResponseData = ResponseData(asn_basic_response.at(0));
  resp_data_der_encoded = asn_basic_response.at(0).Unparse();
  // [1] is AlgorithmIdentifier expected szOID_CP_GOST_R3411_12_256_R3410
  signatureAlgorithm = asn_basic_response.at(1).at(0).StringData().value_or("");
  if (signatureAlgorithm.empty()) {
    throw std::runtime_error(
        "[BasicOCSPResponse] Empty signature algorithm OID");
  }
  // [2] is signature value
  signature = asn_basic_response.at(2).Data();
  // [3] is  EXPLICIT SEQUENCE OF Certificate OPTIONAL
  if (asn_basic_response.Size() > 3) {
    certs = asn_basic_response.at(3).at(0).at(0).Unparse();
  }
}

ResponseData::ResponseData(const AsnObj &asn_response_data)
    : producedAt(asn_response_data.at(1).StringData().value_or("")) {
  // [0] is Responder id
  // [1] is generalized time
  // [2] is SEQUENCE OF SingleResponse
  if (asn_response_data.Size() < 3 ||
      asn_response_data.at(0).Header().asn_tag != AsnTag::kInteger ||
      asn_response_data.at(1).Header().asn_tag != AsnTag::kGeneralizedTime ||
      asn_response_data.at(2).Header().asn_tag != AsnTag::kSequence) {
    throw std::runtime_error("Invlaid ResponseData struct");
  }
  // PARSE Choice
  const unsigned char first_byte =
      asn_response_data.at(0).Header().raw_header[0];
  switch (first_byte) {
  case 0xA1:
    responderID_name = std::string(asn_response_data.at(0).Data().cbegin(),
                                   asn_response_data.at(0).Data().cend());
    break;
  case 0xA2:
    responderID_hash = asn_response_data.at(0).Data();
    break;
  default:
    throw std::runtime_error("[ResponseData] parse choice ResponderID failed");
    break;
  }

  // save SingleResponse structs
  for (const auto &child : asn_response_data.at(2).Childs()) {
    responses.emplace_back(child);
  }
  // TODO(Oleg) parse extensions
}

SingleResponse::SingleResponse(const AsnObj &asn_single_resp) {
  if (asn_single_resp.Size() < 3 ||
      asn_single_resp.at(0).Header().asn_tag != AsnTag::kSequence ||
      asn_single_resp.at(2).Header().asn_tag != AsnTag::kGeneralizedTime) {
    throw std::runtime_error("Invalid SingleResponse struct");
  }
  // [0] is certID
  certID = CertID(asn_single_resp.at(0));
  // [1] is certStatus it can be NULL or RevokedInfo or  UnknownInfo
  auto first_byte = asn_single_resp.at(1).Header().tag;
  first_byte.reset(7);
  first_byte.reset(6);
  first_byte.reset(5);
  switch (first_byte.to_ulong()) {
  case 0:
    certStatus = CertStatus::kGood;
    break;
  case 2:
    certStatus = CertStatus::kUnknown;
    break;
  case 1:
    certStatus = CertStatus::kRevoked;
    // TODO(Oleg) parse and store RevokedInfo
  default:
    throw std::runtime_error("Unknown certificate status");
  }
  // [2] thisUpdate time
  thisUpdate = asn_single_resp.at(2).StringData().value_or("");
  // [3] nextUpdate or extensions
  if (asn_single_resp.at(3).Header().asn_tag == AsnTag::kGeneralizedTime) {
    nextUpdate = asn_single_resp.at(3).StringData().value_or("");
  }
  // TODO(oleg) parse extensions
}

CertID::CertID(const AsnObj &asn_cert_id) {
  if (asn_cert_id.Size() != 4 ||
      asn_cert_id.at(0).Header().asn_tag != AsnTag::kSequence ||
      asn_cert_id.at(1).Header().asn_tag != AsnTag::kOctetString ||
      asn_cert_id.at(2).Header().asn_tag != AsnTag::kOctetString ||
      asn_cert_id.at(3).Header().asn_tag != AsnTag::kInteger) {
    throw std::runtime_error("Invalid CertID structure");
  }
  // [0] is Hashing algo OID wrapped to sequence szOID_OIWSEC_sha1 (20bytes
  // hash)
  hashAlgorithm = asn_cert_id.at(0).at(0).StringData().value_or("");
  // [1] is Issuer name hash
  issuerNameHash = asn_cert_id.at(1).Data();
  // [2] is issuer key hash
  issuerKeyHash = asn_cert_id.at(2).Data();
  // [3] is the cert serial number
  serialNumber = asn_cert_id.at(3).Data();
}

} // namespace pdfcsp::csp::asn