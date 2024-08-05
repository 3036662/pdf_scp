#pragma once

namespace pdfcsp::csp::asn {

// RFC 3161  TSP unsigned attribute
constexpr const char *const OID_id_aa_signatureTimeStampToken =
    "1.2.840.113549.1.9.16.2.14";
// RFC 5652
constexpr const char *const OID_SignedData = "1.2.840.113549.1.7.2";

// RFC 3161 id-ct-TSTInfo
constexpr const char *const OID_tSTInfo = "1.2.840.113549.1.9.16.1.4";

} // namespace pdfcsp::csp::asn