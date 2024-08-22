#pragma once

#include "cert_refs.hpp"
#include "certificate.hpp"
#include "certificate_id.hpp"
#include "cms.hpp"
#include "ocsp.hpp"
#include "revoc_refs.hpp"
#include "revoc_vals.hpp"
#include <vector>

namespace pdfcsp::csp::checks {

/**
 * @brief Storage for X_LONG cerificates and revocations
 */
struct XLCertsData {
  asn::CompleteCertificateRefs cert_refs;
  asn::CompleteRevocationRefs revoc_refs;
  std::vector<Certificate> cert_vals;
  asn::RevocationValues revoc_vals;
  CertificateID signers_cert;
  time_t last_timestamp = 0;
};

using OcspReferenceValuePair =
    std::pair<asn::OcspResponsesID, asn::BasicOCSPResponse>;

using CrlReferenceValuePair =
    std::pair<asn::CrlValidatedID, asn::CertificateList>;

using CertIterator = std::vector<Certificate>::const_iterator;

using CertReferenceValueIteratorPair =
    std::pair<asn::OtherCertID, CertIterator>;

} // namespace pdfcsp::csp::checks