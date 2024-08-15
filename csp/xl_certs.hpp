#pragma once

#include "cert_refs.hpp"
#include "certificate.hpp"
#include "certificate_id.hpp"
#include "ocsp.hpp"
#include "resolve_symbols.hpp"
#include "revoc_refs.hpp"
#include "revoc_vals.hpp"

namespace pdfcsp::csp {
struct XLongCertsCheckResult {
  bool all_revoc_refs_have_value = false;
  bool all_cert_refs_have_value = false;
  bool signing_cert_found = false;
  bool summary = false;
};

struct XLCertsData {
  asn::CompleteCertificateRefs cert_refs;
  asn::CompleteRevocationRefs revoc_refs;
  std::vector<Certificate> cert_vals;
  asn::RevocationValues revoc_vals;
  CertificateID signers_cert;
};

using OcspReferenceValuePair =
    std::pair<asn::OcspResponsesID, asn::BasicOCSPResponse>;

using CertIterator = std::vector<Certificate>::const_iterator;

using CertReferenceValueIteratorPair =
    std::pair<asn::OtherCertID, CertIterator>;

[[nodiscard]] XLongCertsCheckResult
CheckXCerts(const XLCertsData &xdata, const PtrSymbolResolver &symbols);

[[nodiscard]] std::vector<OcspReferenceValuePair>
MatchRevocRefsToValues(const XLCertsData &xdata,
                       const PtrSymbolResolver &symbols);

[[nodiscard]] std::vector<CertReferenceValueIteratorPair>
MatchCertRefsToValueIterators(const XLCertsData &xdata,
                              const PtrSymbolResolver &symbols);

[[nodiscard]] CertIterator FindSignersCert(const XLCertsData &xdata,
                                           const PtrSymbolResolver &symbols);

} // namespace pdfcsp::csp