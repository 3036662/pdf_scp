#pragma once

#include "cert_refs.hpp"
#include "certificate.hpp"
#include "certificate_id.hpp"
#include "ocsp.hpp"
#include "resolve_symbols.hpp"
#include "revoc_refs.hpp"
#include "revoc_vals.hpp"
#include <vector>

namespace pdfcsp::csp {
struct XLongCertsCheckResult {
  bool all_revoc_refs_have_value = false;
  bool all_cert_refs_have_value = false;
  bool signing_cert_found = false;
  bool all_ocsp_responses_valid = false;
  bool summary = false;
};

/**
 * @brief Storage for X_LONG cerificates and revocations
 */
struct XLCertsData {
  asn::CompleteCertificateRefs cert_refs;
  asn::CompleteRevocationRefs revoc_refs;
  std::vector<Certificate> cert_vals;
  asn::RevocationValues revoc_vals;
  CertificateID signers_cert;
  time_t last_timestamp;
};

using OcspReferenceValuePair =
    std::pair<asn::OcspResponsesID, asn::BasicOCSPResponse>;

using CertIterator = std::vector<Certificate>::const_iterator;

using CertReferenceValueIteratorPair =
    std::pair<asn::OtherCertID, CertIterator>;

[[nodiscard]] XLongCertsCheckResult
CheckXCerts(const XLCertsData &xdata, const PtrSymbolResolver &symbols);

/**
 * @brief Matches each revocation reference to the coressponding OCSP response
 * @param xdata XLCertsData structure
 * @param symbols
 * @return std::vector<OcspReferenceValuePair>
 */
[[nodiscard]] std::vector<OcspReferenceValuePair>
MatchRevocRefsToValues(const XLCertsData &xdata,
                       const PtrSymbolResolver &symbols);

/**
 * @brief Matches each certificate referense to the corresponding certificate
 * @param xdata XLCertsData structure
 * @param symbols
 * @return std::vector<CertReferenceValueIteratorPair>
 */
[[nodiscard]] std::vector<CertReferenceValueIteratorPair>
MatchCertRefsToValueIterators(const XLCertsData &xdata,
                              const PtrSymbolResolver &symbols);

/**
 * @brief Finds a signer's certificate in XLCertsData
 * @param xdata XLCertsData struct
 * @param symbols
 * @return CertIterator  iterator to signer's certificate
 */
[[nodiscard]] CertIterator FindSignersCert(const XLCertsData &xdata,
                                           const PtrSymbolResolver &symbols);

[[nodiscard]] bool
CheckAllRevocValues(const XLCertsData &xdata,
                    const std::vector<OcspReferenceValuePair> &revocation_data,
                    const PtrSymbolResolver &symbols);

/**
 * @brief Find a certificate by it's public key SHA1 hash
 * @param xdata XLCertsData struct
 * @param sha1 BytesVector with sha1 hash to look for
 * @param symbols
 * @return CertIterator iterator to the corresponding certificate
 */
CertIterator FindCertByPublicKeySHA1(const XLCertsData &xdata,
                                     const BytesVector &sha1,
                                     const PtrSymbolResolver &symbols);

} // namespace pdfcsp::csp