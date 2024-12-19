/* File: xl_certs.hpp  
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

#include "cert_refs.hpp"
#include "certificate.hpp"
#include "certificate_id.hpp"
#include "cms.hpp"
#include "ocsp.hpp"
#include "revoc_refs.hpp"
#include "revoc_vals.hpp"
#include "store_hanler.hpp"
#include <memory>
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
  asn::CertificateID signers_cert;
  time_t last_timestamp = 0;
  std::unique_ptr<StoreHandler> tmp_store_;
};

using OcspReferenceValuePair =
    std::pair<asn::OcspResponsesID, asn::BasicOCSPResponse>;

using CrlReferenceValuePair =
    std::pair<asn::CrlValidatedID, asn::CertificateList>;

using CertIterator = std::vector<Certificate>::const_iterator;

using CertReferenceValueIteratorPair =
    std::pair<asn::OtherCertID, CertIterator>;

} // namespace pdfcsp::csp::checks