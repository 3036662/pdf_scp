/* File: cert_refs.cpp
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

#include "cert_refs.hpp"

#include <iostream>
#include <stdexcept>

#include "asn1.hpp"
#include "cms.hpp"
#include "utils.hpp"

namespace pdfcsp::csp::asn {

OtherHashAlgAndValue::OtherHashAlgAndValue(const AsnObj &obj) {
  if (obj.Size() != 2) {
    throw std::runtime_error("Invalid OtherHashAlgAndValue structure");
  }
  hashAlgorithm = AlgorithmIdentifier(obj.at(0));
  hashValue = obj.at(1).Data();
}

OtherCertID::OtherCertID(const AsnObj &obj) {
  if (obj.Size() < 1 || obj.Size() > 2) {
    throw std::runtime_error("Invalid OtherCertID strucure");
  }
  // parse otherCertHash
  otherCertHash.emplace<OtherHashAlgAndValue>(obj.at(0));
  if (obj.Size() > 1) {
    issuerSerial = IssuerSerial(obj.at(1));
  }
}

/**
 * @brief Returns parsed revocation references
 * @param obj - AsnObj containing revocation refs
 * @return CompleteCertificateRefs
 */
CompleteCertificateRefs ParseCertRefs(const AsnObj &obj) {
  CompleteCertificateRefs res;
  if (obj.Size() == 0) {
    return res;
  }
  for (const auto &ref : obj.Childs()) {
    res.emplace_back(ref);
  }
  return res;
}

}  // namespace pdfcsp::csp::asn