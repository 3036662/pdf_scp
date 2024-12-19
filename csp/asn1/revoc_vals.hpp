/* File: revoc_vals.hpp
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

#include <vector>

#include "asn1.hpp"
#include "cms.hpp"
#include "ocsp.hpp"
#include "typedefs.hpp"
namespace pdfcsp::csp::asn {

// OtherRevVals ::= SEQUENCE {
//       OtherRevValType   OtherRevValType,
//       OtherRevVals      ANY DEFINED BY OtherRevValType }
struct OtherRevVals {
  std::string OtherRevValType;  // oid
  BytesVector OtherRevVals;
};

// RevocationValues ::=  SEQUENCE {
//      crlVals           [0] SEQUENCE OF CertificateList OPTIONAL,
//      ocspVals          [1] SEQUENCE OF BasicOCSPResponse OPTIONAL,
//      otherRevVals      [2] OtherRevVals OPTIONAL
//    }
struct RevocationValues {
  std::vector<CertificateList> crlVals;
  std::vector<BasicOCSPResponse> ocspVals;
  std::optional<OtherRevVals> otherRevVals;

  RevocationValues() = default;
  explicit RevocationValues(const AsnObj &obj);
};

}  // namespace pdfcsp::csp::asn