/* File: revoc_vals.cpp  
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


#include "asn1.hpp"
#include "cms.hpp"
#include <iostream>
#include <revoc_vals.hpp>
#include <stdexcept>
#include <vector>

namespace pdfcsp::csp::asn {

RevocationValues::RevocationValues(const AsnObj &obj) {
  if (obj.Size() == 0) {
    return;
  }
  for (const auto &child : obj.Childs()) {
    const uint choice = child.ParseChoiceNumber();
    switch (choice) {
    case 0: // crlVals
    {
      std::vector<CertificateList> res;
      const AsnObj cert_lists_asn = child.ParseAs(AsnTag::kSequence);
      if (cert_lists_asn.Childs().empty()) {
        return;
      }
      for (const auto &list_asn : cert_lists_asn.at(0).Childs()) {
        res.emplace_back(list_asn);
      }
      crlVals = std::move(res);
      // cert_list_asn.PrintInfo();
      break;
    }
    case 1: { // ocspVals
      std::vector<BasicOCSPResponse> res;
      const AsnObj ocsp_vals_asn = child.ParseAs(AsnTag::kSequence).at(0);
      for (const auto &ocsp_val : ocsp_vals_asn.Childs()) {
        res.emplace_back(ocsp_val);
      }
      ocspVals = std::move(res);
      break;
    }
    default:
      throw std::runtime_error("[RevocationValues] unsupported choice");
    }
  }
}

} // namespace pdfcsp::csp::asn