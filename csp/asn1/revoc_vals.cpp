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