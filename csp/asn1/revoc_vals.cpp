#include "asn1.hpp"
#include <iostream>
#include <revoc_vals.hpp>
#include <stdexcept>

namespace pdfcsp::csp::asn {

RevocationValues::RevocationValues(const AsnObj &obj) {
  if (obj.Size() == 0) {
    return;
  }
  for (const auto &child : obj.Childs()) {
    const uint choice = child.ParseChoiceNumber();
    // TODO(Oleg) implement choice 0 and 2
    if (choice != 1) {
      throw std::runtime_error("[RevocationValues] unsupported choice");
    }
    std::vector<BasicOCSPResponse> res;
    const AsnObj ocsp_vals_asn = obj.at(0).ParseAs(AsnTag::kSequence).at(0);
    for (const auto &ocsp_val : ocsp_vals_asn.Childs()) {
      res.emplace_back(ocsp_val);
    }
    ocspVals = std::move(res);
  }
}

} // namespace pdfcsp::csp::asn