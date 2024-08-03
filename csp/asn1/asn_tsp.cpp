#include "asn_tsp.hpp"
#include "asn1.hpp"
#include "oids.hpp"
#include <iostream>
#include <stdexcept>

namespace pdfcsp::csp::asn {

TspAttribute::TspAttribute(const AsnObj &asn_obj) {
  constexpr const char *const expl = "Invalid TSP attribute structure";
  // expected OID and SEQENCE
  if (asn_obj.IsFlat() || asn_obj.GetAsnTag() != AsnTag::kSequence ||
      asn_obj.ChildsCount() != 2 || asn_obj.at(0).GetAsnTag() != AsnTag::kOid ||
      asn_obj.at(0).GetStringData().value_or("") != OID_SignedData ||
      asn_obj.at(1).IsFlat()) {
    throw std::runtime_error(expl);
  }
  // expected SignedData
  const AsnObj &signed_data = asn_obj.at(1).at(0);
  if (signed_data.ChildsCount() < 4 || signed_data.ChildsCount() > 6 ||
      signed_data.at(0).GetAsnTag() != AsnTag::kInteger ||
      signed_data.at(1).GetAsnTag() != AsnTag::kSet ||
      signed_data.at(2).GetAsnTag() != AsnTag::kSequence) {
    std::cout << signed_data.ChildsCount() << "\n";
    throw std::runtime_error(expl);
  }
}

} // namespace pdfcsp::csp::asn