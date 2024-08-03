#include "certificate_id.hpp"
#include "asn1.hpp"
#include "typedefs.hpp"
#include <iostream>
#include <iterator>
#include <stdexcept>

namespace pdfcsp::csp {

CertificateID::CertificateID(BytesVector ser, std::string iss)
    : serial(std::move(ser)), issuer(std::move(iss)) {}

CertificateID::CertificateID(const asn::AsnObj &asn) {
  // explanation - Certificate2.drawio
  constexpr const char *const exl =
      "[CertificateID] Error extracting the Certificate ID from ASN object\n";
  if (asn.IsFlat() || asn.ChildsCount() == 0) {
    throw std::runtime_error(exl);
  }
  const auto &level1 = asn.GetChilds();
  if (level1[0].IsFlat() || level1[0].ChildsCount() == 0) {
    throw std::runtime_error(exl);
  }
  const auto &level2 = level1[0].GetChilds();
  if (level2[0].IsFlat() || level2[0].ChildsCount() == 0) {
    throw std::runtime_error(exl);
  }
  const auto &level3 = level2[0].GetChilds();
  if (level3.size() != 3) {
    throw std::runtime_error("[Certificate ID] wrong number of subobjects");
  }
  if (level3[0].IsFlat() || level3[0].ChildsCount() == 0) {
    throw std::runtime_error(exl);
  }
  // OBJECT IDENTIFICATOR for hashing algo
  {
    auto oid = level3[0].GetChilds()[0].GetStringData();
    if (!oid) {
      throw std::runtime_error("no OID found");
    }
    hashing_algo_oid = oid.value_or("");
    // the certificate hash
    auto hash_from_asn = level3[1].GetStringData();
    if (!hash_from_asn || hash_from_asn->empty()) {
      throw std::runtime_error("Certificate hash is empty");
    }
    hash_cert.clear();
    std::copy(hash_from_asn->cbegin(), hash_from_asn->cend(),
              std::back_inserter(hash_cert));
  }
  // get the Issuer
  {
    if (level3[2].ChildsCount() != 2 ||
        level3[2].GetChilds()[0].ChildsCount() == 0) {
      throw std::runtime_error(exl);
    }
    auto iss = level3[2].GetChilds()[0].GetChilds()[0].GetDecodedStringData();
    if (!iss || iss->empty()) {
      throw std::runtime_error(exl);
    }
    issuer = iss.value_or("");
  }
  // get the Data Hash
  serial = level3[2].GetChilds()[1].GetData();
  if (serial.empty()) {
    throw std::runtime_error(exl);
  }
}

bool CertificateID::operator==(const CertificateID &other) const noexcept {
  return issuer == other.issuer && serial == other.serial;
}

} // namespace pdfcsp::csp
