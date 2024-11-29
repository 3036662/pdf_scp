#include "d_name.hpp"
#include "asn1.hpp"
#include "logger_utils.hpp"
#include "oids.hpp"
#include "utils.hpp"
#include <iostream>
#include <stdexcept>

namespace pdfcsp::csp::asn {

// NOLINTNEXTLINE(readability-function-cognitive-complexity)
DName::DName(const AsnObj &obj) {
  if (obj.Size() == 0) {
    return;
  }
  auto logger = logger::InitLog();
  for (const auto &child : obj.Childs()) {
    if (child.Size() == 0) {
      continue;
    }
    const AsnObj &comp = child.at(0);
    if (comp.Size() != 2 || comp.at(0).GetAsnTag() != AsnTag::kOid) {
      throw std::runtime_error("[asn::DName] invalid structure");
    }
    auto opt_oid = comp.at(0).StringData();
    if (!opt_oid || opt_oid->empty()) {
      throw std::runtime_error("[asn::DName] empty oid");
    }
    const std::string &oid = opt_oid.value();
    const auto &opt_val = comp.at(1).StringData();
    if (!opt_val) {
      throw std::runtime_error("[asn::DName] parse value failed");
    }
    const std::string &val = opt_val.value();
    if (oid == kOid_id_at_name) {
      name = val;
      continue;
    }
    if (oid == kOid_id_at_surname) {
      surname = val;
      continue;
    }

    if (oid == kOid_id_at_givenName) {
      givenName = val;
      continue;
    }
    if (oid == kOid_id_at_initials) {
      initials = val;
      continue;
    }
    if (oid == kOid_id_at_generationQualifier) {
      generationQualifier = val;
      continue;
    }
    if (oid == kOid_id_at_organizationalUnitName) {
      organizationalUnitName = val;
      continue;
    }
    if (oid == kOid_id_at_countryName) {
      countryName = val;
      continue;
    }
    if (oid == kOid_id_at_serialNumber) {
      serialNumber = val;
      continue;
    }
    if (oid == kOid_id_at_commonName) {
      commonName = val;
      continue;
    }
    if (oid == kOid_id_at_localityName) {
      localityName = val;
      continue;
    }
    if (oid == kOid_id_at_stateOrProvinceName) {
      stateOrProvinceName = val;
      continue;
    }
    if (oid == kOid_id_at_organizationName) {
      organizationName = val;
      continue;
    }
    if (oid == kOid_id_at_title) {
      title = val;
      continue;
    }
    if (oid == kOid_id_at_dnQualifier) {
      dnQualifier = val;
      continue;
    }
    if (oid == kOid_id_at_pseudonym) {
      pseudonym = val;
      continue;
    }
    if (oid == kOid_id_emailAddress) {
      emailAddress = val;
      continue;
    }
    if (oid == kOid_id_inn || oid == kOid_id_inn2) {
      inn = val;
      continue;
    }
    if (oid == kOid_id_ogrn) {
      ogrn = val;
      continue;
    }
    if (oid == kOid_id_at_streetAddress) {
      streetAddress = val;
      continue;
    }
    if (oid == kOid_id_snils) {
      snils = val;
      continue;
    }
    if (logger) {
      logger->warn("UNPARSED OID = {} VALUE = {}", oid, val);
    }
    unknownOidVals.emplace_back(oid, val);
  }
}

// rfc1779 Table 1
std::string DName::DistinguishedName() const noexcept {
  std::string res;
  if (ogrn) {
    res += "ОРГН=";
    res += ogrn.value();
  }
  if (inn) {
    if (!res.empty()) {
      res += ", ";
    }
    res += "ИНН=";
    res += inn.value();
  }
  if (streetAddress) {
    if (!res.empty()) {
      res += ", ";
    }
    res += "STREET=";
    res += streetAddress.value();
  }
  if (countryName) {
    if (!res.empty()) {
      res += ", ";
    }
    res += "C=";
    res += countryName.value();
  }
  if (stateOrProvinceName) {
    if (!res.empty()) {
      res += ", ";
    }
    res += "S=";
    res += stateOrProvinceName.value();
  }
  if (localityName) {
    if (!res.empty()) {
      res += ", ";
    }
    res += "L=";
    res += localityName.value();
  }
  if (organizationName) {
    if (!res.empty()) {
      res += ", ";
    }
    res += "O=";
    res += organizationName.value();
  }
  if (commonName) {
    if (!res.empty()) {
      res += ", ";
    }
    res += "CN=";
    res += commonName.value();
  }

  if (snils) {
    if (!res.empty()) {
      res += ", ";
    }
    res += "SNILS=";
    res += snils.value();
  }

  return res;
}

std::string DName::SimpleString() const noexcept {
  std::string res;
  if (inn) {
    res += inn.value();
  }
  if (ogrn) {
    if (!res.empty()) {
      res += ", ";
    }
    res += ogrn.value();
  }
  if (countryName) {
    if (!res.empty()) {
      res += ", ";
    }
    res += countryName.value();
  }
  if (stateOrProvinceName) {
    if (!res.empty()) {
      res += ", ";
    }
    res += stateOrProvinceName.value();
  }
  if (localityName) {
    if (!res.empty()) {
      res += ", ";
    }
    res += localityName.value();
  }
  if (streetAddress) {
    if (!res.empty()) {
      res += ", ";
    }
    res += streetAddress.value();
  }
  if (organizationName) {
    if (!res.empty()) {
      res += ", ";
    }
    res += organizationName.value();
  }
  if (commonName) {
    if (!res.empty()) {
      res += ", ";
    }
    res += commonName.value();
  }

  if (snils) {
    if (!res.empty()) {
      res += ", ";
    }
    res += "SNILS=";
    res += snils.value();
  }

  return res;
}

} // namespace pdfcsp::csp::asn