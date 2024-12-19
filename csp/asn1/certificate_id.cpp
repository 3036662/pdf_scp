/* File: certificate_id.cpp
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

#include "certificate_id.hpp"

#include <stdexcept>

#include "asn1.hpp"
#include "typedefs.hpp"
#include "utils.hpp"

namespace pdfcsp::csp::asn {

CertificateID::CertificateID(BytesVector ser, std::string iss)
  : serial(std::move(ser)), issuer(std::move(iss)) {}

CertificateID::CertificateID(const asn::AsnObj &asn) {
  // explanation - Certificate2.drawio
  constexpr const char *const exl =
    "[CertificateID] Error extracting the Certificate ID from ASN object\n";
  if (asn.IsFlat() || asn.Size() == 0) {
    throw std::runtime_error(exl);
  }
  const auto &level1 = asn.Childs();
  if (level1[0].IsFlat() || level1[0].Size() == 0) {
    throw std::runtime_error(exl);
  }
  const auto &level2 = level1[0].Childs();
  if (level2[0].IsFlat() || level2[0].Size() == 0) {
    throw std::runtime_error(exl);
  }
  const auto &level3 = level2[0].Childs();
  if (level3.size() != 3) {
    throw std::runtime_error("[Certificate ID] wrong number of subobjects");
  }
  if (level3[0].IsFlat() || level3[0].Size() == 0) {
    throw std::runtime_error(exl);
  }
  // OBJECT IDENTIFICATOR for hashing algo
  {
    auto oid = level3[0].Childs()[0].StringData();
    if (!oid) {
      throw std::runtime_error("no OID found");
    }
    hashing_algo_oid = oid.value_or("");
    // the certificate hash
    auto hash_from_asn = level3[1].Data();
    if (hash_from_asn.empty()) {
      throw std::runtime_error("Certificate hash is empty");
    }
    hash_cert = std::move(hash_from_asn);
  }
  // get the Issuer
  {
    if (level3[2].Size() != 2 || level3[2].Childs()[0].Size() == 0) {
      throw std::runtime_error(exl);
    }
    const asn::AsnObj &issuer_asn = level3[2].Childs()[0].Childs()[0];
    auto decoded_res = NameBlobToStringEx(issuer_asn.at(0));
    //  gives valgrind errors
    // auto decoded_res = NameRawToString(issuer_asn.GetData(), symbols);
    if (!decoded_res) {
      throw std::runtime_error(exl);
    }
    issuer = decoded_res.value();
  }
  // get the Data Hash
  serial = level3[2].Childs()[1].Data();
  if (serial.empty()) {
    throw std::runtime_error(exl);
  }
}

bool CertificateID::operator==(const CertificateID &other) const noexcept {
  return issuer == other.issuer && serial == other.serial;
}

}  // namespace pdfcsp::csp::asn
