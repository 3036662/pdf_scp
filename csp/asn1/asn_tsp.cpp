/* File: asn_tsp.cpp
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

#include "asn_tsp.hpp"

#include <iostream>
#include <memory>
#include <stdexcept>

#include "asn1.hpp"
#include "cms.hpp"
#include "oids.hpp"
#include "resolve_symbols.hpp"

namespace pdfcsp::csp::asn {

Accuracy::Accuracy(const AsnObj &obj) {
  if (obj.GetAsnTag() != AsnTag::kSequence) {
    throw std::runtime_error("[Accuracy] Invalid ASN1 type");
  }
  if (obj.Size() > 0) {
    seconds = obj.at(0).Data();
  }
  if (obj.Size() > 1) {
    millis = obj.at(1).Data();
  }
  if (obj.Size() > 2) {
    micros = obj.at(2).Data();
  }
}

TspAttribute::TspAttribute(const AsnObj &asn_obj) {
  constexpr const char *const expl = "Invalid TSP attribute structure";
  // expected OID and SEQENCE
  if (asn_obj.IsFlat() || asn_obj.GetAsnTag() != AsnTag::kSequence ||
      asn_obj.Size() != 2 || asn_obj.at(0).GetAsnTag() != AsnTag::kOid ||
      asn_obj.at(0).StringData().value_or("") != kOID_SignedData ||
      asn_obj.at(1).IsFlat()) {
    throw std::runtime_error(expl);
  }
  contentType = asn_obj.at(0).StringData().value_or("");
  // expected SignedData
  const AsnObj &signed_data = asn_obj.at(1).at(0);
  if (signed_data.Size() < 4 || signed_data.Size() > 6 ||
      signed_data.at(0).GetAsnTag() != AsnTag::kInteger ||
      signed_data.at(1).GetAsnTag() != AsnTag::kSet ||
      signed_data.at(2).GetAsnTag() != AsnTag::kSequence) {
    throw std::runtime_error(expl);
  }
  content = SignedData<TSTInfo>(signed_data);
}

MessageImprint::MessageImprint(const AsnObj &obj) {
  const std::string func_name = "[MessageImprint] ";
  if (obj.GetAsnTag() != AsnTag::kSequence || obj.Size() != 2) {
    throw std::runtime_error(func_name + "Invalid ASN1 structure");
  }
  hashAlgorithm = AlgorithmIdentifier(obj.at(0));
  hashedMessage = obj.at(1).Data();
}

TSTInfo::TSTInfo(const AsnObj &obj) {
  const std::string func_name = "[TSTInfo] ";
  if (obj.Size() == 0) {
    throw std::runtime_error(func_name + "no childs in ASN1 object");
  }
  const AsnObj &tst_encoded = obj.at(0);
  // if obj is OCTET_STRING - decode this string to asn obj;
  const bool decoded_needed = tst_encoded.GetAsnTag() == AsnTag::kOctetString;
  // decode an encoded tstinfo if needed
  const AsnObj tst_decoded = decoded_needed ? AsnObj(tst_encoded.Data().data(),
                                                     tst_encoded.Data().size())
                                            : AsnObj();
  // use tst_decoded if needed
  const AsnObj &tst = decoded_needed ? tst_decoded : obj;
  if (tst.GetAsnTag() != AsnTag::kSequence || tst.Size() < 6) {
    throw std::runtime_error(func_name + "invalid tSTInfo structure");
  }
  // version
  {
    const AsnObj &vers = tst.at(0);
    if (vers.GetAsnTag() != AsnTag::kInteger || vers.Data().size() > 1) {
      throw std::runtime_error(func_name + "invalid version");
    }
    version = vers.Data()[0];
  }
  // policy OID
  {
    const AsnObj &pol = tst.at(1);
    if (pol.GetAsnTag() != AsnTag::kOid ||
        pol.StringData().value_or("").empty()) {
      throw std::runtime_error(" Invalid TSAPolicyId");
    }
    policy = pol.StringData().value_or("");
  }
  // messageImprint
  messageImprint = MessageImprint(tst.at(2));
  // serialNumber
  serialNumber = tst.at(3).Data();
  if (serialNumber.empty()) {
    throw std::runtime_error(func_name + "invalid TimeStampToken serial");
  }
  // genTime
  genTime = tst.at(4).StringData().value_or("");
  if (genTime.empty()) {
    throw std::runtime_error(func_name + "Invalid getTime");
  }
  // accuracy
  if (tst.at(5).GetAsnTag() == AsnTag::kSequence && tst.at(5).Size() > 0 &&
      tst.at(5).at(0).GetAsnTag() == AsnTag::kInteger) {
    accuracy = Accuracy(tst.at(5));
  }
  // TODO(Oleg) parse ordering,nonce,tsa,extensions
}

}  // namespace pdfcsp::csp::asn