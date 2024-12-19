/* File: certificate_id.hpp  
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

#include "asn1.hpp"
#include "typedefs.hpp"
#include <string>

namespace pdfcsp::csp::asn {

struct CertificateID {
  BytesVector serial;
  std::string issuer;
  std::string hashing_algo_oid;
  BytesVector hash_cert;
  CertificateID() = default;
  explicit CertificateID(const asn::AsnObj &asn);
  explicit CertificateID(BytesVector ser, std::string iss);

  bool operator==(const CertificateID &other) const noexcept;
};

} // namespace pdfcsp::csp::asn
