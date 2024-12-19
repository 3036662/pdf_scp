/* File: cert_common_info.cpp  
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


#include "cert_common_info.hpp"
#include "asn1.hpp"
#include "d_name.hpp"
#include "utils.hpp"
#include "utils_cert.hpp"
#include <algorithm>
#include <boost/json/object.hpp>
#include <iostream>
#include <iterator>
#include <sstream>
#include <stdexcept>

namespace pdfcsp::csp {

CertCommonInfo::CertCommonInfo(const CERT_INFO *p_info) {
  if (p_info == nullptr) {
    throw std::runtime_error("[CertCommonInfo]  p_info = nullptr ");
  }
  // version
  version = p_info->dwVersion;
  // serial
  {
    const BytesVector ser{p_info->SerialNumber.pbData,
                          p_info->SerialNumber.pbData +
                              p_info->SerialNumber.cbData};
    std::reverse_copy(ser.begin(), ser.end(), std::back_inserter(serial));
  }
  // sig algo
  if (p_info->SignatureAlgorithm.pszObjId != nullptr) {
    sig_algo = p_info->SignatureAlgorithm.pszObjId;
  }

  if (p_info->SubjectPublicKeyInfo.Algorithm.pszObjId != nullptr) {
    pub_key_algo = p_info->SubjectPublicKeyInfo.Algorithm.pszObjId;
  }
  // issuer
  {
    const asn::AsnObj obj(p_info->Issuer.pbData, p_info->Issuer.cbData);
    issuer = asn::DName(obj).DistinguishedName();
    const asn::DName dname(obj);
    issuer = dname.DistinguishedName();
    issuer_common_name = dname.commonName.value_or("");
  }
  // subject
  {
    const asn::AsnObj obj(p_info->Subject.pbData, p_info->Subject.cbData);
    const asn::DName dname(obj);
    subject = asn::DName(obj).DistinguishedName();
    subj_common_name = dname.commonName.value_or("");
  }
  // notBefore and not after
  not_before = FileTimeToTimeT(p_info->NotBefore);
  not_after = FileTimeToTimeT(p_info->NotAfter);
  // keyUsage
  key_usage = utils::cert::CertificateKeyUsageRawBits(p_info);
  // keyUsage string
  key_usage_bits_str = utils::cert::CertificateKeyUsageRawBitsToStr(p_info);
}

void CertCommonInfo::PrintToStdOut() const noexcept {
  std::cout << "version = " << version << "\n";
  std::cout << "serial: ";
  PrintBytes(serial);
  std::cout << "sig_algo =" << sig_algo << "\n";
  std::cout << "issuer: " << issuer << "\n";
  std::cout << "subject: " << subject << "\n";
  std::cout << std::dec << "not before " << not_before << "\n";
  std::cout << "not after " << not_after << "\n";
  std::cout << "key usage " << key_usage_bits_str << "\n";
}

json::object CertCommonInfo::ToJson() const noexcept {
  json::object res;
  res["version"] = version;
  res["serial"] = VecBytesStringRepresentation(serial);
  res["issuer"] = issuer;
  res["issuer_common_name"] = issuer_common_name;
  res["subject"] = subject;
  res["subject_common_name"] = subj_common_name;
  res["not_before"] = not_before;
  res["not_before_readable"] = TimeTToString(not_before);
  res["not_after"] = not_after;
  res["not_after_readable"] = TimeTToString(not_after);
  res["key_usage"] = key_usage_bits_str;
  res["trust_status"] = trust_status.value_or(false);
  return res;
}

void CertCommonInfo::SetTrustStatus(const PtrSymbolResolver &symbols,
                                    _CERT_INFO *p_info, DWORD dwErrorStatus,
                                    FILETIME *p_time,
                                    bool ignore_revoc_check_errors) {
  if (!symbols || p_info == nullptr) {
    throw std::runtime_error("invalid parameters (nullptr)");
  }
  trust_status = dwErrorStatus == 0;
  // ignore revocation check error
  if (dwErrorStatus == 0x40 && ignore_revoc_check_errors) {
    trust_status = true;
  }
  // validate time (just in case
  if (symbols->dl_CertVerifyTimeValidity(p_time, p_info) != 0) {
    trust_status = false;
  }
}

} // namespace pdfcsp::csp