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
  // issuer
  {
    const asn::AsnObj obj(p_info->Issuer.pbData, p_info->Issuer.cbData);
    issuer = asn::DName(obj).DistinguishedName();
  }
  // subject
  {
    const asn::AsnObj obj(p_info->Subject.pbData, p_info->Subject.cbData);
    subject = asn::DName(obj).DistinguishedName();
  }
  // notBefore and not after
  not_before = FileTimeToTimeT(p_info->NotBefore);
  not_after = FileTimeToTimeT(p_info->NotAfter);
  // keyUsage
  key_usage = utils::cert::CertificateKeyUsageRawBits(p_info);
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
  std::cout << "key usage " << key_usage << "\n";
}

json::object CertCommonInfo::ToJson() const noexcept {
  json::object res;
  res["version"] = version;
  res["serial"] = VecBytesStringRepresentation(serial);
  res["issuer"] = issuer;
  res["subject"] = subject;
  res["not_before"] = not_before;
  res["not_after"] = not_after;
  res["key_usage"] = key_usage;
  res["trust_status"] = trust_status.value_or(false);
  return res;
}

} // namespace pdfcsp::csp