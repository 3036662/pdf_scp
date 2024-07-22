#pragma once

#include "asn1.hpp"
#include "typedefs.hpp"
#include <string>
#include <vector>

namespace pdfcsp::csp {

struct CertificateID {
  BytesVector serial;
  std::string issuer;
  std::string hashing_algo_oid;
  BytesVector hash_cert;
  explicit CertificateID(const AsnObj &asn);
  explicit CertificateID(BytesVector ser, std::string iss);
};

} // namespace pdfcsp::csp
