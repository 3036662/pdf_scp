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
  CertificateID() = default;
  explicit CertificateID(const asn::AsnObj &asn);
  explicit CertificateID(BytesVector ser, std::string iss);

  bool operator==(const CertificateID &other) const noexcept;
};

} // namespace pdfcsp::csp
