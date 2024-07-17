#pragma once

#include <string>
#include <vector>

namespace pdfcsp::csp {

struct CertificateID {
  std::vector<unsigned char> serial;
  std::string issuer;
};

} // namespace pdfcsp::csp
