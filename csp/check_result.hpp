#pragma once

#include "typedefs.hpp"
#include <string>

namespace pdfcsp::csp {

struct CheckResult {
  bool signer_index_ok = false;
  bool cades_type_ok = false;
  bool bes_fatal = true;
  // bool ocsp_online_used = false;

  CadesType cades_type = CadesType::kUnknown;
  std::string cades_t_str;
};

} // namespace pdfcsp::csp