#pragma once

#include "bool_results.hpp"
#include "d_name.hpp"
#include "typedefs.hpp"
#include <ctime>
#include <string>

namespace pdfcsp::csp::checks {

struct CheckResult {
  BoolResults bres;
  CadesType cades_type = CadesType::kUnknown;
  std::string cades_t_str;
  std::string hashing_oid;
  BytesVector encrypted_digest;
  std::vector<time_t> times_collection;
  std::vector<time_t> x_times_collection;
  std::vector<BytesVector> revoced_cers_serials;
  asn::DName cert_issuer;
  asn::DName cert_subject;
  BytesVector cert_public_key;
  BytesVector cert_serial;
  time_t signers_time = 0;
  time_t cert_not_before = 0;
  time_t cert_not_after = 0;

  [[nodiscard]] std::string Str() const noexcept;
};

} // namespace pdfcsp::csp::checks