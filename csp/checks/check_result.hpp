#pragma once

#include "bool_results.hpp"
#include "d_name.hpp"
#include "typedefs.hpp"
#include <ctime>
#include <string>
#include <sys/types.h>

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
  BytesVector cert_der_encoded;
  std::string signers_chain_json;
  std::string tsp_json_info;
  std::string signers_cert_ocsp_json_info;
  time_t signers_time = 0;
  time_t cert_not_before = 0;
  time_t cert_not_after = 0;
  uint signers_cert_version = 0;
  uint64_t signers_cert_key_usage = 0;

  [[nodiscard]] std::string Str() const noexcept;
};

} // namespace pdfcsp::csp::checks