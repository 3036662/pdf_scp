#pragma once

#include "typedefs.hpp"
#include <string>

namespace pdfcsp::csp {

struct CheckResult {
  // CADES_BES
  bool signer_index_ok = false;
  bool cades_type_ok = false;
  bool data_hash_ok = false;
  bool computed_hash_ok = false;
  bool certificate_hash_ok = false;
  bool certificate_usage_signing = false;
  bool certificate_chain_ok = false;
  bool certificate_ocsp_ok = false;
  bool certificate_ok = false;
  bool msg_signature_ok = false;
  bool ocsp_online_used = false;
  bool bes_fatal = false;
  bool bes_all_ok = false;

  // CADES_T

  bool t_fatal = false;
  bool t_all_tsp_msg_signatures_ok = false;
  bool t_all_tsp_contents_ok = false;
  bool t_all_ok = false;

  CadesType cades_type = CadesType::kUnknown;
  std::string cades_t_str;
  std::string hashing_oid;
  BytesVector encrypted_digest;
  std::vector<time_t> times_collection;
};

} // namespace pdfcsp::csp