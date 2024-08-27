#pragma once

#include "d_name.hpp"
#include "typedefs.hpp"
#include <string>

namespace pdfcsp::csp::checks {

struct CheckResult {
  // CADES_BES
  bool signer_index_ok = false;
  bool cades_type_ok = false;
  bool data_hash_ok = false;
  bool computed_hash_ok = false;
  bool certificate_hash_ok = false;
  bool certificate_usage_signing = false;
  bool certificate_chain_ok = false;
  bool certificate_time_ok = false;
  bool certificate_ocsp_ok = false;
  bool certificate_ocsp_check_failed = false;
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

  // CADES_X
  bool x_fatal = false;
  bool x_esc_tsp_ok = false;
  bool x_data_ok = false;
  bool x_all_revoc_refs_have_value = false;
  bool x_all_cert_refs_have_value = false;
  bool x_signing_cert_found = false;
  bool x_signing_cert_chain_ok = false;
  bool x_singers_cert_has_ocsp_response = false;
  bool x_all_ocsp_responses_valid = false;
  bool x_all_crls_valid = false;
  bool x_all_ok = false;

  // PKSC_7
  bool pks_fatal = false;
  bool pks_all_ok = false;

  bool check_summary = false;

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

  [[nodiscard]] std::string Str() const noexcept;
};

} // namespace pdfcsp::csp::checks