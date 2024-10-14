#pragma once
#include "bool_results.hpp"
#include "bridge_obj_storage.hpp"
#include "typedefs.hpp"
#include <cstddef>
#include <cstdint>

namespace pdfcsp::c_bridge {

struct CPodParam {
  uint64_t *byte_range_arr = nullptr;
  uint64_t byte_ranges_size = 0;
  const unsigned char *raw_signature_data = nullptr;
  uint64_t raw_signature_size = 0;
  const char *file_path = nullptr;
  uint64_t file_path_size = 0;
};

// pod c-language container to pass
// pdfcsp::csp::checks::CheckResult struct
struct CPodResult {
  pdfcsp::csp::checks::BoolResults bres;
  pdfcsp::csp::CadesType cades_type = pdfcsp::csp::CadesType::kUnknown;
  const char *cades_t_str = nullptr;
  const char *hashing_oid = nullptr;
  unsigned char *encrypted_digest = nullptr;
  size_t encrypted_digest_size = 0;
  time_t *times_collection = nullptr;
  size_t times_collection_size = 0;
  time_t *x_times_collection = nullptr;
  size_t x_times_collection_size = 0;
  const char *cert_issuer_dname = nullptr;
  const char *cert_subject_dname = nullptr;

  // cert_info - issuer
  const char *issuer_common_name = nullptr;
  const char *issuer_email = nullptr;
  const char *issuer_organization = nullptr;
  // cert_info - subject
  const char *subj_common_name = nullptr;
  const char *subj_email = nullptr;
  const char *subj_organization = nullptr;
  // cert_chain
  const char *cert_chain_json = nullptr;
  // tspinfo
  const char *tsp_json_info = nullptr;
  // ocsp info
  const char *signers_cert_ocsp_json_info = nullptr;

  unsigned char *cert_public_key = nullptr;
  size_t cert_public_key_size = 0;
  unsigned char *cert_serial = nullptr;
  size_t cert_serial_size = 0;
  time_t signers_time = 0;
  time_t cert_not_before = 0;
  time_t cert_not_after = 0;

  BrigeObjStorage *p_stor = nullptr;
};

}; // namespace pdfcsp::c_bridge