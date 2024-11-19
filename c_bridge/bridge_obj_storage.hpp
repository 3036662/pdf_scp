#pragma once
#include <string>
#include <vector>

namespace pdfcsp::c_bridge {

struct BrigeObjStorage {
  std::string cades_t_str;
  std::string hashing_oid;
  std::vector<time_t> times_collection;
  std::vector<time_t> x_times_collection;
  std::vector<unsigned char> encrypted_digest;
  std::string cert_issuer;
  std::string cert_subject;
  std::vector<unsigned char> cert_public_key;
  std::vector<unsigned char> cert_serial;
  std::vector<unsigned char> cert_der_encoded;
  std::string cert_chain_json;
  std::string tsp_json_info;
  std::string signers_cert_ocsp_json_info;

  // cert_info - issuer
  std::string issuer_common_name;
  std::string issuer_email;
  std::string issuer_organization;
  // cert_info - subject
  std::string subj_common_name;
  std::string subj_email;
  std::string subj_organization;

  // json certificate list
  std::string user_certifitate_list_json;

  // raw signature (sign result)
  std::vector<unsigned char> raw_signature;
  // common error sring
  std::string err_string;
};

} // namespace pdfcsp::c_bridge