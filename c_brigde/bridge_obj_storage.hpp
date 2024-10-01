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
};

} // namespace pdfcsp::c_bridge