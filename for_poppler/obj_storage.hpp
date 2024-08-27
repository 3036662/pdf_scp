#pragma once
#include <string>
#include <vector>

namespace pdfcsp::poppler {

using BytesVector = std::vector<unsigned char>;

struct ObjStorage {
  std::string issuer_common_name;
  std::string issuer_distinguished_name;
  std::string issuer_email;
  std::string issuer_organization;
  std::string subj_common_name;
  std::string subj_distinguished_name;
  std::string subj_email;
  std::string subj_organization;
  BytesVector public_key;
  BytesVector cert_serial;
  BytesVector cert_der;
  std::string cert_nick;
  std::string signers_name;
  std::string signer_subject_dn;
  BytesVector signature;
};

} // namespace pdfcsp::poppler