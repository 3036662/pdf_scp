#include "check_result.hpp"
#include "utils_msg.hpp"
#include <sstream>

namespace pdfcsp::csp::checks {

std::string CheckResult::Str() const noexcept {
  std::ostringstream builder;
  builder << "signer_index_ok " << signer_index_ok << "\n";
  builder << "cades_type_ok " << cades_type_ok << "\n";
  builder << "data_hash_ok " << data_hash_ok << "\n";
  builder << "computed_hash_ok " << computed_hash_ok << "\n";
  builder << "certificate_hash_ok " << certificate_hash_ok << "\n";
  builder << "certificate_usage_signing " << certificate_usage_signing << "\n";
  builder << "certificate_chain_ok " << certificate_chain_ok << "\n";
  builder << "certificate_time_ok " << certificate_time_ok << "\n";
  builder << "certificate_ocsp_ok " << certificate_ocsp_ok << "\n";
  builder << "certificate_ocsp_check_failed " << certificate_ocsp_check_failed
          << "\n";
  builder << "certificate_ok " << certificate_ok << "\n";
  builder << "msg_signature_ok " << msg_signature_ok << "\n";
  builder << "ocsp_online_used " << ocsp_online_used << "\n";
  builder << "bes_fatal " << bes_fatal << "\n";
  builder << "bes_all_ok " << bes_all_ok << "\n";
  builder << "\n T CHECKS \n";

  builder << "t_fatal " << t_fatal << "\n";
  builder << "t_all_tsp_msg_signatures_ok " << t_all_tsp_msg_signatures_ok
          << "\n";
  builder << "t_all_tsp_contents_ok " << t_all_tsp_contents_ok << "\n";
  builder << "t_all_ok " << t_all_ok << "\n";

  builder << "\n X CHECKS \n";
  builder << "x_fatal " << x_fatal << "\n";
  builder << "x_esc_tsp_ok " << x_esc_tsp_ok << "\n";
  builder << "x_data_ok " << x_data_ok << "\n";
  builder << "x_all_revoc_refs_have_value " << x_all_revoc_refs_have_value
          << "\n";
  builder << "x_all_cert_refs_have_value " << x_all_cert_refs_have_value
          << "\n";
  builder << "x_signing_cert_found " << x_signing_cert_found << "\n";
  builder << "x_signing_cert_chain_ok " << x_signing_cert_chain_ok << "\n";
  builder << "x_singers_cert_has_ocsp_response "
          << x_singers_cert_has_ocsp_response << "\n";
  builder << "x_all_ocsp_responses_valid " << x_all_ocsp_responses_valid
          << "\n";
  builder << "x_all_crls_valid " << x_all_crls_valid << "\n";
  builder << "x_all_ok " << x_all_ok << "\n";
  builder << "\n PKS CHECKS \n";
  builder << "pks_fatal " << pks_fatal << "\n";
  builder << "pks_fatal " << pks_fatal << "\n";
  builder << "\n SUMMARY \n";
  builder << "check_summary " << check_summary << "\n";
  builder << "CADES_TYPE" << cades_t_str << "\n";
  builder << "cert_issuer" << cert_issuer.DistinguishedName() << "\n";
  builder << "cert_subject" << cert_subject.DistinguishedName() << "\n";
  return builder.str();
}

} // namespace pdfcsp::csp::checks