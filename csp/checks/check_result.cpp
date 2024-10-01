#include "check_result.hpp"
#include "utils_msg.hpp"
#include <sstream>

namespace pdfcsp::csp::checks {

std::string CheckResult::Str() const noexcept {
  std::ostringstream builder;
  builder << "signer_index_ok " << bres.signer_index_ok << "\n";
  builder << "cades_type_ok " << bres.cades_type_ok << "\n";
  builder << "data_hash_ok " << bres.data_hash_ok << "\n";
  builder << "computed_hash_ok " << bres.computed_hash_ok << "\n";
  builder << "certificate_hash_ok " << bres.certificate_hash_ok << "\n";
  builder << "certificate_usage_signing " << bres.certificate_usage_signing
          << "\n";
  builder << "certificate_chain_ok " << bres.certificate_chain_ok << "\n";
  builder << "certificate_time_ok " << bres.certificate_time_ok << "\n";
  builder << "certificate_ocsp_ok " << bres.certificate_ocsp_ok << "\n";
  builder << "certificate_ocsp_check_failed "
          << bres.certificate_ocsp_check_failed << "\n";
  builder << "certificate_ok " << bres.certificate_ok << "\n";
  builder << "msg_signature_ok " << bres.msg_signature_ok << "\n";
  builder << "ocsp_online_used " << bres.ocsp_online_used << "\n";
  builder << "bes_fatal " << bres.bes_fatal << "\n";
  builder << "bes_all_ok " << bres.bes_all_ok << "\n";
  builder << "\n T CHECKS \n";

  builder << "t_fatal " << bres.t_fatal << "\n";
  builder << "t_all_tsp_msg_signatures_ok " << bres.t_all_tsp_msg_signatures_ok
          << "\n";
  builder << "t_all_tsp_contents_ok " << bres.t_all_tsp_contents_ok << "\n";
  builder << "t_all_ok " << bres.t_all_ok << "\n";

  builder << "\n X CHECKS \n";
  builder << "x_fatal " << bres.x_fatal << "\n";
  builder << "x_esc_tsp_ok " << bres.x_esc_tsp_ok << "\n";
  builder << "x_data_ok " << bres.x_data_ok << "\n";
  builder << "x_all_revoc_refs_have_value " << bres.x_all_revoc_refs_have_value
          << "\n";
  builder << "x_all_cert_refs_have_value " << bres.x_all_cert_refs_have_value
          << "\n";
  builder << "x_signing_cert_found " << bres.x_signing_cert_found << "\n";
  builder << "x_signing_cert_chain_ok " << bres.x_signing_cert_chain_ok << "\n";
  builder << "x_singers_cert_has_ocsp_response "
          << bres.x_singers_cert_has_ocsp_response << "\n";
  builder << "x_all_ocsp_responses_valid " << bres.x_all_ocsp_responses_valid
          << "\n";
  builder << "x_all_crls_valid " << bres.x_all_crls_valid << "\n";
  builder << "x_all_ok " << bres.x_all_ok << "\n";
  builder << "\n PKS CHECKS \n";
  builder << "pks_fatal " << bres.pks_fatal << "\n";
  builder << "pks_fatal " << bres.pks_fatal << "\n";
  builder << "\n SUMMARY \n";
  builder << "check_summary " << bres.check_summary << "\n";
  builder << "CADES_TYPE " << cades_t_str << "\n";
  builder << "cert_issuer " << cert_issuer.DistinguishedName() << "\n";
  builder << "cert_subject " << cert_subject.DistinguishedName() << "\n";
  builder << "signers_time " << signers_time << "\n";
  builder << "certificate notBefore " << cert_not_before << "\n";
  builder << "certificate notAfter " << cert_not_after << "\n";
  return builder.str();
}

} // namespace pdfcsp::csp::checks