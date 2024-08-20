#include "bes_checks.hpp"
#include "message.hpp"
#include "utils_msg.hpp"
#include <stdexcept>
#include <string>

namespace pdfcsp::csp::checks {

BesChecks::BesChecks(Message *pmsg, unsigned int signer_index, bool ocsp_online)
    : msg_(pmsg), signer_index_(signer_index), ocsp_online_(ocsp_online),
      res_{} {
  if (msg_ == nullptr) {
    throw std::runtime_error(std::string(class_name) +
                             "nullptr pointer to message");
  }
}

const CheckResult &BesChecks::All() noexcept {
  SignerIndex();
  CadesTypeFind();
  return res_;
}

/// @brief Check if a signer with this index exists.
bool BesChecks::SignerIndex() noexcept {
  auto signers_count = msg_->GetSignersCount();
  if (signers_count && signers_count.value_or(0) > signer_index_) {
    res_.signer_index_ok = true;
    return true;
  }
  res_.signer_index_ok = false;
  return false;
}

/// @brief find a cades_type
void BesChecks::CadesTypeFind() noexcept {
  const CadesType msg_type = msg_->GetCadesTypeEx(signer_index_);
  res_.cades_type = msg_type;
  res_.cades_t_str = InternalCadesTypeToString(msg_type);
  if (msg_type < CadesType::kCadesBes) {
    res_.bes_fatal = true;
    res_.cades_type_ok = false;
    return;
  }
  res_.bes_fatal = false;
  res_.cades_type_ok = true;
}

} // namespace pdfcsp::csp::checks