#include "altcsp.hpp"
#include "cert_common_info.hpp"
#include "message.hpp"
#include "store_hanler.hpp"
#include <exception>
#include <iostream>
#include <memory>

namespace pdfcsp::csp {

// get Message object
PtrMsg Csp::OpenDetached(const BytesVector &message) noexcept {
  try {
    return std::make_shared<Message>(dl_, message, MessageType::kDetached);
  } catch (const std::exception &ex) {
    Log(ex.what());
    return nullptr;
  }
}

std::vector<CertCommonInfo> Csp::GetCertList() noexcept {
  std::vector<CertCommonInfo> res;
  try {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-cstyle-cast)
    const StoreHandler store(CERT_STORE_PROV_SYSTEM,
                             CERT_SYSTEM_STORE_CURRENT_USER |
                                 CERT_STORE_OPEN_EXISTING_FLAG |
                                 CERT_STORE_READONLY_FLAG,
                             L"MY", dl_);
    PCCERT_CONTEXT p_cert_context = nullptr;
    while ((p_cert_context = dl_->dl_CertEnumCertificatesInStore(
                store.RawHandler(), p_cert_context)) != nullptr) {
      if (p_cert_context->pCertInfo != nullptr) {
        res.emplace_back(p_cert_context->pCertInfo);
      }
    }
  } catch (const std::exception &ex) {
    Log(std::string("[GetCertList]") + ex.what());
    return {};
  }
  return res;
};

// -------------------------- private -----------------------------------

void Csp::Log(const char *msg) const noexcept {
  if (std_err_flag_) {
    std::cerr << "[CSP]" << msg << "\n";
  }
}

inline void Csp::Log(const std::string &msg) const noexcept {
  Log(msg.c_str());
}

} // namespace pdfcsp::csp