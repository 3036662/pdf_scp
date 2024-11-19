#include "store_hanler.hpp"
#include "utils.hpp"
#include <iostream>
#include <stdexcept>

namespace pdfcsp::csp {

StoreHandler::StoreHandler(const char *store_provider, DWORD flags,
                           const void *params, PtrSymbolResolver symbols)
    : symbols_(std::move(symbols)) {
  if (!symbols_) {
    throw std::runtime_error("[StoreHandler] invalid symbol resolver");
  }
  h_store_ = symbols_->dl_CertOpenStore(store_provider, 0, 0, flags, params);
  if (h_store_ == nullptr) {
    symbols_->log->debug("[StoreHandler] constructor for store {} failed",
                         store_provider);
    throw std::runtime_error("[StoreHandler] CertOpenStore failed");
  }
}

StoreHandler::~StoreHandler() {
  if (h_store_ != nullptr) {
    symbols_->dl_CertCloseStore(h_store_, 0);
  }
}

void StoreHandler::AddCertificate(const Certificate &cert) {
  ResCheck(symbols_->dl_CertAddCertificateContextToStore(
               h_store_, cert.GetContext(), CERT_STORE_ADD_ALWAYS, nullptr),
           "CertAddCertificateContextToStore", symbols_);
}

} // namespace pdfcsp::csp