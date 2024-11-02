#pragma once
#include "resolve_symbols.hpp"
#include "utils.hpp"
#include <iostream>
#include <stdexcept>
namespace pdfcsp::csp {

/**
 * @brief Owns a handler for user's private key
 * @throws invalid_argument,runtime_error on construct
 */
class PKeyHandler final {
public:
  PKeyHandler(PCCERT_CONTEXT cert_contex, PtrSymbolResolver symbols)
      : symbols_(std::move(symbols)) {
    if (!symbols_ || cert_contex == nullptr) {
      throw std::invalid_argument("[PKeyHandler] invalid args");
    }
    ResCheck(symbols_->dl_CryptAcquireCertificatePrivateKey(
                 cert_contex, 0, nullptr, &h_csp_, &key_additional_info_,
                 &caller_must_free_),
             "CryptAcquireCertificatePrivateKey", symbols);
    if (h_csp_ == 0) {
      throw std::runtime_error(
          "[PKeyHandler] failed to get a private key for the certificate");
    }
  }

  PKeyHandler(const PKeyHandler &) = delete;
  PKeyHandler(PKeyHandler &&) = delete;
  PKeyHandler &operator=(const PKeyHandler &) = delete;
  PKeyHandler &operator=(PKeyHandler &&) = delete;

  ~PKeyHandler() {
    if (caller_must_free_ == TRUE) {
      symbols_->dl_CryptReleaseContext(h_csp_, 0);
    }
  }

private:
  PtrSymbolResolver symbols_;
  HCRYPTPROV_OR_NCRYPT_KEY_HANDLE h_csp_ = 0;
  DWORD key_additional_info_ = 0;
  BOOL caller_must_free_ = 0;
};

} // namespace pdfcsp::csp