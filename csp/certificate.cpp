#include "certificate.hpp"
#include "CSP_WinBase.h"
#include "CSP_WinCrypt.h"
#include "message.hpp"
#include "resolve_symbols.hpp"
#include "utils.hpp"
#include <cstring>
#include <exception>
#include <iostream>
#include <optional>
#include <stdexcept>

namespace pdfcsp::csp {

Certificate::Certificate(const BytesVector &raw_cert, PtrSymbolResolver symbols)
    : symbols_(std::move(symbols)) {
  if (raw_cert.empty()) {
    throw std::runtime_error("empty certificate data");
  }
  if (!symbols_) {
    throw std::runtime_error("invalid symbol resolver");
  }
  p_ctx_ = symbols_->dl_CertCreateCertificateContext(
      X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, raw_cert.data(),
      raw_cert.size());
  if (p_ctx_ == nullptr) {
    throw std::runtime_error("Decode certificate failed");
  }
}

Certificate::Certificate(Certificate &&other) noexcept
    : p_ctx_(other.p_ctx_), symbols_(std::move(other.symbols_)) {
  other.p_ctx_ = nullptr;
}

Certificate &Certificate::operator=(Certificate &&other) noexcept {
  if (this == &other) {
    return *this;
  }
  if (p_ctx_ != nullptr) {
    symbols_->dl_CertFreeCertificateContext(p_ctx_);
  }
  p_ctx_ = other.p_ctx_;
  other.p_ctx_ = nullptr;
  symbols_ = std::move(other.symbols_);
  return *this;
}

Certificate::~Certificate() {
  if (p_ctx_ != nullptr) {
    symbols_->dl_CertFreeCertificateContext(p_ctx_);
  }
}

[[nodiscard]] bool Certificate::IsTimeValid() const noexcept {
  if (p_ctx_ == nullptr || p_ctx_->pCertInfo == nullptr) {
    return false;
  }
  return symbols_->dl_CertVerifyTimeValidity(nullptr, p_ctx_->pCertInfo) == 0;
}

[[nodiscard]] bool Certificate::IsRevocationStatusOK() const noexcept {
  PCCERT_CHAIN_CONTEXT p_chain_context = nullptr;
  try {
    CERT_CHAIN_PARA chain_params{};
    chain_params.cbSize = sizeof(CERT_CHAIN_PARA);
    // CERT_CHAIN_REVOCATION_CHECK_CHAIN Checks the revocation status of all
    // certificates in the chain
    // CERT_CHAIN_CACHE_END_CERT Caches the end certificate in the chain for
    // future use.
    ResCheck(symbols_->dl_CertGetCertificateChain(
                 nullptr, p_ctx_, nullptr, nullptr, &chain_params,
                 CERT_CHAIN_CACHE_END_CERT | CERT_CHAIN_REVOCATION_CHECK_CHAIN,
                 nullptr, &p_chain_context),
             "CertGetCertificateChain", symbols_);
    if (p_chain_context == nullptr) {
      throw std::runtime_error("Build certificate chain failed");
    }
    CERT_CHAIN_POLICY_PARA policy_params{};
    memset(&policy_params, 0x00, sizeof(CERT_CHAIN_POLICY_PARA));
    policy_params.cbSize = sizeof(CERT_CHAIN_POLICY_PARA);
    CERT_CHAIN_POLICY_STATUS policy_status{};
    memset(&policy_status, 0x00, sizeof(CERT_CHAIN_POLICY_STATUS));
    policy_status.cbSize = sizeof(CERT_CHAIN_POLICY_STATUS);

    ResCheck(
        symbols_->dl_CertVerifyCertificateChainPolicy(
            CERT_CHAIN_POLICY_BASE, // NOLINT(cppcoreguidelines-pro-type-cstyle-cast)
            p_chain_context, &policy_params, &policy_status),
        "CertVerifyCertificateChainPolicy", symbols_);
    if (policy_status.dwError != 0) {
      throw std::logic_error("The chain revocation status is not good\n");
    }
  } catch (const std::exception &ex) {
    if (p_chain_context != nullptr) {
      std::cerr << "[IsRevocationStatusOK] " << ex.what();
      symbols_->dl_CertFreeCertificateChain(p_chain_context);
      return false;
    }
  }
  if (p_chain_context != nullptr) {
    symbols_->dl_CertFreeCertificateChain(p_chain_context);
  }
  return true;
}

} // namespace pdfcsp::csp