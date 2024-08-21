#include "certificate.hpp"
#include "ocsp.hpp"
#include "resolve_symbols.hpp"
#include "store_hanler.hpp"
#include "typedefs.hpp"
#include "utils.hpp"
#include "utils_cert.hpp"
#include <algorithm>
#include <cstring>
#include <exception>
#include <iostream>
#include <iterator>
#include <memory>
#include <oids.hpp>
#include <stdexcept>
#include <utility>

namespace pdfcsp::csp {

///@brief construct from a raw certificate
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
  time_bounds_ = SaveTimeBounds();
}

/**
 * @brief Wrap Certificate object without decoding
 * @param h_store A handle of a certificate store.
 * @param p_cert_ctx A pointer to the CERT_CONTEXT
 * @param symbols
 * @throws runtime_error
 */
Certificate::Certificate(HCERTSTORE h_store, PCCERT_CONTEXT p_cert_ctx,
                         PtrSymbolResolver symbols)
    : p_ctx_(p_cert_ctx), symbols_(std::move(symbols)), h_store_(h_store) {
  if (h_store == nullptr || p_cert_ctx == nullptr || !symbols_) {
    throw std::runtime_error("[Certificate] Invalid constructor parametets");
  }
  time_bounds_ = SaveTimeBounds();
}

Certificate::Certificate(Certificate &&other) noexcept
    : p_ctx_(other.p_ctx_), symbols_(std::move(other.symbols_)),
      time_bounds_(other.time_bounds_), h_store_(other.h_store_) {
  other.p_ctx_ = nullptr;
  other.h_store_ = nullptr;
}

Certificate &Certificate::operator=(Certificate &&other) noexcept {
  if (this == &other) {
    return *this;
  }
  if (p_ctx_ != nullptr) {
    symbols_->dl_CertFreeCertificateContext(p_ctx_);
  }
  if (h_store_ != nullptr) {
    symbols_->dl_CertCloseStore(h_store_, 0);
  }
  p_ctx_ = other.p_ctx_;
  time_bounds_ = other.time_bounds_;
  other.p_ctx_ = nullptr;
  other.h_store_ = nullptr;
  symbols_ = std::move(other.symbols_);
  return *this;
}

Certificate::~Certificate() {
  if (p_ctx_ != nullptr) {
    symbols_->dl_CertFreeCertificateContext(p_ctx_);
  }
  if (h_store_ != nullptr) {
    symbols_->dl_CertCloseStore(h_store_, 0);
  }
}

///@brief check notBefore notAfter bounds
[[nodiscard]] bool Certificate::IsTimeValid(FILETIME *p_time) const noexcept {
  if (p_ctx_ == nullptr || p_ctx_->pCertInfo == nullptr) {
    return false;
  }
  return symbols_->dl_CertVerifyTimeValidity(p_time, p_ctx_->pCertInfo) == 0;
}

///@brief check the certificate chain
[[nodiscard]] bool
Certificate::IsChainOK(FILETIME *p_time,
                       HCERTSTORE h_additional_store) const noexcept {
  if (p_ctx_ == nullptr || p_ctx_->pCertInfo == nullptr) {
    return false;
  }
  PCCERT_CHAIN_CONTEXT p_chain_context = nullptr;
  try {
    p_chain_context =
        CreateCertChain(p_ctx_, symbols_, p_time, h_additional_store);
    std::cout << "Call to check chain\n";
    if (!CheckCertChain(p_chain_context, false, symbols_)) {
      throw std::logic_error("The chain revocation status is not good\n");
    }
  } catch (const std::exception &ex) {
    FreeChainContext(p_chain_context, symbols_);
    std::cerr << "[IsRevocationStatusOK] " << ex.what();
    return false;
  }
  FreeChainContext(p_chain_context, symbols_);
  return true;
}

/**
 * @brief Ask the OSCP server about the certificate's status.
 * @details checks the OCSP answer signature and certificate
 * @param ocsp_params - empty struct by default
 * @see OcspCheckParams
 * @throws runtime_error
 */
[[nodiscard]] bool
Certificate::IsOcspStatusOK(const OcspCheckParams &ocsp_params) const {
  if (p_ctx_ == nullptr || p_ctx_->pCertInfo == nullptr) {
    return false;
  }
  bool root_certs_equal = false;
  bool cert_status_ok = false;
  bool ocsp_signature_ok = false;
  PCCERT_CHAIN_CONTEXT p_chain = nullptr;
  PCCERT_CHAIN_CONTEXT ocsp_cert_chain = nullptr;
  PCCERT_CONTEXT p_ocsp_cert_ctx = nullptr;
  try {
    // get chain for this certificate
    FILETIME *p_time = nullptr;
    FILETIME ftime{};
    if (ocsp_params.p_time_tsp != nullptr) {
      ftime = TimetToFileTime(*ocsp_params.p_time_tsp);
      p_time = &ftime;
    }
    HCERTSTORE h_additional_store = nullptr;
    if (ocsp_params.p_additional_store != nullptr) {
      h_additional_store = ocsp_params.p_additional_store->RawHandler();
    }
    p_chain = CreateCertChain(p_ctx_, symbols_, p_time, h_additional_store);
    // prepare an OCSP response
    asn::OCSPResponse response;
    if (ocsp_params.p_response == nullptr) {
      response = GetOCSPResponseOnline(p_chain, symbols_);
    } else { // get OCSP response offline
      response.responseBytes.response = *ocsp_params.p_response;
    }
    // check signature algorithm
    const std::string sig_algo =
        response.responseBytes.response.signatureAlgorithm;
    if (sig_algo != szOID_CP_GOST_R3411_12_256_R3410) {
      throw std::runtime_error("Unknown signature OID in OCSP response");
    }
    // decode cert from response
    std::unique_ptr<Certificate> cert_dedoced = nullptr;
    if (ocsp_params.p_ocsp_cert == nullptr) {
      cert_dedoced = std::make_unique<Certificate>(
          response.responseBytes.response.certs, symbols_);
      p_ocsp_cert_ctx = cert_dedoced->GetContext();
    }
    // get ocsp certificate from params
    else {
      p_ocsp_cert_ctx = ocsp_params.p_ocsp_cert->GetContext();
    }
    // check time validity
    const bool online_certifate_expired =
        cert_dedoced && !cert_dedoced->IsTimeValid(p_time);
    const bool offline_certificate_expired =
        ocsp_params.p_ocsp_cert != nullptr &&
        !ocsp_params.p_ocsp_cert->IsTimeValid(p_time);
    if (online_certifate_expired || offline_certificate_expired) {
      throw std::runtime_error("OCSP Certificate time is not valid");
    }
    // check if certificate is suitable for OCSP signing
    if (!CertificateHasExtendedKeyUsage(p_ocsp_cert_ctx,
                                        asn::kOID_id_kp_OCSPSigning)) {
      throw std::runtime_error("OCSP certificate is not suitable for signing");
    }
    // check a chain for OCSP certificate
    ocsp_cert_chain =
        CreateCertChain(p_ocsp_cert_ctx, symbols_, p_time, h_additional_store);
    // RFC6960 [4.2.2.2.1]  ignore revocation check errors for OCSP certificate
    // if it has ocsp-nocheck extension
    const bool igone_revocation_check_errors =
        CertificateHasOcspNocheck(p_ocsp_cert_ctx);
    std::cout << "Call to check chain for OCSP cert\n";
    if (!CheckCertChain(ocsp_cert_chain, igone_revocation_check_errors,
                        symbols_)) {
      throw std::runtime_error("Check OCSP chain status = bad");
    }
    // compare root certificates by subject
    root_certs_equal =
        CompareRootSubjectsForTwoChains(p_chain, ocsp_cert_chain);
    if (!root_certs_equal) {
      throw std::runtime_error("Check OCSP chain roots are not equal");
    }
    // check status in the response
    cert_status_ok = CheckOCSPResponseStatusForCert(response, p_ctx_,
                                                    ocsp_params.p_time_tsp);
    std::cout << "cert ocsp status " << (cert_status_ok ? "OK" : "BAD") << "\n";
    // verify signature the OCSP signature
    ocsp_signature_ok =
        VerifyOCSPResponseSignature(response, p_ocsp_cert_ctx, symbols_);
    std::cout << "Verify OCSP response signature ... "
              << (ocsp_signature_ok ? "OK" : "FAILED") << "\n";
  } catch (const std::exception &ex) {
    std::cerr << "[IsOcspStatusOK]" << ex.what() << "\n";
    FreeChainContext(ocsp_cert_chain, symbols_);
    FreeChainContext(p_chain, symbols_);
    throw;
  }
  FreeChainContext(ocsp_cert_chain, symbols_);
  FreeChainContext(p_chain, symbols_);
  return root_certs_equal && cert_status_ok && ocsp_signature_ok;
}

// @brief get bounds , notBefore, notAfter, (optional) revocation date
CertTimeBounds Certificate::SaveTimeBounds() const {
  CertTimeBounds res;
  if (p_ctx_ == nullptr || p_ctx_->pCertInfo == nullptr) {
    return res;
  }
  res.not_before = FileTimeToTimeT(p_ctx_->pCertInfo->NotBefore);
  res.not_after = FileTimeToTimeT(p_ctx_->pCertInfo->NotAfter);
  return res;
}

[[nodiscard]] BytesVector Certificate::GetRawCopy() const noexcept {
  BytesVector res;
  if (p_ctx_ == nullptr || p_ctx_->cbCertEncoded == 0 ||
      p_ctx_->pbCertEncoded == nullptr) {
    return res;
  }
  std::copy(p_ctx_->pbCertEncoded,
            p_ctx_->pbCertEncoded + p_ctx_->cbCertEncoded,
            std::back_inserter(res));
  return res;
}

BytesVector Certificate::Serial() const noexcept {
  if (p_ctx_ == nullptr || p_ctx_->pCertInfo == nullptr ||
      p_ctx_->pCertInfo->SerialNumber.pbData == nullptr ||
      p_ctx_->pCertInfo->SerialNumber.cbData == 0) {
    return {};
  }
  BytesVector serial{p_ctx_->pCertInfo->SerialNumber.pbData,
                     p_ctx_->pCertInfo->SerialNumber.pbData +
                         p_ctx_->pCertInfo->SerialNumber.cbData};
  std::reverse(serial.begin(), serial.end());
  return serial;
}

BytesVector Certificate::PublicKey() const noexcept {
  if (p_ctx_ == nullptr || p_ctx_->pCertInfo == nullptr ||
      p_ctx_->pCertInfo->SubjectPublicKeyInfo.PublicKey.pbData == nullptr ||
      p_ctx_->pCertInfo->SubjectPublicKeyInfo.PublicKey.cbData == 0) {
    return {};
  }
  return {p_ctx_->pCertInfo->SubjectPublicKeyInfo.PublicKey.pbData,
          p_ctx_->pCertInfo->SubjectPublicKeyInfo.PublicKey.pbData +
              p_ctx_->pCertInfo->SubjectPublicKeyInfo.PublicKey.cbData};
}

} // namespace pdfcsp::csp