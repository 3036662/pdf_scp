#include "certificate.hpp"
#include "CSP_WinCrypt.h"
#include "asn1.hpp"
#include "hash_handler.hpp"
#include "ocsp.hpp"
#include "resolve_symbols.hpp"
#include "typedefs.hpp"
#include "utils.hpp"
#include "utils_cert.hpp"
#include "utils_msg.hpp"
#include <algorithm>
#include <chrono>
#include <cstring>
#include <exception>
#include <iostream>
#include <iterator>
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
  time_bounds_ = SetTimeBounds();
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
  time_bounds_ = SetTimeBounds();
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
[[nodiscard]] bool Certificate::IsTimeValid() const noexcept {
  if (p_ctx_ == nullptr || p_ctx_->pCertInfo == nullptr) {
    return false;
  }
  return symbols_->dl_CertVerifyTimeValidity(nullptr, p_ctx_->pCertInfo) == 0;
}

///@brief check the certificate chain
[[nodiscard]] bool Certificate::IsChainOK() const noexcept {
  if (p_ctx_ == nullptr || p_ctx_->pCertInfo == nullptr) {
    return false;
  }
  PCCERT_CHAIN_CONTEXT p_chain_context = nullptr;
  try {
    p_chain_context = CreateCertChain(p_ctx_, symbols_);
    std::cout << "Call to check chain\n";
    if (!CheckCertChain(p_chain_context, false, symbols_)) {
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

/**
 * @brief Ask the OSCP server about the certificate's status.
 * @throws runtime_error
 */
[[nodiscard]] bool Certificate::IsOcspStatusOK() const {
  if (p_ctx_ == nullptr || p_ctx_->pCertInfo == nullptr) {
    return false;
  }
  bool root_certs_equal = false;
  bool cert_id_equal = false;
  bool cert_status_ok = false;
  bool time_ok = false;
  PCCERT_CHAIN_CONTEXT p_chain = nullptr;
  PCCERT_CHAIN_CONTEXT ocsp_cert_chain = nullptr;
  PCCERT_CONTEXT p_ocsp_cert_ctx = nullptr;
  std::pair<HCERT_SERVER_OCSP_RESPONSE, PCCERT_SERVER_OCSP_RESPONSE_CONTEXT>
      ocsp_result{nullptr, nullptr};
  try {
    // get chain for this certificate
    p_chain = CreateCertChain(p_ctx_, symbols_);
    // get OCSP response
    ocsp_result = GetOcspResponseAndContext(p_chain, symbols_);
    const auto &resp_context = ocsp_result.second;
    // parse response
    const asn::AsnObj resp(resp_context->pbEncodedOcspResponse,
                           resp_context->cbEncodedOcspResponse, symbols_);
    const asn::OCSPResponse response(resp);
    // check status
    if (response.responseStatus != asn::OCSPResponseStatus::kSuccessful) {
      std::cerr << "bad OCSP response status\n";
      throw std::runtime_error("OCSP status != success");
    }
    // check signature algorithm
    const std::string sig_algo =
        response.responseBytes.response.signatureAlgorithm;
    if (sig_algo != szOID_CP_GOST_R3411_12_256_R3410) {
      throw std::runtime_error("Unknown signature OID in OCSP response");
    }
    // calculate a hash of ResponseData
    HashHandler hash(szOID_CP_GOST_R3411_12_256, symbols_);
    hash.SetData(response.responseBytes.response.resp_data_der_encoded);
    // decode cert from response
    p_ocsp_cert_ctx = symbols_->dl_CertCreateCertificateContext(
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        response.responseBytes.response.certs.data(),
        response.responseBytes.response.certs.size());
    if (p_ocsp_cert_ctx == nullptr) {
      throw std::runtime_error("Decode OCSP certificate failed");
    }
    CERT_PUBLIC_KEY_INFO *p_ocsp_public_key_info =
        &p_ocsp_cert_ctx->pCertInfo->SubjectPublicKeyInfo;
    // check if ocsp certificate time valid
    if (symbols_->dl_CertVerifyTimeValidity(nullptr,
                                            p_ocsp_cert_ctx->pCertInfo) != 0) {
      throw std::runtime_error("OCSP Certificate time is not valid");
    }
    // check if certificate is suitable for OCSP signing
    if (!CertificateHasExtendedKeyUsage(p_ocsp_cert_ctx,
                                        asn::kOID_id_kp_OCSPSigning)) {
      throw std::runtime_error("OCSP certificate is not suitable for signing");
    }
    // check a chain for OCSP certificate
    ocsp_cert_chain = CreateCertChain(p_ocsp_cert_ctx, symbols_);
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
    {
      const PCCERT_CONTEXT p_root_cert_context =
          GetRootCertificateCtxFromChain(p_chain);
      const PCCERT_CONTEXT p_ocsp_root_cert_context =
          GetRootCertificateCtxFromChain(ocsp_cert_chain);
      // NOLINTBEGIN(cppcoreguidelines-pro-bounds-pointer-arithmetic)
      BytesVector subj1;
      std::copy(p_root_cert_context->pCertInfo->Subject.pbData,
                p_root_cert_context->pCertInfo->Subject.pbData +
                    p_root_cert_context->pCertInfo->Subject.cbData,
                std::back_inserter(subj1));
      BytesVector subj2;
      std::copy(p_ocsp_root_cert_context->pCertInfo->Subject.pbData,
                p_ocsp_root_cert_context->pCertInfo->Subject.pbData +
                    p_ocsp_root_cert_context->pCertInfo->Subject.cbData,
                std::back_inserter(subj2));
      if (subj1 != subj2) {
        throw std::runtime_error("Root certificates are no equal");
      }
      root_certs_equal = true;
    }
    {
      // compare certificate serial with serial in response
      BytesVector serial;
      std::copy(p_ctx_->pCertInfo->SerialNumber.pbData,
                p_ctx_->pCertInfo->SerialNumber.pbData +
                    p_ctx_->pCertInfo->SerialNumber.cbData,
                std::back_inserter(serial));
      std::reverse(serial.begin(), serial.end());
      const auto it_response = std::find_if(
          response.responseBytes.response.tbsResponseData.responses.cbegin(),
          response.responseBytes.response.tbsResponseData.responses.cend(),
          [&serial](const asn::SingleResponse &response) {
            return response.certID.serialNumber == serial;
          });
      // NOLINTEND(cppcoreguidelines-pro-bounds-pointer-arithmetic)
      // check status of the certificate
      if (it_response != response.responseBytes.response.tbsResponseData
                             .responses.cend() &&
          it_response->certStatus == asn::CertStatus::kGood) {
        cert_id_equal = true;
        cert_status_ok = true;
        // Check the time
        const ParsedTime time_parsed =
            GeneralizedTimeToTimeT(it_response->thisUpdate);
        const std::time_t time_stamp =
            time_parsed.time + time_parsed.gmt_offset;
        auto now = std::chrono::system_clock::now();
        const std::time_t now_c = std::chrono::system_clock::to_time_t(now);
        if (now_c >= time_stamp && now_c - time_stamp < 100) {
          time_ok = true;
        }
      }
      // TODO(Oleg) place revocation time in time_bounds_ if revoced
    }

    // ---------------------------------------------------------
    // import public key
    HCRYPTKEY handler_pub_key = 0;
    ResCheck(symbols_->dl_CryptImportPublicKeyInfo(
                 hash.get_csp_hanler(), PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
                 p_ocsp_public_key_info, &handler_pub_key),
             "CryptImportPublicKeyInfo", symbols_);

    if (handler_pub_key == 0) {
      throw std::runtime_error("Import public key failed");
    }
    // verify signature
    BytesVector signature = response.responseBytes.response.signature;
    std::reverse(signature.begin(), signature.end());
    // delete last 0 byte from signature
    signature.pop_back();
    ResCheck(symbols_->dl_CryptVerifySignatureA(
                 hash.get_hash_handler(), signature.data(), signature.size(),
                 handler_pub_key, nullptr, 0),
             "CryptVerifySignature", symbols_);

    std::cout << "Verify OCSP response signature ... OK\n";
  } catch (const std::exception &ex) {
    std::cerr << "[IsOcspStatusOK]" << ex.what() << "\n";
    FreeChainContext(ocsp_cert_chain, symbols_);
    if (p_ocsp_cert_ctx != nullptr) {
      symbols_->dl_CertFreeCertificateContext(p_ocsp_cert_ctx);
    }
    FreeOcspResponseAndContext(ocsp_result, symbols_);
    FreeChainContext(p_chain, symbols_);
    throw;
  }
  FreeChainContext(ocsp_cert_chain, symbols_);
  if (p_ocsp_cert_ctx != nullptr) {
    symbols_->dl_CertFreeCertificateContext(p_ocsp_cert_ctx);
  }
  FreeOcspResponseAndContext(ocsp_result, symbols_);
  FreeChainContext(p_chain, symbols_);
  return root_certs_equal && cert_id_equal && cert_status_ok && time_ok;
}

// @brief get bounds , notBefore, notAfter, (optional) revocation date
CertTimeBounds Certificate::SetTimeBounds() const {
  CertTimeBounds res;
  if (p_ctx_ == nullptr || p_ctx_->pCertInfo == nullptr) {
    return res;
  }
  res.not_before = FileTimeToTimeT(p_ctx_->pCertInfo->NotBefore);
  res.not_after = FileTimeToTimeT(p_ctx_->pCertInfo->NotAfter);

  // std::cout << res.not_before << "\n";
  //  const std::tm *localTime = std::localtime(&res.not_before); // NOLINT
  //  std::cout << std::put_time(localTime, "%Y-%m-%d %H:%M:%S") << "\n";
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

} // namespace pdfcsp::csp