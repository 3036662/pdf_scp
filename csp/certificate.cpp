/* File: certificate.cpp  
Copyright (C) Basealt LLC,  2024
Author: Oleg Proskurin, <proskurinov@basealt.ru>

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with this program; if not, write to the Free Software Foundation,
Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/


#include "certificate.hpp"
#include "CSP_WinCrypt.h"
#include "asn1.hpp"
#include "cert_common_info.hpp"
#include "d_name.hpp"
#include "ocsp.hpp"
#include "resolve_symbols.hpp"
#include "store_hanler.hpp"
#include "typedefs.hpp"
#include "utils.hpp"
#include "utils_cert.hpp"
#include <algorithm>
#include <boost/json/array.hpp>
#include <boost/json/object.hpp>
#include <boost/json/serialize.hpp>
#include <cstdint>
#include <cstring>
#include <exception>
#include <iostream>
#include <iterator>
#include <memory>
#include <oids.hpp>
#include <stdexcept>
#include <utility>

namespace pdfcsp::csp {

// NOLINTNEXTLINE(google-build-using-namespace)
using namespace utils::cert;

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

/**
 * @brief Check the certificate chain
 * @param p_time time to use for check
 * @param h_additional_store an additional certificate store
 * @param ignore_revoc_check_errors ignore revocation check errors if true
 */
[[nodiscard]] bool
Certificate::IsChainOK(FILETIME *p_time, HCERTSTORE h_additional_store,
                       bool ignore_revoc_check_errors) const noexcept {
  if (p_ctx_ == nullptr || p_ctx_->pCertInfo == nullptr) {
    return false;
  }
  PCCERT_CHAIN_CONTEXT p_chain_context = nullptr;
  try {
    p_chain_context =
        CreateCertChain(p_ctx_, symbols_, p_time, h_additional_store);
    symbols_->log->debug("Call to check chain");
    if (!CheckCertChain(p_chain_context, ignore_revoc_check_errors, symbols_)) {
      throw std::logic_error("The chain revocation status is not good\n");
    }
  } catch (const std::exception &ex) {
    FreeChainContext(p_chain_context, symbols_);
    symbols_->log->error("[IsRevocationStatusOK] ", ex.what());
    return false;
  }
  FreeChainContext(p_chain_context, symbols_);
  return true;
}

std::string
Certificate::ChainInfo(FILETIME *p_time, HCERTSTORE h_additional_store,
                       bool ignore_revoc_check_errors) const noexcept {
  PCCERT_CHAIN_CONTEXT p_chain_context = nullptr;
  boost::json::array res;
  try {
    p_chain_context =
        CreateCertChain(p_ctx_, symbols_, p_time, h_additional_store);
    if (p_chain_context == nullptr) {
      throw std::runtime_error("read certificate chain failed");
    }
    using CertificateChain = std::pair<bool, std::vector<CertCommonInfo>>;
    using ChainsArr = std::vector<CertificateChain>;
    ChainsArr chains_arr;
    // for each simple chain
    for (uint64_t i = 0; i < p_chain_context->cChain; ++i) {
      const _CERT_SIMPLE_CHAIN *p_simple_chain = p_chain_context->rgpChain[i];
      if (p_simple_chain == nullptr) {
        break;
      }
      CertificateChain chain;
      chain = std::make_pair(p_simple_chain->TrustStatus.dwErrorStatus == 0,
                             std::vector<CertCommonInfo>{});
      // ignore revocation check error
      if (p_simple_chain->TrustStatus.dwErrorStatus == 0x40 &&
          ignore_revoc_check_errors) {
        chain.first = true;
      }
      // for each certificate in chain
      for (uint64_t j = 0; j < p_simple_chain->cElement; ++j) {
        const _CERT_CHAIN_ELEMENT *p_element = p_simple_chain->rgpElement[j];

        if (p_element == nullptr || p_element->pCertContext == nullptr ||
            p_element->pCertContext->pCertInfo == nullptr) {
          throw std::runtime_error("invalid _CERT_CHAIN_ELEMENT");
        }
        CERT_INFO *p_info = p_element->pCertContext->pCertInfo;
        CertCommonInfo info(p_info);
        info.SetTrustStatus(symbols_, p_info,
                            p_element->TrustStatus.dwErrorStatus, p_time,
                            ignore_revoc_check_errors);
        chain.second.emplace_back(std::move(info));
      }
      if (!chain.second.empty()) {
        chains_arr.emplace_back(std::move(chain));
      }
    }
    // put to json
    for (const auto &chain : chains_arr) {
      boost::json::object chain_json_obj;
      chain_json_obj["trust_status"] = chain.first;
      boost::json::array cert_json_arr;
      for (const auto &certinfo : chain.second) {
        cert_json_arr.push_back(certinfo.ToJson());
      }
      chain_json_obj["certs"] = std::move(cert_json_arr);
      res.push_back(chain_json_obj);
    }
  } catch (const std::exception &ex) {
    FreeChainContext(p_chain_context, symbols_);
    symbols_->log->error("[IsRevocationStatusOK] {}", ex.what());
    return {};
  }
  FreeChainContext(p_chain_context, symbols_);
  return boost::json::serialize(res);
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
  // use a timestamp as current time
  const bool mocked_time = ocsp_params.p_time_tsp != nullptr;
  // use a local response as an OCSP server response
  const bool mocked_ocsp = ocsp_params.p_response != nullptr;
  PCCERT_CHAIN_CONTEXT p_chain = nullptr;
  PCCERT_CHAIN_CONTEXT ocsp_cert_chain = nullptr;
  PCCERT_CONTEXT p_ocsp_cert_ctx = nullptr;
  try {
    // get chain for this certificate
    FILETIME *p_time = nullptr;
    FILETIME ftime{};
    if (mocked_time) {
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
    if (!mocked_ocsp) {
      response = GetOCSPResponseOnline(p_chain, symbols_);
    } else { // use the local OCSP response
      response.responseBytes.response = *ocsp_params.p_response;
    }
    // check signature algorithm
    const std::string sig_algo =
        response.responseBytes.response.signatureAlgorithm;
    if (sig_algo != szOID_CP_GOST_R3411_12_256_R3410) {
      throw std::runtime_error("Unknown signature OID in OCSP response");
    }
    // decode cert from response
    std::unique_ptr<Certificate> cert_decoded = nullptr;
    if (ocsp_params.p_ocsp_cert == nullptr) {
      cert_decoded = std::make_unique<Certificate>(
          response.responseBytes.response.certs, symbols_);
      p_ocsp_cert_ctx = cert_decoded->GetContext();
    }
    // get ocsp certificate from params
    else {
      p_ocsp_cert_ctx = ocsp_params.p_ocsp_cert->GetContext();
    }
    // check time validity
    const bool online_certifate_expired =
        cert_decoded && !cert_decoded->IsTimeValid();
    const bool offline_certificate_expired =
        ocsp_params.p_ocsp_cert != nullptr &&
        !ocsp_params.p_ocsp_cert->IsTimeValid(p_time);
    if (online_certifate_expired || offline_certificate_expired) {
      throw std::runtime_error("OCSP Certificate time is not valid");
    }
    auto cert_info = CertCommonInfo(p_ocsp_cert_ctx->pCertInfo);
    symbols_->log->info("OCSP certificate: subject {} issuer {} serial {}",
                        cert_info.subj_common_name,
                        cert_info.issuer_common_name,
                        VecBytesStringRepresentation(cert_info.serial));
    // check if certificate is suitable for OCSP signing
    if (!CertificateHasExtendedKeyUsage(p_ocsp_cert_ctx,
                                        asn::kOID_id_kp_OCSPSigning)) {

      throw std::runtime_error(
          "OCSP certificate is not suitable for OCSP signing");
    }
    // check a chain for OCSP certificate
    ocsp_cert_chain = CreateCertChain(
        p_ocsp_cert_ctx, symbols_,
        mocked_ocsp ? p_time : nullptr, // use timestamp for mocked response
        h_additional_store);
    // RFC6960 [4.2.2.2.1]  ignore revocation check errors for OCSP certificate
    // if it has ocsp-nocheck extension
    const bool igone_revocation_check_errors =
        CertificateHasOcspNocheck(p_ocsp_cert_ctx);
    symbols_->log->info("Call to check chain for OCSP cert");
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
    cert_status_ok = CheckOCSPResponseStatusForCert(
        response, p_ctx_, ocsp_params.p_time_tsp, mocked_ocsp);

    symbols_->log->info("cert ocsp status {}", (cert_status_ok ? "OK" : "BAD"));
    // verify signature the OCSP signature
    ocsp_signature_ok =
        VerifyOCSPResponseSignature(response, p_ocsp_cert_ctx, symbols_);
    symbols_->log->info("Verify OCSP response signature ... {}",
                        (ocsp_signature_ok ? "OK" : "FAILED"));
  } catch (const std::exception &ex) {
    symbols_->log->error("[IsOcspStatusOK] {}", ex.what());
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

asn::DName Certificate::DecomposedIssuerName() const {
  if (p_ctx_ == nullptr || p_ctx_->pCertInfo == nullptr ||
      p_ctx_->pCertInfo->Issuer.pbData == nullptr ||
      p_ctx_->pCertInfo->Issuer.cbData == 0) {
    throw std::runtime_error(
        "[Certificate::DecomposedIssuerName] invalid context");
  }
  const asn::AsnObj obj(p_ctx_->pCertInfo->Issuer.pbData,
                        p_ctx_->pCertInfo->Issuer.cbData);
  return asn::DName(obj);
}

asn::DName Certificate::DecomposedSubjectName() const {
  if (p_ctx_ == nullptr || p_ctx_->pCertInfo == nullptr ||
      p_ctx_->pCertInfo->Issuer.pbData == nullptr ||
      p_ctx_->pCertInfo->Issuer.cbData == 0) {
    throw std::runtime_error(
        "[Certificate::DecomposedSubjectName] invalid context");
  }
  const asn::AsnObj obj(p_ctx_->pCertInfo->Subject.pbData,
                        p_ctx_->pCertInfo->Subject.cbData);
  return asn::DName(obj);
}

} // namespace pdfcsp::csp