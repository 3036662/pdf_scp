/* File: utils_cert.cpp
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

#include "utils_cert.hpp"

#include <algorithm>
#include <bitset>
#include <boost/json/array.hpp>
#include <boost/system/system_error.hpp>
#include <chrono>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <exception>
#include <iterator>
#include <memory>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>

#include "CSP_WinCrypt.h"
#include "CSP_WinDef.h"
#include "asn1.hpp"
#include "cert_common_info.hpp"
#include "certificate.hpp"
#include "certificate_id.hpp"
#include "hash_handler.hpp"
#include "ocsp.hpp"
#include "oids.hpp"
#include "resolve_symbols.hpp"
#include "typedefs.hpp"
#include "utils.hpp"

namespace pdfcsp::csp::utils::cert {

/**
 * @brief Create a Certifate Chain context
 * @details context must be freed by the receiver with FreeChainContext
 * @param p_cert_ctx Certificate context
 * @param p_time time for witch chain should be created
 * @param h_additional_store additional certificate store to use
 * @param symbols
 * @return PCCERT_CHAIN_CONTEXT chain context
 * @throws runtime_error
 */
PCCERT_CHAIN_CONTEXT
CreateCertChain(PCCERT_CONTEXT p_cert_ctx, const PtrSymbolResolver &symbols,
                FILETIME *p_time, HCERTSTORE h_additional_store, bool offline) {
  PCCERT_CHAIN_CONTEXT p_chain_context = nullptr;
  CERT_CHAIN_PARA chain_params{};
  std::memset(&chain_params, 0x00, sizeof(CERT_CHAIN_PARA));
  chain_params.cbSize = sizeof(CERT_CHAIN_PARA);
  /*
    TODO(Oleg) CERT_CHAIN_REVOCATION_CHECK_CHAIN yields CertOpenStore!failed:
    LastError in system journal
    Removing CERT_CHAIN_REVOCATION_CHECK_CHAIN pacifies valgrind
  */
  DWORD flags = CERT_CHAIN_CACHE_END_CERT | CERT_CHAIN_REVOCATION_CHECK_CHAIN;

  if (offline) {
    flags |= CERT_CHAIN_REVOCATION_CHECK_CACHE_ONLY;
  }
  symbols->log->info("[CreateCertChain] offline = {}", offline);
  ResCheck(symbols->dl_CertGetCertificateChain(
             nullptr, p_cert_ctx, p_time, h_additional_store, &chain_params,
             flags, nullptr, &p_chain_context),
           "CertGetCertificateChain", symbols);
  if (p_chain_context == nullptr) {
    throw std::runtime_error("Build certificate chain failed");
  }
  return p_chain_context;
}

/**
 * @brief Free chain context
 * @param ctx
 * @param symbols
 */
void FreeChainContext(PCCERT_CHAIN_CONTEXT ctx,
                      const PtrSymbolResolver &symbols) noexcept {
  if (ctx != nullptr) {
    symbols->dl_CertFreeCertificateChain(ctx);
  }
}

/**
 * @brief Verify Certificate chain
 * @param p_chain_context pointer to chain context
 * @param ignore_revoc_check_errors - revocation check errors are ignored if
 * true
 * @param symbols
 * @throws runtime_error
 */
bool CheckCertChain(PCCERT_CHAIN_CONTEXT p_chain_context,
                    bool ignore_revoc_check_errors,
                    const PtrSymbolResolver &symbols) {
  CERT_CHAIN_POLICY_PARA policy_params{};
  memset(&policy_params, 0x00, sizeof(CERT_CHAIN_POLICY_PARA));
  policy_params.cbSize = sizeof(CERT_CHAIN_POLICY_PARA);
  CERT_CHAIN_POLICY_STATUS policy_status{};
  memset(&policy_status, 0x00, sizeof(CERT_CHAIN_POLICY_STATUS));
  policy_status.cbSize = sizeof(CERT_CHAIN_POLICY_STATUS);
  if (ignore_revoc_check_errors) {
    policy_params.dwFlags |= CERT_CHAIN_POLICY_IGNORE_END_REV_UNKNOWN_FLAG;
    symbols->log->info("Ignoring revoc checks errors");
  }
  ResCheck(
    symbols->dl_CertVerifyCertificateChainPolicy(
      CERT_CHAIN_POLICY_BASE,  // NOLINT(cppcoreguidelines-pro-type-cstyle-cast)
      p_chain_context, &policy_params, &policy_status),
    "CertVerifyCertificateChainPolicy", symbols);
  if (policy_status.dwError != 0) {
    switch (policy_status.dwError) {
      case 0x800b0109:
        symbols->log->error(
          "A certification chain processed correctly but terminated in a "
          "root certificate that is not trusted by the trust provider.");
        break;
      case 0x80092012L:
        symbols->log->error(
          "The revocation function was unable to check revocation for "
          "the certificate");
        break;
      case 0x80092010L:
        symbols->log->error("The certificate or signature has been revoked.");
        break;
      case 0x800b0101L:
        symbols->log->error(
          "A required certificate is not within its validity period.");
        break;
      default:
        symbols->log->error("[CheckCertChain] error {:#x}",
                            policy_status.dwError);
    }
  }
  return policy_status.dwError == 0;
}

/**
 * @brief Get the Root Certificate Ctx From Chain object
 * @param p_chain_context
 * @return PCCERT_CONTEXT
 * @throw runtime_error
 */
PCCERT_CONTEXT
GetRootCertificateCtxFromChain(PCCERT_CHAIN_CONTEXT p_chain_context) {
  if (p_chain_context == nullptr) {
    throw std::runtime_error(
      "[GetRootCertificateCtxFromChain] chain context == nullptr");
  }
  if (p_chain_context->cChain == 0) {
    throw std::runtime_error("No simple chains in the certificate chain");
  }
  PCERT_SIMPLE_CHAIN simple_chain =
    p_chain_context->rgpChain[p_chain_context->cChain - 1];
  if (simple_chain->cElement == 0) {
    throw std::runtime_error("No elements in simple chain");
  }
  // 2.get a root certificate context
  PCCERT_CONTEXT p_root_cert_context =
    simple_chain->rgpElement[simple_chain->cElement - 1]->pCertContext;
  if (p_root_cert_context == nullptr) {
    throw std::runtime_error("pointer to CERT_PUBLIC_KEY_INFO = nullptr");
  }
  return p_root_cert_context;
}

/**
 * @brief Check if the certificate has an id-pkix-ocsp-nocheck extension
 * @details  RFC 6960 [4.2.2.2.1]
 * @param cert_ctx - The certificate context
 * @throws runtime_error
 */
bool CertificateHasOcspNocheck(PCCERT_CONTEXT cert_ctx) {
  const std::string func_name = "[CertificateHasOcspNocheck] ";
  if (cert_ctx == nullptr) {
    throw std::runtime_error(func_name + "context == nullptr");
  }
  const unsigned int numb_extension = cert_ctx->pCertInfo->cExtension;
  // id-pkix-ocsp-nocheck OBJECT IDENTIFIER ::= { id-pkix-ocsp 5 }
  std::string oid_ocsp_no_check(szOID_PKIX_OCSP_BASIC_SIGNED_RESPONSE);
  oid_ocsp_no_check.pop_back();
  oid_ocsp_no_check.push_back('5');
  const BytesVector expected_val{0x05, 0x00};
  bool found = false;
  for (uint i = 0; i < numb_extension; ++i) {
    CERT_EXTENSION *ext = &cert_ctx->pCertInfo->rgExtension[i];
    // RFC 6960 [4.2.2.2.1] ocsp-nocheck extension can't be critical
    if (ext->fCritical == TRUE || ext->Value.cbData == 0 ||
        ext->Value.pbData == nullptr) {
      continue;
    }
    if (oid_ocsp_no_check != ext->pszObjId) {
      continue;
    }
    const BytesVector extval(ext->Value.pbData,
                             ext->Value.pbData + ext->Value.cbData);
    if (extval == expected_val) {
      found = true;
      break;
    }
  }
  return found;
}

/**
 * @brief Check if the certificate has an Extended Key Usage
 * @details  RFC 5280 [4.2.1.12]
 * @param cert_ctx - The certificate context
 * @param oid_usage - string OID to check for
 * @throws runtime_error
 */
bool CertificateHasExtendedKeyUsage(PCCERT_CONTEXT cert_ctx,
                                    const std::string &oid_usage) {
  const std::string func_name = "[CertificateHashKeyUsage] ";
  const PtrSymbolResolver symbols = std::make_shared<ResolvedSymbols>();
  if (cert_ctx == nullptr) {
    throw std::runtime_error(func_name + "context == nullptr");
  }
  const unsigned int numb_extension = cert_ctx->pCertInfo->cExtension;
  const std::string oid_key_usage(asn::kOID_id_ce_extKeyUsage);
  bool found = false;
  for (uint i = 0; i < numb_extension; ++i) {
    CERT_EXTENSION *ext = &cert_ctx->pCertInfo->rgExtension[i];
    if (ext->Value.cbData == 0 || ext->Value.pbData == nullptr) {
      continue;
    }
    if (oid_key_usage != ext->pszObjId) {
      continue;
    }
    const asn::AsnObj asn_obj(ext->Value.pbData, ext->Value.cbData);
    if (asn_obj.GetAsnTag() != asn::AsnTag::kSequence || asn_obj.Size() == 0) {
      continue;
    }
    if (asn_obj.at(0).GetAsnTag() == asn::AsnTag::kOid &&
        asn_obj.at(0).StringData().value_or("") == oid_usage) {
      found = true;
      break;
    }
  }
  return found;
}

/**
 * @brief Check if the certificate has a Key Usage bit
 * @details  RFC 5280 [4.2.1.3]
 * @param cert_ctx - The certificate context
 * @param bit_number witch bit to check
 * @throws runtime_error
 */
bool CertificateHasKeyUsageBit(PCCERT_CONTEXT cert_ctx, uint8_t bit_number) {
  const std::string func_name = "[CertificateHasKeyUsageBit] ";
  const PtrSymbolResolver symbols = std::make_shared<ResolvedSymbols>();
  if (cert_ctx == nullptr) {
    throw std::runtime_error(func_name + "context == nullptr");
  }

  std::string sbits = CertificateKeyUsageRawBitsToStr(cert_ctx->pCertInfo);
  if (bit_number < sbits.size()) {
    return sbits[bit_number] == '1';
  }
  return false;
}

// return only first 8 bits
uint8_t CertificateKeyUsageRawBits(const CERT_INFO *p_info) {
  const std::string func_name = "[CertificateHasKeyUsageBit] ";
  const PtrSymbolResolver symbols = std::make_shared<ResolvedSymbols>();
  if (p_info == nullptr) {
    throw std::runtime_error(func_name + "p_info == nullptr");
  }
  const unsigned int numb_extension = p_info->cExtension;
  const std::string oid_key_usage(asn::kOID_id_ce_keyUsage);
  for (uint i = 0; i < numb_extension; ++i) {
    CERT_EXTENSION *ext = &p_info->rgExtension[i];
    if (ext->Value.cbData < 4 || ext->Value.pbData == nullptr) {
      continue;
    }
    if (oid_key_usage != ext->pszObjId) {
      continue;
    }
    const BytesVector val(ext->Value.pbData,
                          ext->Value.cbData + ext->Value.pbData);
    // check if asn1 bit string
    if (val[0] != 0x03) {
      continue;
    }
    auto unused = static_cast<uint>(val[2]);
    if (unused > 8 * val[1]) {
      throw std::runtime_error(func_name + "unused bits > 8");
    }
    const uint8_t bits(val[3]);
    return bits;
  }
  return 0;
}

std::string CertificateKeyUsageRawBitsToStr(const CERT_INFO *p_info) {
  const std::string func_name = "[CertificateHasKeyUsageBit] ";
  const PtrSymbolResolver symbols = std::make_shared<ResolvedSymbols>();
  if (p_info == nullptr) {
    throw std::runtime_error(func_name + "p_info == nullptr");
  }
  const unsigned int numb_extension = p_info->cExtension;
  const std::string oid_key_usage(asn::kOID_id_ce_keyUsage);
  for (uint i = 0; i < numb_extension; ++i) {
    CERT_EXTENSION *ext = &p_info->rgExtension[i];
    if (ext->Value.cbData < 4 || ext->Value.pbData == nullptr) {
      continue;
    }
    if (oid_key_usage != ext->pszObjId) {
      continue;
    }
    const BytesVector val(ext->Value.pbData,
                          ext->Value.cbData + ext->Value.pbData);
    // check if asn1 bit string
    if (val[0] != 0x03) {
      continue;
    }
    auto unused = static_cast<uint8_t>(val[2]);
    BytesVector bits_raw_vec = val;
    bits_raw_vec.erase(bits_raw_vec.begin(), bits_raw_vec.begin() + 3);
    // erase
    if (unused > 8 * val[1] || bits_raw_vec.size() * 8 < unused) {
      throw std::runtime_error(func_name + "unused bits > sizeof data");
    }
    const size_t bits_expected = bits_raw_vec.size() * 8 - unused;
    std::ostringstream builder;
    for (size_t j = 0; j < bits_raw_vec.size(); ++j) {
      const std::bitset<8> bits(bits_raw_vec[j]);
      builder << bits.to_string();
    }
    std::string res = builder.str();
    res.resize(bits_expected);
    return res;
  }
  return {};
}

/**
 * @brief identifies whether the subject of the
   certificate is a CA
 * @details  RFC 5280 [4.2.1.9]
 * @param cert_ctx - The certificate context
 * @throws runtime_error
 */
bool CertificateIsCA(PCCERT_CONTEXT cert_ctx) {
  const std::string func_name = "[CertificateIsCA] ";
  const PtrSymbolResolver symbols = std::make_shared<ResolvedSymbols>();
  if (cert_ctx == nullptr) {
    throw std::runtime_error(func_name + "context == nullptr");
  }
  const unsigned int numb_extension = cert_ctx->pCertInfo->cExtension;
  const std::string oid_basic_constraints(asn::kOID_id_ce_basicConstraints);
  for (uint i = 0; i < numb_extension; ++i) {
    CERT_EXTENSION *ext = &cert_ctx->pCertInfo->rgExtension[i];
    if (ext->Value.cbData < 1 || ext->Value.pbData == nullptr) {
      continue;
    }
    if (oid_basic_constraints != ext->pszObjId || ext->fCritical != TRUE) {
      continue;
    }
    const asn::AsnObj ext_asn(ext->Value.pbData, ext->Value.cbData);
    if (ext_asn.GetAsnTag() == asn::AsnTag::kSequence && ext_asn.Size() == 1 &&
        ext_asn.at(0).GetAsnTag() == asn::AsnTag::kBoolean &&
        ext_asn.at(0).Data().size() == 1 &&
        ext_asn.at(0).Data().at(0) == 0xFF) {
      return true;
    }
  }
  return false;
}

/**
 * @brief Looks for a certificate in users store
 * @details Looks by serial and subject
 * @param subject - subject common name
 * @param symbols
 * @return std::optional<Certificate>
 * @details keeps a store handler till destroy
 */
std::optional<Certificate> FindCertInUserStoreBySerial(
  const std::string &subject, const std::string &serial,
  const PtrSymbolResolver &symbols) {
  HCERTSTORE h_store = symbols->dl_CertOpenStore(
    CERT_STORE_PROV_SYSTEM, 0, 0,  // NOLINT
    CERT_SYSTEM_STORE_CURRENT_USER | CERT_STORE_OPEN_EXISTING_FLAG |
      CERT_STORE_READONLY_FLAG,
    L"MY");
  if (h_store == nullptr || subject.empty() || serial.empty()) {
    return std::nullopt;
  }
  PCCERT_CONTEXT p_cert_context = nullptr;
  while ((p_cert_context = symbols->dl_CertEnumCertificatesInStore(
            h_store, p_cert_context)) != nullptr) {
    const CertCommonInfo cert_info(p_cert_context->pCertInfo);
    if (VecBytesStringRepresentation(cert_info.serial) == serial &&
        cert_info.subj_common_name == subject) {
      // certificate will own h_store
      return Certificate(h_store, p_cert_context, symbols);
    }
  }
  symbols->dl_CertCloseStore(h_store, 0);
  return std::nullopt;
}

/**
 * @brief Looks for a certificate in store
 * @details Looks by serial and hash
 * @param cert_id serial, hash and algo can't be empty
 * @param storage widestring like L"MY"
 * @param symbols
 * @return std::optional<Certificate>
 */
std::optional<Certificate> FindCertInStoreByID(
  asn::CertificateID &cert_id, const std::wstring &storage,
  const PtrSymbolResolver &symbols) noexcept {
  if (cert_id.serial.empty() || cert_id.hash_cert.empty() ||
      cert_id.hashing_algo_oid.empty() || !symbols) {
    return std::nullopt;
  }
  // Open the store
  HCERTSTORE h_store = symbols->dl_CertOpenStore(
    CERT_STORE_PROV_SYSTEM, 0, 0,  // NOLINT
    CERT_SYSTEM_STORE_CURRENT_USER | CERT_STORE_OPEN_EXISTING_FLAG |
      CERT_STORE_READONLY_FLAG,
    storage.c_str());
  if (h_store == nullptr) {
    return std::nullopt;
  }
  // look for the certificate
  BytesVector expected;
  std::reverse_copy(cert_id.serial.cbegin(), cert_id.serial.cend(),
                    std::back_inserter(expected));
  PCCERT_CONTEXT p_cert_context = nullptr;
  while ((p_cert_context = symbols->dl_CertEnumCertificatesInStore(
            h_store, p_cert_context)) != nullptr) {
    const BytesVector serial(p_cert_context->pCertInfo->SerialNumber.pbData,
                             p_cert_context->pCertInfo->SerialNumber.pbData +
                               p_cert_context->pCertInfo->SerialNumber.cbData);
    // when found - check hash
    if (expected == serial && p_cert_context->cbCertEncoded != 0 &&
        p_cert_context->pbCertEncoded != nullptr) {
      const BytesVector cert_raw(
        p_cert_context->pbCertEncoded,
        p_cert_context->pbCertEncoded + p_cert_context->cbCertEncoded);
      try {
        HashHandler hash(cert_id.hashing_algo_oid, symbols);
        hash.SetData(cert_raw);
        if (cert_id.hash_cert == hash.GetValue()) {
          break;
        }
      } catch (const std::exception &) {
        continue;
      }
    }
  }
  // if found, create Certificate and return
  if (p_cert_context != nullptr) {
    try {
      // on success, the Certificate object will own h_store,p_cert_context
      return Certificate(h_store, p_cert_context, symbols);
    } catch (const std::exception &) {
      symbols->dl_CertFreeCertificateContext(p_cert_context);
      symbols->dl_CertCloseStore(h_store, 0);
      return std::nullopt;
    }
  }
  symbols->dl_CertCloseStore(h_store, 0);
  return std::nullopt;
}

/**
 * @brief  Get an OCSP server response online
 * @param p_chain chain, built for the subject certifiate
 * @param symbols
 * @return asn::OCSPResponse
 * @throws runtime_error
 */
asn::OCSPResponse GetOCSPResponseOnline(const CERT_CHAIN_CONTEXT *p_chain,
                                        const PtrSymbolResolver &symbols) {
  std::pair<HCERT_SERVER_OCSP_RESPONSE, PCCERT_SERVER_OCSP_RESPONSE_CONTEXT>
    ocsp_result{nullptr, nullptr};
  asn::OCSPResponse response;
  if (p_chain == nullptr || !symbols) {
    throw std::runtime_error("[GetOCSPResponseOnline] nullptr in parameters");
  }
  ocsp_result = GetOcspResponseAndContext(p_chain, symbols);
  try {
    const auto &resp_context = ocsp_result.second;
    // parse response
    const asn::AsnObj resp(resp_context->pbEncodedOcspResponse,
                           resp_context->cbEncodedOcspResponse);
    response = asn::OCSPResponse(resp);
    // check status
    if (response.responseStatus != asn::OCSPResponseStatus::kSuccessful) {
      symbols->log->error("[GetOCSPResponseOnline] bad OCSP response status");
      throw std::runtime_error("OCSP status != success");
    }
  } catch (const std::exception & /*ex*/) {
    FreeOcspResponseAndContext(ocsp_result, symbols);
    throw;
  }
  FreeOcspResponseAndContext(ocsp_result, symbols);
  return response;
}

/**
 * @brief Compare root certificates of two chains by subject
 * @param first chain1
 * @param second chain2
 * @throws runtime_error if nullptr in params
 */
bool CompareRootSubjectsForTwoChains(const CERT_CHAIN_CONTEXT *first,
                                     const CERT_CHAIN_CONTEXT *second) {
  if (first == nullptr || second == nullptr) {
    throw std::runtime_error(
      "[CompareRootSubjectsForTwoChains] nullptr in params");
  }
  const PCCERT_CONTEXT first_root_cert_ctx =
    GetRootCertificateCtxFromChain(first);
  const PCCERT_CONTEXT sec_root_cert_ctx =
    GetRootCertificateCtxFromChain(second);
  BytesVector subj1;
  std::copy(first_root_cert_ctx->pCertInfo->Subject.pbData,
            first_root_cert_ctx->pCertInfo->Subject.pbData +
              first_root_cert_ctx->pCertInfo->Subject.cbData,
            std::back_inserter(subj1));
  BytesVector subj2;
  std::copy(sec_root_cert_ctx->pCertInfo->Subject.pbData,
            sec_root_cert_ctx->pCertInfo->Subject.pbData +
              sec_root_cert_ctx->pCertInfo->Subject.cbData,
            std::back_inserter(subj2));
  return subj1 == subj2;
}

/**
 * @brief Check ocsp response status for the cerificate at certain data
 * @param response OCSPResponse obj
 * @param p_ctx_ Subject certificate context
 * @param p_time_t nullptr for "now"
 * @return true
 * @return false
 * @throws runtime error
 */
bool CheckOCSPResponseStatusForCert(const asn::OCSPResponse &response,
                                    const CERT_CONTEXT *p_ctx_,
                                    const time_t *p_time_t, bool mocked_ocsp) {
  if (p_ctx_ == nullptr) {
    throw std::runtime_error(
      "[CheckOCSPResponseStatucForCert] cert contex == nullptr");
  }
  auto logger = logger::InitLog();
  if (!logger) {
    throw std::runtime_error(
      "[CheckOCSPResponseStatusForCert] init logger failed");
  }
  BytesVector serial;
  std::reverse_copy(p_ctx_->pCertInfo->SerialNumber.pbData,
                    p_ctx_->pCertInfo->SerialNumber.pbData +
                      p_ctx_->pCertInfo->SerialNumber.cbData,
                    std::back_inserter(serial));
  const auto it_response = std::find_if(
    response.responseBytes.response.tbsResponseData.responses.cbegin(),
    response.responseBytes.response.tbsResponseData.responses.cend(),
    [&serial](const asn::SingleResponse &response) {
      return response.certID.serialNumber == serial;
    });
  if (it_response ==
      response.responseBytes.response.tbsResponseData.responses.cend()) {
    logger->error(
      "[CheckOCSPResponseStatusForCert] response was not found for cert");
  }
  // check status of the certificate
  bool cert_id_equal = false;
  bool cert_status_ok = false;
  bool time_ok = false;

  if (it_response !=
      response.responseBytes.response.tbsResponseData.responses.cend()) {
    cert_id_equal = true;
    // if we have a good certificate
    if (it_response->certStatus == asn::CertStatus::kRevoked &&
        p_time_t != nullptr) {
      const auto parsed_revocation_time =
        GeneralizedTimeToTimeT(it_response->revocationTime);
      const time_t revoc_time =
        parsed_revocation_time.time + parsed_revocation_time.gmt_offset;
      if (logger) {
        logger->info("revocation time = {}", revoc_time);
        logger->info("current (time_stamp_time) = {}", *p_time_t);
      }
      if (*p_time_t < revoc_time) {
        cert_status_ok = true;
      }
    }
    if (it_response->certStatus == asn::CertStatus::kGood) {
      cert_status_ok = true;
    }
    // Check the time
    const ParsedTime time_parsed =
      GeneralizedTimeToTimeT(it_response->thisUpdate);
    const std::time_t response_time = time_parsed.time + time_parsed.gmt_offset;
    auto now = std::chrono::system_clock::now();
    const std::time_t now_c = p_time_t != nullptr
                                ? *p_time_t
                                : std::chrono::system_clock::to_time_t(now);
    const bool mocked_time = p_time_t != nullptr;
    // if we use the real time,the response must be fresh
    logger->info("Resonse time = {} now= {}", response_time, now_c);
    time_ok = CompareCurrTimeAndResponseTime(mocked_time, mocked_ocsp, now_c,
                                             response_time);
    if (!time_ok) {
      logger->error("Response time is not valid");
    }
  }
  // TODO(Oleg) place revocation time in time_bounds_ if revoced
  return cert_id_equal && cert_status_ok && time_ok;
}

bool CompareCurrTimeAndResponseTime(bool mocked_time, bool mocked_ocsp,
                                    time_t now_c, time_t response_time) {
  const std::time_t time_abs_delta =
    now_c >= response_time ? now_c - response_time : response_time - now_c;
  auto logger = logger::InitLog();
  if (logger) {
    logger->info("time delta = {}", time_abs_delta);
  }
  bool time_ok = false;
  if ((mocked_time && mocked_ocsp) || (!mocked_time && !mocked_ocsp)) {
    if (response_time <= now_c && time_abs_delta < 50) {
      time_ok = true;
    }
    if (response_time > now_c && time_abs_delta < TIME_RELAX) {
      time_ok = true;
    }
  }
  if (mocked_time && !mocked_ocsp &&
      (response_time >= now_c || time_abs_delta < TIME_RELAX)) {
    time_ok = true;
  }
  return time_ok;
}

/**
 * @brief Verify the OCSP response signature
 * @param response OCSPResponse
 * @param p_ocsp_ctx OCSP certificate context
 * @param symbols
 * @return true
 * @return false
 * @throws runtime_exception
 */
bool VerifyOCSPResponseSignature(const asn::OCSPResponse &response,
                                 const CERT_CONTEXT *p_ocsp_ctx,
                                 const PtrSymbolResolver &symbols) {
  if (p_ocsp_ctx == nullptr) {
    throw std::runtime_error(
      "[VerifyOCSPResponseSignature] ocsp cert == nullptr");
  }
  HCRYPTKEY handler_pub_key = 0;
  try {
    if (response.responseBytes.response.signatureAlgorithm !=
        szOID_CP_GOST_R3411_12_256_R3410) {
      symbols->log->error(response.responseBytes.response.signatureAlgorithm);
      throw std::runtime_error("unsupported signature algorithm");
    }
    HashHandler hash(szOID_CP_GOST_R3411_12_256, symbols);
    hash.SetData(response.responseBytes.response.resp_data_der_encoded);
    // import public key

    CERT_PUBLIC_KEY_INFO *p_ocsp_public_key_info =
      &p_ocsp_ctx->pCertInfo->SubjectPublicKeyInfo;
    ResCheck(symbols->dl_CryptImportPublicKeyInfo(
               hash.get_csp_hanler(), PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
               p_ocsp_public_key_info, &handler_pub_key),
             "CryptImportPublicKeyInfo", symbols);

    if (handler_pub_key == 0) {
      throw std::runtime_error("Import public key failed");
    }
    // verify signature
    BytesVector signature = response.responseBytes.response.signature;
    std::reverse(signature.begin(), signature.end());
    // delete last 0 byte from signature
    signature.pop_back();
    ResCheck(symbols->dl_CryptVerifySignatureA(
               hash.get_hash_handler(), signature.data(), signature.size(),
               handler_pub_key, nullptr, 0),
             "CryptVerifySignature", symbols);
    symbols->dl_CryptDestroyKey(handler_pub_key);
  } catch (const std::exception &ex) {
    symbols->log->error("[VerifyOCSPResponseSignature] {}", ex.what());
    return false;
  }
  return true;
}

/**
 * @brief Get the Ocsp Response Context object
 * @details response and context must be freed by the receiver
 * @param p_chain_context Context of cerificate chain
 * @param symbols
 * @return std::pair<HCERT_SERVER_OCSP_RESPONSE,
 * PCCERT_SERVER_OCSP_RESPONSE_CONTEXT>
 * @throws runtime_error
 */
std::pair<HCERT_SERVER_OCSP_RESPONSE, PCCERT_SERVER_OCSP_RESPONSE_CONTEXT>
GetOcspResponseAndContext(PCCERT_CHAIN_CONTEXT p_chain_context,
                          const PtrSymbolResolver &symbols) {
  HCERT_SERVER_OCSP_RESPONSE ocsp_response =
    symbols->dl_CertOpenServerOcspResponse(p_chain_context, 0, nullptr);

  if (ocsp_response == nullptr) {
    symbols->log->error("CertOpenServerOcspResponse = nullptr");
    throw std::runtime_error("CertOpenServerOcspResponse failed");
  }
  PCCERT_SERVER_OCSP_RESPONSE_CONTEXT resp_context =
    symbols->dl_CertGetServerOcspResponseContext(ocsp_response, 0, nullptr);
  if (resp_context == nullptr) {
    if (ocsp_response != nullptr) {
      symbols->dl_CertCloseServerOcspResponse(ocsp_response, 0);
    }
    symbols->log->warn("OCSP return context == nullptr");
    throw std::runtime_error("OCSP connect failed");
  }
  return std::make_pair(ocsp_response, resp_context);
}

/**
 * @brief Free OCSP response and context
 * @param pair of handle to response and response context
 * @param symbols
 */
void FreeOcspResponseAndContext(
  std::pair<HCERT_SERVER_OCSP_RESPONSE, PCCERT_SERVER_OCSP_RESPONSE_CONTEXT>
    val,
  const PtrSymbolResolver &symbols) noexcept {
  if (val.second != nullptr) {
    symbols->dl_CertFreeServerOcspResponseContext(val.second);
  }
  if (val.first != nullptr) {
    symbols->dl_CertCloseServerOcspResponse(val.first, 0);
  }
}

std::shared_ptr<boost::json::array> CertListToJSONArray(
  const std::vector<CertCommonInfo> &cert_list) noexcept {
  try {
    auto res = std::make_shared<boost::json::array>();
    for (const auto &cert : cert_list) {
      res->emplace_back(cert.ToJson());
    }
    return res;
  } catch (const std::exception &) {
    return nullptr;
  }
}

}  // namespace pdfcsp::csp::utils::cert
