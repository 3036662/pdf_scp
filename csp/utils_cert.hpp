/* File: utils_cert.hpp  
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


#pragma once

#include "cert_common_info.hpp"
#include "certificate.hpp"
#include "certificate_id.hpp"
#include "ocsp.hpp"
#include "resolve_symbols.hpp"
#include <boost/json/array.hpp>
#include <cstdint>
#include <ctime>
#include <memory>
#include <optional>
#include <vector>

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
PCCERT_CHAIN_CONTEXT CreateCertChain(PCCERT_CONTEXT p_cert_ctx,
                                     const PtrSymbolResolver &symbols,
                                     FILETIME *p_time = nullptr,
                                     HCERTSTORE h_additional_store = nullptr,
                                     bool offline = false);

/**
 * @brief Free chain context
 * @param ctx
 * @param symbols
 */
void FreeChainContext(PCCERT_CHAIN_CONTEXT ctx,
                      const PtrSymbolResolver &symbols) noexcept;

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
                    const PtrSymbolResolver &symbols);

/**
 * @brief Get the Root Certificate Ctx From Chain object
 * @param p_chain_context
 * @return PCCERT_CONTEXT
 * @throw runtime_error
 */
PCCERT_CONTEXT
GetRootCertificateCtxFromChain(PCCERT_CHAIN_CONTEXT p_chain_context);

/**
 * @brief Check if the certificate has an id-pkix-ocsp-nocheck extension
 * @details  RFC 6960 [4.2.2.2.1]
 * @param cert_ctx - The certificate context
 * @throws runtime_error
 */
bool CertificateHasOcspNocheck(PCCERT_CONTEXT cert_ctx);

/**
 * @brief Check if the certificate has an Extended Key Usage
 * @details  RFC 5280 [4.2.1.12]
 * @param cert_ctx - The certificate context
 * @param oid_usage - string OID to check for
 * @throws runtime_error
 */
bool CertificateHasExtendedKeyUsage(PCCERT_CONTEXT cert_ctx,
                                    const std::string &oid_usage);

/**
 * @brief Check if the certificate has a Key Usage bit
 * @details  RFC 5280 [4.2.1.3]
 * @param cert_ctx - The certificate context
 * @param bit_number witch bit to check
 * @throws runtime_error
 */
bool CertificateHasKeyUsageBit(PCCERT_CONTEXT cert_ctx, uint8_t bit_number);

/**
 * @brief Get the Certificate raw keyUsage bits value
 * @details reads only 8 first bits RFC 5280 [4.2.1.3]
 * @param cert_info - pointer to CERT_INFO
 * @throws runtime_error
 */
uint8_t CertificateKeyUsageRawBits(const CERT_INFO *p_info);

/**
 * @brief  Get the Certificate raw keyUsage bits value
 * @details  RFC 5280 [4.2.1.3]
 * @param p_info
 * @return std::string
 * @throws runtime_error
 */
std::string CertificateKeyUsageRawBitsToStr(const CERT_INFO *p_info);

/**
 * @brief Looks for a certificate in store
 * @details Looks by serial and hash
 * @param cert_id serial, hash and algo can't be empty
 * @param storage widestring like L"MY"
 * @param symbols
 * @return std::optional<Certificate>
 * @details keeps a store handler till destroy
 */
std::optional<Certificate>
FindCertInStoreByID(asn::CertificateID &cert_id, const std::wstring &storage,
                    const PtrSymbolResolver &symbols) noexcept;

/**
 * @brief Looks for a certificate in users store
 * @details Looks by serial and subject
 * @param subject - subject common name
 * @param symbols
 * @return std::optional<Certificate>
 * @details keeps a store handler till destroy
 */
std::optional<Certificate>
FindCertInUserStoreBySerial(const std::string &subject,
                            const std::string &serial,
                            const PtrSymbolResolver &symbols);

/**
 * @brief  Get an OCSP server response online
 * @param p_chain chain, built for the subject certifiate
 * @param symbols
 * @return asn::OCSPResponse
 * @throws runtime_error
 */
asn::OCSPResponse GetOCSPResponseOnline(const CERT_CHAIN_CONTEXT *p_chain,
                                        const PtrSymbolResolver &symbols);

/**
 * @brief Compare root certificates of two chains by subject
 * @param first chain1
 * @param second chain2
 * @throws runtime_error if nullptr in params
 */
bool CompareRootSubjectsForTwoChains(const CERT_CHAIN_CONTEXT *first,
                                     const CERT_CHAIN_CONTEXT *second);

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
                                    const time_t *p_time_t = nullptr,
                                    bool mocked_ocsp = false);

bool CompareCurrTimeAndResponseTime(bool mocked_time, bool mocked_ocsp,
                                    time_t now_c, time_t response_time);

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
                                 const PtrSymbolResolver &symbols);

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
                          const PtrSymbolResolver &symbols);

/**
 * @brief Free OCSP response and context
 * @param pair of handle to response and response context
 * @param symbols
 */
void FreeOcspResponseAndContext(
    std::pair<HCERT_SERVER_OCSP_RESPONSE, PCCERT_SERVER_OCSP_RESPONSE_CONTEXT>
        val,
    const PtrSymbolResolver &symbols) noexcept;

/**
 * @brief identifies whether the subject of the
   certificate is a CA
 * @details  RFC 5280 [4.2.1.9]
 * @param cert_ctx - The certificate context
 * @throws runtime_error
 */
bool CertificateIsCA(PCCERT_CONTEXT cert_ctx);

/**
 * @brief Creates a JSON array from array of CertCommonInfi
 * @param cert_list
 * @return std::shared_ptr<boost::json::array> , nullptr on error
 */
std::shared_ptr<boost::json::array>
CertListToJSONArray(const std::vector<CertCommonInfo> &cert_list) noexcept;

} // namespace pdfcsp::csp::utils::cert
