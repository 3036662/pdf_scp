#pragma once

#include "certificate.hpp"
#include "certificate_id.hpp"
#include "resolve_symbols.hpp"
#include <optional>

namespace pdfcsp::csp {

/**
 * @brief Create a Certifate Chain context
 * @details context must be freed by the receiver with FreeChainContext
 * @param p_cert_ctx Certificate context
 * @param symbols
 * @return PCCERT_CHAIN_CONTEXT chain context
 * @throws runtime_error
 */
PCCERT_CHAIN_CONTEXT CreateCertChain(PCCERT_CONTEXT p_cert_ctx,
                                     const PtrSymbolResolver &symbols);

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
 * @brief Looks for a certificate in store
 * @details Looks by serial and hash
 * @param cert_id serial, hash and algo can't be empty
 * @param storage widestring like L"MY"
 * @param symbols
 * @return std::optional<Certificate>
 */
std::optional<Certificate>
FindCertInStoreByID(CertificateID &cert_id, const std::wstring &storage,
                    const PtrSymbolResolver &symbols) noexcept;

} // namespace pdfcsp::csp