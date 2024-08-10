#include "utils_cert.hpp"
#include "CSP_WinCrypt.h"
#include "certificate.hpp"
#include "certificate_id.hpp"
#include "hash_handler.hpp"
#include "oids.hpp"
#include "typedefs.hpp"
#include "utils.hpp"
#include <algorithm>
#include <cstring>
#include <exception>
#include <iostream>
#include <iterator>
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
                                     const PtrSymbolResolver &symbols) {
  PCCERT_CHAIN_CONTEXT p_chain_context = nullptr;
  CERT_CHAIN_PARA chain_params{};
  chain_params.cbSize = sizeof(CERT_CHAIN_PARA);
  ResCheck(symbols->dl_CertGetCertificateChain(
               nullptr, p_cert_ctx, nullptr, nullptr, &chain_params,
               CERT_CHAIN_CACHE_END_CERT | CERT_CHAIN_REVOCATION_CHECK_CHAIN,
               nullptr, &p_chain_context),
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
    std::cerr << "Ignoring revoc checks errors\n";
  }
  ResCheck(
      symbols->dl_CertVerifyCertificateChainPolicy(
          CERT_CHAIN_POLICY_BASE, // NOLINT(cppcoreguidelines-pro-type-cstyle-cast)
          p_chain_context, &policy_params, &policy_status),
      "CertVerifyCertificateChainPolicy", symbols);
  if (policy_status.dwError != 0) {
    switch (policy_status.dwError) {
    case 0x800b0109:
      std::cerr
          << "A certification chain processed correctly but terminated in a "
             "root certificate that is not trusted by the trust provider.\n";
      break;
    case 0x80092012L:
      std::cerr << "The revocation function was unable to check revocation for "
                   "the certificate\n";
      break;
    default:
      std::cerr << "[CheckCertChain] error " << std::hex
                << policy_status.dwError << "\n";
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
  // NOLINTBEGIN(cppcoreguidelines-pro-bounds-pointer-arithmetic)
  PCERT_SIMPLE_CHAIN simple_chain =
      p_chain_context->rgpChain[p_chain_context->cChain - 1];
  if (simple_chain->cElement == 0) {
    throw std::runtime_error("No elements in simple chain");
  }
  // 2.get a root certificate context
  PCCERT_CONTEXT p_root_cert_context =
      simple_chain->rgpElement[simple_chain->cElement - 1]->pCertContext;
  // NOLINTEND(cppcoreguidelines-pro-bounds-pointer-arithmetic)
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
    // NOLINTBEGIN(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    const BytesVector extval(ext->Value.pbData,
                             ext->Value.pbData + ext->Value.cbData);
    // NOLINTEND(cppcoreguidelines-pro-bounds-pointer-arithmetic)
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
    const asn::AsnObj asn_obj(ext->Value.pbData, ext->Value.cbData, symbols);
    if (asn_obj.GetAsnTag() != asn::AsnTag::kSequence ||
        asn_obj.ChildsCount() == 0) {
      continue;
    }
    if (asn_obj.at(0).GetAsnTag() == asn::AsnTag::kOid &&
        asn_obj.at(0).GetStringData().value_or("") == oid_usage) {
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
  const unsigned int numb_extension = cert_ctx->pCertInfo->cExtension;
  const std::string oid_key_usage(asn::kOID_id_ce_keyUsage);
  for (uint i = 0; i < numb_extension; ++i) {
    CERT_EXTENSION *ext = &cert_ctx->pCertInfo->rgExtension[i];
    if (ext->Value.cbData < 4 || ext->Value.pbData == nullptr) {
      continue;
    }
    if (oid_key_usage != ext->pszObjId) {
      continue;
    }
    // NOLINTBEGIN(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    const BytesVector val(ext->Value.pbData,
                          ext->Value.cbData + ext->Value.pbData);
    // NOLINTEND(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    // check if asn1 bit string
    if (val[0] != 0x03 || val[1] != 0x02) {
      continue;
    }
    auto unused = static_cast<uint>(val[2]);
    if (unused > 7) {
      return false;
    }
    auto max_index = 7 - unused;
    if (bit_number > max_index) {
      return false;
    }
    const std::bitset<8> bits(val[3]);
    return bits.test(bit_number + unused);
  }
  return false;
}

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
                    const PtrSymbolResolver &symbols) noexcept {
  if (cert_id.serial.empty() || cert_id.hash_cert.empty() ||
      cert_id.hashing_algo_oid.empty() || !symbols) {
    return std::nullopt;
  }
  HCERTSTORE h_store = symbols->dl_CertOpenStore(
      CERT_STORE_PROV_SYSTEM, 0, 0, // NOLINT
      CERT_SYSTEM_STORE_CURRENT_USER | CERT_STORE_OPEN_EXISTING_FLAG |
          CERT_STORE_READONLY_FLAG,
      storage.c_str());
  if (h_store == nullptr) {
    return std::nullopt;
  }
  BytesVector expected;
  std::reverse_copy(cert_id.serial.cbegin(), cert_id.serial.cend(),
                    std::back_inserter(expected));
  PCCERT_CONTEXT p_cert_context = nullptr;
  while ((p_cert_context = symbols->dl_CertEnumCertificatesInStore(
              h_store, p_cert_context)) != nullptr) {
    const BytesVector serial(
        p_cert_context->pCertInfo->SerialNumber.pbData,
        p_cert_context->pCertInfo->SerialNumber.pbData + // NOLINT
            p_cert_context->pCertInfo->SerialNumber.cbData);
    // when found - check hash
    if (expected == serial && p_cert_context->cbCertEncoded != 0 &&
        p_cert_context->pbCertEncoded != nullptr) {
      const BytesVector cert_raw(p_cert_context->pbCertEncoded,
                                 p_cert_context->pbCertEncoded +
                                     p_cert_context->cbCertEncoded);
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
  if (p_cert_context != nullptr) {
    try {
      return Certificate(h_store, p_cert_context, symbols);
    } catch (const std::exception &) {
      symbols->dl_CertFreeCertificateContext(p_cert_context);
      symbols->dl_CertCloseStore(h_store, 0);
    }
  }
  if (h_store != nullptr) {
    symbols->dl_CertCloseStore(h_store, 0);
  }
  return std::nullopt;
};

} // namespace pdfcsp::csp