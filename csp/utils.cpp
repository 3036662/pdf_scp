#include "utils.hpp"
#include "asn1.hpp"
#include "cades.h"
#include "message.hpp"
#include "resolve_symbols.hpp"
#include "typedefs.hpp"
#include <cstdint>
#include <cstring>
#include <exception>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <limits>
#include <memory>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <utility>
#include <vector>

namespace pdfcsp::csp {

std::vector<unsigned char> CreateBuffer(size_t size) {
  std::vector<unsigned char> res;
  if (size > res.max_size()) {
    throw std::logic_error("Can't reserve a buffer, size > max_size");
  }
  res.reserve(size + 1);
  return res;
}

std::optional<std::vector<unsigned char>>
IntBlobToVec(const CRYPT_INTEGER_BLOB *p_blob) noexcept {
  if (p_blob == nullptr || p_blob->cbData <= 0 || p_blob->cbData > 0x7FFFFFFF) {
    return std::nullopt;
  }
  std::vector<unsigned char> res;
  const DWORD index_last = p_blob->cbData - 1;
  for (int64_t i = static_cast<int>(index_last); i >= 0; --i) {
    // NOLINTNEXTLINE (cppcoreguidelines-pro-bounds-pointer-arithmetic)
    res.push_back(p_blob->pbData[i]);
  }
  if (res.empty()) {
    return std::nullopt;
  }
  return res;
}

std::string
VecBytesStringRepresentation(const std::vector<unsigned char> &vec) noexcept {
  std::stringstream builder;
  for (const auto symbol : vec) {
    builder << std::hex << static_cast<int>(symbol);
  }
  return builder.str();
}

void PrintBytes(const BytesVector &val) noexcept {
  for (const auto &symbol : val) {
    std::cout << std::hex << static_cast<int>(symbol) << " ";
  }
  std::cout << "\n";
}

// throw exception if FALSE
void ResCheck(BOOL res, const std::string &msg,
              const PtrSymbolResolver &symbols) {
  if (res != TRUE) {
    std::stringstream string_builder;
    string_builder << msg << " error " << std::hex
                   << symbols->dl_GetLastError();
    throw std::runtime_error(string_builder.str());
  }
}

// TODO(Oleg) consider implementing a low-level function to decode asn name
// string, because of errors in dl_CertNameToStrA
[[nodiscard]] std::optional<std::string>
NameBlobToString(CERT_NAME_BLOB *ptr_name_blob,
                 const PtrSymbolResolver &symbols) noexcept {
  if (ptr_name_blob == nullptr || !symbols) {
    return std::nullopt;
  }
  const DWORD dw_size = symbols->dl_CertNameToStrA(
      X509_ASN_ENCODING, ptr_name_blob, CERT_X500_NAME_STR, nullptr, 0);
  // std::cout << "DECODED numb=" << dw_size << "\n";
  if (dw_size == 0 || dw_size > std::numeric_limits<unsigned int>::max()) {
    return std::nullopt;
  }
  try {
    auto tmp_buff = CreateBuffer(dw_size);
    tmp_buff.resize(dw_size, 0x00);
    //  NOLINTNEXTLINE (cppcoreguidelines-pro-type-reinterpret-cast)
    char *ptr_buff_raw = reinterpret_cast<char *>(tmp_buff.data());
    const DWORD resSize = symbols->dl_CertNameToStrA(
        X509_ASN_ENCODING, ptr_name_blob, CERT_X500_NAME_STR, ptr_buff_raw,
        dw_size); // NOLINT
    if (resSize == 0) {
      return std::nullopt;
    }
    std::string buff;
    // NOLINTNEXTLINE (cppcoreguidelines-pro-bounds-pointer-arithmetic)
    std::copy(tmp_buff.data(), tmp_buff.data() + resSize - 1,
              std::back_inserter(buff));
    tmp_buff.clear();
    return buff;
  } catch (const std::exception &) {
    return std::nullopt;
  }
  return std::nullopt;
}

// read file to vector
std::optional<std::vector<unsigned char>>
FileToVector(const std::string &path) noexcept {
  namespace fs = std::filesystem;
  if (path.empty() || !fs::exists(path)) {
    return std::nullopt;
  }
  std::ifstream file(path, std::ios_base::binary);
  if (!file.is_open()) {
    return std::nullopt;
  }
  std::vector<unsigned char> res;
  try {
    std::vector<unsigned char> tmp((std::istream_iterator<unsigned char>(file)),
                                   std::istream_iterator<unsigned char>());
    res = std::move(tmp);
  } catch ([[maybe_unused]] const std::exception &ex) {
    file.close();
    return std::nullopt;
  }
  file.close();
  return res;
}

/**
 * @brief Get the CSP Provider Type
 * @param hashing_algo
 * @return unsigned long aka HCRYPTPROV
 * @throws runtime_error for an unknown algorithm
 */
uint64_t GetProviderType(const std::string &hashing_algo) {
  if (hashing_algo == szOID_CP_GOST_R3411_12_256) {
    return PROV_GOST_2012_256;
  }
  throw std::runtime_error("[GetProviderType] Unknown hashing algorithm");
}

/**
 * @brief Get the Hash Calc Type object
 * @param hashing_algo
 * @return unsigned int aka ALG_ID
 * @throws runtime_error for an unknown algo
 */
unsigned int GetHashCalcType(const std::string &hashing_algo) {
  if (hashing_algo == szOID_CP_GOST_R3411_12_256) {
    return CALG_GR3411_2012_256;
  }
  throw std::runtime_error("[GetHashCalcType] Unknown hashing algorithm");
}

/**
 * @brief Convert CadesType enum to int constant like CADES_BES, etc.
 * @param type
 * @return int
 * @throws runtime_error if type is unknown
 */
int InternalCadesTypeToCspType(CadesType type) {
  switch (type) {
  case CadesType::kUnknown:
    throw std::runtime_error("Unknowdn cades type");
    break;
  case CadesType::kCadesBes:
    return CADES_BES;
    break;
  case CadesType::kCadesT:
    return CADES_T;
    break;
  case CadesType::kCadesXLong1:
    return CADES_X_LONG_TYPE_1;
    break;
  case CadesType::kPkcs7:
    return PKCS7_TYPE;
    break;
  }
  return 0;
}

/**
 * @brief Convert CadesType enum to string
 * @param type
 * @return string

 */
std::string InternalCadesTypeToString(CadesType type) noexcept {
  switch (type) {
  case CadesType::kUnknown:
    return "Unknown";
    break;
  case CadesType::kCadesBes:
    return "CADES_BES";
    break;
  case CadesType::kCadesT:
    return "CADES_T";
    break;
  case CadesType::kCadesXLong1:
    return "CADES_X_LONG_TYPE_1";
    break;
  case CadesType::kPkcs7:
    return "PKCS7_TYPE";
    break;
  }
  return "Unknown";
}

/**
 * @brief Find index of CONTENT object in a root signature ASN object
 *
 * @param sig_obj Root signature ASN obj
 * @return uint64_t the index of "content"
 * @throw runtime_error on fail
 */
uint64_t FindSigContentIndex(const AsnObj &sig_obj) {
  uint64_t index_content = 0;
  bool content_found = false;
  for (auto i = 0UL; i < sig_obj.ChildsCount(); ++i) {
    const AsnObj &tmp = sig_obj.GetChilds()[i];
    if (!tmp.IsFlat() && tmp.get_asn_header().asn_tag == AsnTag::kUnknown &&
        tmp.get_asn_header().constructed) {
      index_content = i;
      content_found = true;
      break;
    }
  }
  if (!content_found) {
    throw std::runtime_error("Content node was node found in signature");
  }
  return index_content;
}

/**
 * @brief Find a SignerInfos node index in a SignedData node
 * @param signed_data ASN obj
 * @return uint64_t index of SignerInfos
 * @throws runtime_error on fail
 */
uint64_t FindSignerInfosIndex(const AsnObj &signed_data) {
  // signer infos - second set in signed_data
  u_int64_t index_signers_infos = 0;
  bool signer_infos_found = false;
  u_int64_t set_num = 0;
  for (u_int64_t i = 0; i < signed_data.ChildsCount(); ++i) {
    if (signed_data.GetChilds()[i].get_asn_header().asn_tag == AsnTag::kSet) {
      ++set_num;
      if (set_num == 2) {
        index_signers_infos = i;
        signer_infos_found = true;
        break;
      }
    }
  }
  if (!signer_infos_found) {
    throw std::runtime_error("signerInfos node was note found");
  }
  return index_signers_infos;
}

std::vector<std::string>
FindOcspLinksInAuthorityInfo(const AsnObj &authority_info) {
  std::vector<std::string> ocsp_links;
  for (const auto &seq : authority_info.GetChilds()) {
    if (seq.IsFlat() || seq.ChildsCount() != 2 ||
        seq.GetChilds()[0].get_asn_header().asn_tag != AsnTag::kOid) {
      throw std::runtime_error(
          "invalid data in the authorityInfoAccess extension");
    }
    if (seq.GetChilds()[0].GetStringData() == szOID_PKIX_OCSP &&
        seq.GetChilds()[1].get_asn_header().tag_type ==
            AsnTagType::kContentSpecific) {
      ocsp_links.emplace_back(seq.GetChilds()[1].GetData().cbegin(),
                              seq.GetChilds()[1].GetData().cend());
    }
  }
  return ocsp_links;
}

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
 * @param symbols
 * @throws runtime_error
 */
bool CheckCertChain(PCCERT_CHAIN_CONTEXT p_chain_context,
                    const PtrSymbolResolver &symbols) {
  CERT_CHAIN_POLICY_PARA policy_params{};
  memset(&policy_params, 0x00, sizeof(CERT_CHAIN_POLICY_PARA));
  policy_params.cbSize = sizeof(CERT_CHAIN_POLICY_PARA);
  CERT_CHAIN_POLICY_STATUS policy_status{};
  memset(&policy_status, 0x00, sizeof(CERT_CHAIN_POLICY_STATUS));
  policy_status.cbSize = sizeof(CERT_CHAIN_POLICY_STATUS);

  ResCheck(
      symbols->dl_CertVerifyCertificateChainPolicy(
          CERT_CHAIN_POLICY_BASE, // NOLINT(cppcoreguidelines-pro-type-cstyle-cast)
          p_chain_context, &policy_params, &policy_status),
      "CertVerifyCertificateChainPolicy", symbols);
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
    std::cerr << "CertOpenServerOcspResponse = nullptr";
    throw std::runtime_error("CertOpenServerOcspResponse failed");
  }
  PCCERT_SERVER_OCSP_RESPONSE_CONTEXT resp_context =
      symbols->dl_CertGetServerOcspResponseContext(ocsp_response, 0, nullptr);
  if (resp_context == nullptr) {
    if (ocsp_response != nullptr) {
      symbols->dl_CertCloseServerOcspResponse(ocsp_response, 0);
    }
    std::cerr << "OCSP return context == nullptr\n";
    throw std::runtime_error("OCSP connect failed");
  }
  return std::make_pair(ocsp_response, resp_context);
}

/**
 * @brief Free OCSP response and context
 *
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

} // namespace pdfcsp::csp