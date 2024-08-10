#pragma once

#include "asn1.hpp"
#include "message.hpp"
#include "typedefs.hpp"
namespace pdfcsp::csp {

/**
 * @brief Convert CadesType enum to int constant like CADES_BES, etc.
 * @param type
 * @return int
 * @throws runtime_error if type is unknown
 */
int InternalCadesTypeToCspType(CadesType type);

/**
 * @brief Convert CadesType enum to string
 * @param type
 * @return string
 */
std::string InternalCadesTypeToString(CadesType type) noexcept;

/**
 * @brief Find index of CONTENT object in a root signature ASN object
 *
 * @param sig_obj Root signature ASN obj
 * @return uint64_t the index of "content"
 * @throw runtime_error on fail
 */
uint64_t FindSigContentIndex(const asn::AsnObj &sig_obj);

/**
 * @brief Find a SignerInfos node index in a SignedData node
 * @param signed_data ASN obj
 * @return uint64_t index of SignerInfos
 * @throws runtime_error on fail
 */
uint64_t FindSignerInfosIndex(const asn::AsnObj &signed_data);

/**
 * @brief Extratc OCSP server links from authorityInfo
 * @param authority_info
 * @return std::vector<std::string>
 */
[[nodiscard]] std::vector<std::string>
FindOcspLinksInAuthorityInfo(const asn::AsnObj &authority_info);

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
 * @brief Count attributes with a particular OID
 * @param attrs
 * @param oid
 * @return unsigned int
 */
unsigned int CountAttributesWithOid(const CryptoAttributesBunch &attrs,
                                    const std::string &oid) noexcept;

/**
 * @brief Extract ASN1 signersInfo from raw signature
 * @param signer_index
 * @param raw_signature
 * @param symbols
 * @return asn::AsnObj
 * @throws runtime_error
 */
asn::AsnObj ExtractAsnSignersInfo(uint signer_index,
                                  const BytesVector &raw_signature,
                                  const PtrSymbolResolver &symbols);

/**
 * @brief Copy a raw atrribute except it's osn header (type and size)
 * @param attrs AsnObj with attributes
 * @param oid - attribute to copy
 * @param dest - destanation BytesVector
 */
void CopyRawAttributeExceptAsnHeader(const asn::AsnObj &attrs,
                                     const std::string &oid, BytesVector &dest);

} // namespace pdfcsp::csp
