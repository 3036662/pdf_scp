/* File: utils_msg.hpp
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

#include "asn1.hpp"
#include "certificate.hpp"
#include "crypto_attribute.hpp"
#include "resolve_symbols.hpp"
#include "revoc_refs.hpp"
#include "typedefs.hpp"
namespace pdfcsp::csp::utils::message {

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
[[nodiscard]] std::vector<std::string> FindOcspLinksInAuthorityInfo(
  const asn::AsnObj &authority_info);

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
                                  const BytesVector &raw_signature);

/**
 * @brief Copy a raw atrribute except it's osn header (type and size)
 * @param attrs AsnObj with attributes
 * @param oid - attribute to copy
 * @param dest - destanation BytesVector
 */
void CopyRawAttributeExceptAsnHeader(const asn::AsnObj &attrs,
                                     const std::string &oid, BytesVector &dest);

/**
 * @brief Returns parsed certificate references attribute
 * @param unsigned_attributes
 * @return asn::CompleteCertificateRefs
 * @throws runtime_error
 */
asn::CompleteCertificateRefs ExtractCertRefs(
  const CryptoAttributesBunch &unsigned_attributes);

/**
 * @brief Returns parsed revocation references attribute
 * @param unsigned_attributes
 * @return asn::CompleteRevocationRefs
 * @throws runtime_error
 */
asn::CompleteRevocationRefs ExtractRevocRefs(
  const CryptoAttributesBunch &unsigned_attributes);

std::vector<Certificate> ExtractCertVals(
  const CryptoAttributesBunch &unsigned_attributes,
  const PtrSymbolResolver &symbols);

}  // namespace pdfcsp::csp::utils::message
