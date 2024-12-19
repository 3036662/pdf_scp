/* File: utils_msg.cpp  
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


#include "utils_msg.hpp"
#include "asn1.hpp"
#include "cert_refs.hpp"
#include "certificate.hpp"
#include "crypto_attribute.hpp"
#include "oids.hpp"
#include "resolve_symbols.hpp"
#include "revoc_refs.hpp"
#include "typedefs.hpp"
#include <algorithm>
#include <stdexcept>
#include <vector>

namespace pdfcsp::csp::utils::message {

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
uint64_t FindSigContentIndex(const asn::AsnObj &sig_obj) {
  uint64_t index_content = 0;
  bool content_found = false;
  for (auto i = 0UL; i < sig_obj.Size(); ++i) {
    const asn::AsnObj &tmp = sig_obj.Childs()[i];
    if (!tmp.IsFlat() && tmp.Header().asn_tag == asn::AsnTag::kUnknown &&
        tmp.Header().constructed) {
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
uint64_t FindSignerInfosIndex(const asn::AsnObj &signed_data) {
  // signer infos - second set in signed_data
  u_int64_t index_signers_infos = 0;
  bool signer_infos_found = false;
  u_int64_t set_num = 0;
  for (u_int64_t i = 0; i < signed_data.Size(); ++i) {
    if (signed_data.Childs()[i].Header().asn_tag == asn::AsnTag::kSet) {
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

/**
 * @brief Extratc OCSP server links from authorityInfo
 * @param authority_info
 * @return std::vector<std::string>
 */
std::vector<std::string>
FindOcspLinksInAuthorityInfo(const asn::AsnObj &authority_info) {
  std::vector<std::string> ocsp_links;
  for (const auto &seq : authority_info.Childs()) {
    if (seq.IsFlat() || seq.Size() != 2 ||
        seq.Childs()[0].Header().asn_tag != asn::AsnTag::kOid) {
      throw std::runtime_error(
          "invalid data in the authorityInfoAccess extension");
    }
    if (seq.Childs()[0].StringData() == szOID_PKIX_OCSP &&
        seq.Childs()[1].Header().tag_type ==
            asn::AsnTagType::kContentSpecific) {
      ocsp_links.emplace_back(seq.Childs()[1].Data().cbegin(),
                              seq.Childs()[1].Data().cend());
    }
  }
  return ocsp_links;
}

/**
 * @brief Count attributes with a particular OID
 * @param attrs
 * @param oid
 * @return unsigned int
 */
unsigned int CountAttributesWithOid(const CryptoAttributesBunch &attrs,
                                    const std::string &oid) noexcept {
  return std::count_if(
      attrs.get_bunch().cbegin(), attrs.get_bunch().cend(),
      [&oid](const CryptoAttribute &attr) { return attr.get_id() == oid; });
}

/**
 * @brief Extract ASN1 signersInfo from raw signature
 * @param signer_index
 * @param raw_signature
 * @param symbols
 * @return asn::AsnObj
 * @throws runtime_error
 */
asn::AsnObj ExtractAsnSignersInfo(uint signer_index,
                                  const BytesVector &raw_signature) {
  const asn::AsnObj asn(raw_signature.data(), raw_signature.size());
  if (asn.IsFlat() || asn.Size() == 0) {
    throw std::runtime_error(
        "Extract signed attributes failed.ASN1 obj is flat");
  }
  // look for content node
  const uint64_t index_content = FindSigContentIndex(asn);
  const asn::AsnObj &content = asn.Childs()[index_content];
  if (content.IsFlat() || content.Size() == 0) {
    throw std::runtime_error("Content node is empty");
  }
  // signed data node
  const asn::AsnObj &signed_data = content.Childs()[0];
  if (signed_data.Header().asn_tag != asn::AsnTag::kSequence ||
      signed_data.Size() == 0) {
    throw std::runtime_error("Signed data element is empty");
  }
  // signer infos - second set
  const uint64_t index_signers_infos = FindSignerInfosIndex(signed_data);
  const asn::AsnObj &signer_infos = signed_data.Childs()[index_signers_infos];
  if (signer_infos.IsFlat() || signer_infos.Size() == 0) {
    throw std::runtime_error("signerInfos node is empty");
  }
  if (signer_infos.Size() < signer_index) {
    throw std::runtime_error("no signer with such index in signers_info");
  }
  const asn::AsnObj &signer_info = signer_infos.Childs()[signer_index];
  if (signer_info.IsFlat() || signer_info.Size() == 0) {
    throw std::runtime_error("Empty signerInfo node");
  }
  return signer_info;
}

/**
 * @brief Copy a raw atrribute except it's osn header (type and size)
 * @param attrs AsnObj with attributes
 * @param oid - attribute to copy
 * @param dest - destanation BytesVector
 */
void CopyRawAttributeExceptAsnHeader(const asn::AsnObj &attrs,
                                     const std::string &oid,
                                     BytesVector &dest) {
  for (const auto &attr : attrs.Childs()) {
    if (attr.Size() == 0) {
      continue;
    }
    const asn::AsnObj &oid_obj = attr.at(0);
    if (oid_obj.StringData().value_or("") == oid) {
      auto unparsed_attribute = attr.Unparse();
      std::copy(unparsed_attribute.cbegin() + attr.Header().sizeof_header,
                unparsed_attribute.cend(), std::back_inserter(dest));
    }
  }
}

/**
 * @brief Returns parsed certificate references attribute
 * @param unsigned_attributes
 * @return asn::CompleteCertificateRefs
 * @throws runtime_error
 */
asn::CompleteCertificateRefs
ExtractCertRefs(const CryptoAttributesBunch &unsigned_attributes) {
  const BytesVector &attr_blob =
      unsigned_attributes.GetAttrBlobByID(asn::kOID_id_aa_ets_certificateRefs);
  const asn::AsnObj cert_refs_asn(attr_blob.data(), attr_blob.size());
  return asn::ParseCertRefs(cert_refs_asn);
}

/**
 * @brief Returns parsed revocation references attribute
 * @param unsigned_attributes
 * @return asn::CompleteRevocationRefs
 * @throws runtime_error
 */
asn::CompleteRevocationRefs
ExtractRevocRefs(const CryptoAttributesBunch &unsigned_attributes) {
  const BytesVector &attr_blob =
      unsigned_attributes.GetAttrBlobByID(asn::kOID_id_aa_ets_revocationRefs);
  const asn::AsnObj revoc_refs_asn(attr_blob.data(), attr_blob.size());
  return asn::ParseRevocRefs(revoc_refs_asn);
}

/**
 * @brief Extracts certificates from the certVals attribute
 * @param unsigned_attributes
 * @param symbols
 * @return std::vector<Certificate> - decoded Certificate objects
 */
std::vector<Certificate>
ExtractCertVals(const CryptoAttributesBunch &unsigned_attributes,
                const PtrSymbolResolver &symbols) {
  std::vector<Certificate> res;
  const BytesVector &attr_blob =
      unsigned_attributes.GetAttrBlobByID(asn::kOID_id_aa_ets_certValues);
  const asn::AsnObj cert_vals_asn(attr_blob.data(), attr_blob.size());
  for (const auto &cert_asn : cert_vals_asn.Childs()) {
    res.emplace_back(cert_asn.Unparse(), symbols);
  }
  return res;
}

} // namespace pdfcsp::csp::utils::message