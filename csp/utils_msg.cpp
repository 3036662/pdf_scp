#include "utils_msg.hpp"
#include "asn1.hpp"
#include "resolve_symbols.hpp"
#include <algorithm>

namespace pdfcsp::csp {

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
  for (auto i = 0UL; i < sig_obj.ChildsCount(); ++i) {
    const asn::AsnObj &tmp = sig_obj.GetChilds()[i];
    if (!tmp.IsFlat() &&
        tmp.get_asn_header().asn_tag == asn::AsnTag::kUnknown &&
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
uint64_t FindSignerInfosIndex(const asn::AsnObj &signed_data) {
  // signer infos - second set in signed_data
  u_int64_t index_signers_infos = 0;
  bool signer_infos_found = false;
  u_int64_t set_num = 0;
  for (u_int64_t i = 0; i < signed_data.ChildsCount(); ++i) {
    if (signed_data.GetChilds()[i].get_asn_header().asn_tag ==
        asn::AsnTag::kSet) {
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
  for (const auto &seq : authority_info.GetChilds()) {
    if (seq.IsFlat() || seq.ChildsCount() != 2 ||
        seq.GetChilds()[0].get_asn_header().asn_tag != asn::AsnTag::kOid) {
      throw std::runtime_error(
          "invalid data in the authorityInfoAccess extension");
    }
    if (seq.GetChilds()[0].GetStringData() == szOID_PKIX_OCSP &&
        seq.GetChilds()[1].get_asn_header().tag_type ==
            asn::AsnTagType::kContentSpecific) {
      ocsp_links.emplace_back(seq.GetChilds()[1].GetData().cbegin(),
                              seq.GetChilds()[1].GetData().cend());
    }
  }
  return ocsp_links;
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
  if (asn.IsFlat() || asn.ChildsCount() == 0) {
    throw std::runtime_error(
        "Extract signed attributes failed.ASN1 obj is flat");
  }
  // look for content node
  const uint64_t index_content = FindSigContentIndex(asn);
  const asn::AsnObj &content = asn.GetChilds()[index_content];
  if (content.IsFlat() || content.ChildsCount() == 0) {
    throw std::runtime_error("Content node is empty");
  }
  // signed data node
  const asn::AsnObj &signed_data = content.GetChilds()[0];
  if (signed_data.get_asn_header().asn_tag != asn::AsnTag::kSequence ||
      signed_data.ChildsCount() == 0) {
    throw std::runtime_error("Signed data element is empty");
  }
  // signer infos - second set
  const uint64_t index_signers_infos = FindSignerInfosIndex(signed_data);
  const asn::AsnObj &signer_infos =
      signed_data.GetChilds()[index_signers_infos];
  if (signer_infos.IsFlat() || signer_infos.ChildsCount() == 0) {
    throw std::runtime_error("signerInfos node is empty");
  }
  if (signer_infos.ChildsCount() < signer_index) {
    throw std::runtime_error("no signer with such index in signers_info");
  }
  const asn::AsnObj &signer_info = signer_infos.GetChilds()[signer_index];
  if (signer_info.IsFlat() || signer_info.ChildsCount() == 0) {
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
  for (const auto &attr : attrs.GetChilds()) {
    if (attr.ChildsCount() == 0) {
      continue;
    }
    const asn::AsnObj &oid_obj = attr.at(0);
    if (oid_obj.GetStringData().value_or("") == oid) {
      auto unparsed_attribute = attr.Unparse();
      std::copy(unparsed_attribute.cbegin() +
                    attr.get_asn_header().sizeof_header,
                unparsed_attribute.cend(), std::back_inserter(dest));
    }
  }
}

} // namespace pdfcsp::csp