
#include "cms.hpp"
#include "asn1.hpp"
#include "asn_tsp.hpp"
#include "oids.hpp"
#include "typedefs.hpp"
#include "utils.hpp"
#include <algorithm>
#include <stdexcept>
#include <sys/types.h>
#include <type_traits>

namespace pdfcsp::csp::asn {

AlgorithmIdentifier::AlgorithmIdentifier(const AsnObj &obj) {
  const std::string func_name = "[AlgorithmIdentifier] ";
  if (obj.GetAsnTag() != AsnTag::kSequence || obj.ChildsCount() < 1) {
    throw std::runtime_error(func_name + "invalid ASN structure");
  }
  algorithm = obj.at(0).GetStringData().value_or("");
  if (algorithm.empty()) {
    throw std::runtime_error("[SignedData] algorithm id is empty");
  }
  if (obj.ChildsCount() == 2) {
    parameters = obj.at(1).GetData();
  }
}

template <typename CONTENT_T>
SignedData<CONTENT_T>::SignedData(const AsnObj &asn_obj) {
  constexpr const char *const expl =
      "[SignedData] invalid SignedData ASN structure";
  // version
  if (asn_obj.at(0).GetAsnTag() != AsnTag::kInteger) {
    throw std::runtime_error(expl);
  }
  version = static_cast<uint>(asn_obj.at(0).GetData()[0]);
  // algorithm IDs
  const auto &algo_set = asn_obj.at(1);
  if (algo_set.IsFlat() || algo_set.ChildsCount() == 0) {
    throw std::runtime_error(expl);
  }
  for (const auto &algo : algo_set.GetChilds()) {
    digestAlgorithms.emplace_back(algo);
  }
  // EncapsulatedContentInfo encapContentInfo
  const AsnObj &content_info = asn_obj.at(2);
  encapContentInfo = EncapsulatedContentInfo<CONTENT_T>(content_info);
  // TODO(Oleg)
  //  certificates
  //  crtls
  //  signers info
}

template <typename CONTENT>
EncapsulatedContentInfo<CONTENT>::EncapsulatedContentInfo(
    const AsnObj &asn_obj) {
  constexpr const char *const expl =
      "Invalid EncapsulatedContentInfo ASN structure";
  const std::string func_name = "[EncapsulatedContentInfo] ";
  if (asn_obj.GetAsnTag() != AsnTag::kSequence || asn_obj.ChildsCount() < 2) {
    throw std::runtime_error(func_name + expl);
  }
  // eContentType
  std::string cont_oid = asn_obj.at(0).GetStringData().value_or("");
  if (cont_oid.empty()) {
    throw std::runtime_error(func_name + "empty algorithm OID");
  }
  eContentType = std::move(cont_oid);
  if (eContentType != kOID_tSTInfo && std::is_same_v<CONTENT, TSTInfo>) {
    throw std::runtime_error(func_name +
                             " Content OID does not match content type");
  }
  // eContent
  const AsnObj &content = asn_obj.at(1);
  eContent = CONTENT(content);
}

// explicit instantination
template struct SignedData<TSTInfo>;

AttributeTypeAndValue::AttributeTypeAndValue(const AsnObj &obj) {
  if (obj.ChildsCount() != 2 || obj.at(0).GetAsnTag() != AsnTag::kOid) {
    throw std::runtime_error("invalid AttributeTypeAndValue structure");
  }
  oid = obj.at(0).GetStringData().value_or("");
  if (oid.empty()) {
    throw std::runtime_error("[AttributeTypeAndValue] empty OID");
  }
  auto str_data = obj.at(1).GetData();
  val = std::string(str_data.cbegin(), str_data.cend());
}
} // namespace pdfcsp::csp::asn