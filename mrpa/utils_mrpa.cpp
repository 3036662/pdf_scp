#include "utils_mrpa.hpp"

#include <boost/algorithm/string/trim.hpp>
#include <boost/json/object.hpp>
#include <boost/json/serialize.hpp>
#include <boost/lexical_cast.hpp>
#include <iostream>
#include <memory>
#include <stdexcept>

#include "grantors.hpp"
#include "logger_utils.hpp"
#include "mrpa_defs.hpp"

// for internal usage
namespace {

using ChildrenMap =
  std::unordered_map<std::string, std::vector<boost::json::value>>;

std::optional<boost::json::value> NodeToJson(const xmlpp::Node* node,
                                             size_t recursion_level = 0);

/// @brief put childern to map (name -> vector<json::value>)
ChildrenMap CreateChildrenMap(const xmlpp::Element* element,
                              size_t recursion_level) {
  ChildrenMap children_map;
  if (element == nullptr) {
    return children_map;
  }
  const auto& children = element->get_children();
  std::for_each(children.begin(), children.end(),
                [&children_map, recursion_level](const xmlpp::Node* child) {
                  if (child == nullptr) {
                    return;
                  }
                  const std::string name = child->get_name();
                  if (name.empty()) {
                    return;
                  }
                  auto opt_val = NodeToJson(child, recursion_level + 1);
                  if (!opt_val.has_value() ||
                      (opt_val->is_string() && opt_val->as_string().empty())) {
                    return;
                  }
                  children_map[name].push_back(std::move(*opt_val));
                });
  return children_map;
}

// recursive convertor
std::optional<boost::json::value> NodeToJson(const xmlpp::Node* node,
                                             size_t recursion_level) {
  boost::json::object obj;
  try {
    if (node == nullptr) {
      return std::nullopt;
    }
    if (recursion_level > mrpa::kXmlToJsonMaxRecursionLevel) {
      auto logger = pdfcsp::logger::InitLog();
      if (logger) {
        logger->error("Maximal number of recurrsion was reached: {}",
                      recursion_level);
      }
      throw std::runtime_error("[NodeToJson] nesting leve is to big");
    }

    const auto* text_node = dynamic_cast<const xmlpp::TextNode*>(node);
    if (text_node != nullptr) {
      std::string val = text_node->get_content();
      boost::algorithm::trim(val);
      if (!val.empty()) {
        return boost::json::string(val);
      }
      return std::nullopt;
    }

    const auto* element = dynamic_cast<const xmlpp::Element*>(node);
    if (element != nullptr) {
      const auto& attrs = element->get_attributes();
      std::for_each(attrs.cbegin(), attrs.cend(),
                    [&obj](const xmlpp::Attribute* attribute) {
                      if (attribute == nullptr) {
                        return;
                      }
                      const std::string attr_name = "@" + attribute->get_name();
                      const std::string attr_value = attribute->get_value();
                      if (attr_name.size() > 1) {
                        obj[attr_name] = attr_value;
                      }
                    });
    }
    ChildrenMap children_map = CreateChildrenMap(element, recursion_level);
    using ChildVectorFromMap =
      std::pair<const std::string, std::vector<boost::json::value>>;
    std::for_each(children_map.begin(), children_map.end(),
                  [&obj](ChildVectorFromMap& child_vector) {
                    if (child_vector.second.empty()) {
                      return;
                    }
                    if (child_vector.second.size() == 1) {
                      obj[child_vector.first] = child_vector.second[0];
                      return;
                    }
                    boost::json::array json_array;
                    std::transform(
                      child_vector.second.begin(), child_vector.second.end(),
                      std::back_inserter(json_array),
                      [](boost::json::value& val) { return std::move(val); });
                    obj[child_vector.first] = std::move(json_array);
                  });
  } catch (const std::exception& ex) {
    if (recursion_level == 0) {
      auto logger = pdfcsp::logger::InitLog();
      if (logger) {
        logger->error(ex.what());
      }
      return std::nullopt;
    }
    throw;
  }
  return obj;
}
}  // namespace

namespace mrpa::utils {

/// @brief get the MRPA uid from XML
std::optional<std::string> GetMRPAGuid(xmlpp::Document* doc) noexcept {
  if (doc == nullptr) {
    return std::nullopt;
  }
  const auto* root = doc->get_root_node();
  if (root == nullptr) {
    return std::nullopt;
  }
  const auto* el_document = root->get_first_child(kNodeDocument);
  if (el_document == nullptr) {
    return std::nullopt;
  }
  const auto* el_attorney = el_document->get_first_child(kNodeAttorney);
  if (el_attorney == nullptr) {
    return std::nullopt;
  }
  const auto* el_attorney_info = dynamic_cast<const xmlpp::Element*>(
    el_attorney->get_first_child(kNodeAttorneyInfo));
  if (el_attorney_info == nullptr) {
    return std::nullopt;
  }
  const auto* attrib_attorney_id =
    el_attorney_info->get_attribute(kAttributeAttorneyID);
  if (attrib_attorney_id == nullptr) {
    return std::nullopt;
  }
  return attrib_attorney_id->get_value();
}

std::optional<boost::json::value> MrpaToJsonObject(xmlpp::Document* doc) {
  if (doc == nullptr) {
    return std::nullopt;
  }
  const auto* root = doc->get_root_node();
  if (root == nullptr) {
    return std::nullopt;
  }
  return NodeToJson(root, 0);
}

/**
 * @brief Convert xml document to JSON format
 */
std::optional<std::string> XmlToJson(xmlpp::Document* doc) {
  auto val = MrpaToJsonObject(doc);
  if (!val.has_value()) {
    return std::nullopt;
  }
  return boost::json::serialize(*val);
}

/**
 * @brief Extract json object holding the signer's certificate
 * @param chain_info json string with chains
 * @param serial signer's certificate serial number
 * @return std::optional<boost::json::object>
 */
std::optional<boost::json::object> SignersCertJson(
  std::string_view chain_info, std::string_view serial) noexcept {
  try {
    // explicit cast to boost string_view (for old boost)
    const boost::json::string_view b_chain_info(chain_info.data(),
                                                chain_info.length());
    const boost::json::string_view b_serial(serial.data(), serial.length());
    const auto chains = boost::json::parse(b_chain_info);
    if (!chains.is_array() || chains.as_array().empty()) {
      return std::nullopt;
    }
    const auto& chains_arr = chains.as_array();
    boost::json::object res;
    // for each chain
    for (const auto& chain : chains_arr) {
      if (!chain.is_object() || !chain.as_object().contains("certs")) {
        continue;
      }
      const auto& certs_val = chain.as_object().at("certs");
      if (!certs_val.is_array()) {
        continue;
      }
      const auto& certs_arr = certs_val.as_array();
      // for each certificate in chain
      for (const auto& cert : certs_arr) {
        if (!cert.is_object() || !cert.as_object().contains("serial")) {
          continue;
        }
        const auto& cert_obj = cert.as_object();
        if (!cert_obj.contains("serial") ||
            !cert_obj.at("serial").is_string()) {
          continue;
        }
        // found
        if (cert_obj.at("serial").as_string() == b_serial) {
          return cert_obj;
        }
      }
    }
  } catch (const std::exception& ex) {
    auto logger = pdfcsp::logger::InitLog();
    if (logger) {
      logger->error(
        "[signersCertJson] failed to find the signers certificate info");
      logger->error(ex.what());
    }
  }
  return std::nullopt;
}

AuthorityConfirmationDoc ParseAuthorityConfirmationDoc(
  const boost::json::object& authority_doc) {
  AuthorityConfirmationDoc doc;
  if (authority_doc.contains(kAuthorityDocName)) {
    doc.doc_name.emplace(
      authority_doc.at(kAuthorityDocName).as_string().c_str());
  }
  if (authority_doc.contains(kDocIssueDate)) {
    doc.date_issued.emplace(
      authority_doc.at(kDocIssueDate).as_string().c_str());
  }
  if (authority_doc.contains(kDocIssuer)) {
    doc.issuer.emplace(authority_doc.at(kDocIssuer).as_string().c_str());
  }
  if (authority_doc.contains(kAuthorityDocInfo)) {
    doc.doc_info.emplace(
      authority_doc.at(kAuthorityDocInfo).as_string().c_str());
  }
  return doc;
}

RegistrationAddress ParseRegistrationAddress(
  const boost::json::object& reg_addr) {
  RegistrationAddress addr;
  addr.region = reg_addr.at(kState).as_string().c_str();
  if (reg_addr.contains(kIDFias)) {
    addr.fias_id.emplace(reg_addr.at(kIDFias).as_string().c_str());
  }
  if (reg_addr.contains(kXMLAddressRF)) {
    addr.address.emplace(
      reg_addr.at(kXMLAddressRF).as_object().at("text").as_string().c_str());
  }
  if (reg_addr.contains(kXMLFiasAddressRF)) {
    addr.fias_address.emplace(reg_addr.at(kXMLFiasAddressRF)
                                .as_object()
                                .at("text")
                                .as_string()
                                .c_str());
  }
  return addr;
}

/**
 * @brief Update Grantor's company info
 *
 * @param [in] company_info "СвОргТип"
 * @param [out] result update Grantor object
 * @throws
 */
void UpdateGrantorCompanyInfo(const boost::json::object& company_info,
                              Grantor& result) {
  if (!company_info.contains(kRussianCompanyName) ||
      !company_info.at(kRussianCompanyName).is_string() ||
      !company_info.contains(kKPP) || !company_info.at(kKPP).is_string()) {
    throw std::runtime_error("[UpdateGrantorCompanyInfo] error");
  }
  result.company_name.emplace(
    company_info.at(kRussianCompanyName).as_string().c_str());
  result.kpp.emplace(company_info.at(kKPP).as_string().c_str());
  if (company_info.contains(kOGRN)) {
    result.ogrn = company_info.at(kOGRN).as_string().c_str();
  }
  if (company_info.contains(kDepartmentNumber)) {
    result.deparment_reg_number.emplace(
      company_info.at(kDepartmentNumber).as_string().c_str());
  }
  if (company_info.contains(kINNle)) {
    result.inn_le.emplace(company_info.at(kINNle).as_string().c_str());
  }
  if (company_info.contains(kIncorpPapers)) {
    result.incorp_doc.emplace(
      company_info.at(kIncorpPapers).as_string().c_str());
  }
  if (company_info.contains(kPhone)) {
    result.phone.emplace(company_info.at(kPhone).as_string().c_str());
  }
  if (company_info.contains(kEmail)) {
    result.email.emplace(company_info.at(kEmail).as_string().c_str());
  }
  if (company_info.contains(kNotarialStatus)) {
    result.notarial_status.emplace(
      company_info.at(kNotarialStatus).as_string().c_str());
  }
  if (company_info.contains(kXMLAuthorityDoc)) {
    const auto& authority_doc = company_info.at(kXMLAuthorityDoc).as_object();
    result.authority_confirmation_doc.emplace(
      ParseAuthorityConfirmationDoc(authority_doc));
  }
  if (company_info.contains(kXMLRegAddress)) {
    const auto& reg_addr = company_info.at(kXMLRegAddress).as_object();
    result.reg_address.emplace(ParseRegistrationAddress(reg_addr));
  }
}

/**
 * @brief Parse grantors for a russian company
 *
 * @param grantor_top
 * @return std::vector<Grantor>
 * @throws
 */
Grantor ParseCompanyGrantor(const boost::json::object& grantor) {
  constexpr const char* parse_err = "[ParseCompanyGrantors] parse failed";
  std::vector<Grantor> res;
  if (!grantor.contains(kManaginCompany) || !grantor.contains(kManaginPerson) ||
      !grantor.contains(kManaginIP) ||
      !grantor.at(kManaginCompany).is_string() ||
      !grantor.at(kManaginPerson).is_string() ||
      !grantor.at(kManaginIP).is_string() ||
      !grantor.contains(kXMLRussianCompanyInfo) ||
      !grantor.at(kXMLRussianCompanyInfo).is_object()) {
    throw std::runtime_error(parse_err);
  }
  Grantor result;
  result.type = GrantorType::kCompany;
  // company info
  const auto& company_info = grantor.at(kXMLRussianCompanyInfo).as_object();
  UpdateGrantorCompanyInfo(company_info, result);
  // parse the SoleExecutive
  const bool is_company = grantor.at(kManaginCompany).as_string() == "1";
  const bool is_ip = grantor.at(kManaginIP).as_string() == "1";
  const bool is_person = grantor.at(kManaginPerson).as_string() == "1";
  const SoleExecutive executive = makeExecutive(is_company, is_ip, is_person);
  if (executive == SoleExecutive::kUnknown ||
      !grantor.contains(kXMLEntityWithoutAttorney)) {
    throw std::runtime_error(parse_err);
  }
  const auto& entity_without_attorney =
    grantor.at(kXMLEntityWithoutAttorney).as_object();
  // on behalf of a legal entity several persons act without a power of
  // attorney.
  const bool many_persons =
    entity_without_attorney.at(kManyPersons).as_string() == "2";
  // Executive compane, parse the "СВЮЛ"
  if (executive == SoleExecutive::kCompany &&
      entity_without_attorney.contains(kXMLExetuiveCompany) &&
      entity_without_attorney.at(kXMLExetuiveCompany)
        .as_object()
        .contains(kXMLExetuiveCompanyInfo)) {
    auto executive_company = std::make_shared<Grantor>();
    executive_company->type = GrantorType::kCompany;
    const auto& ex_company_info =
      entity_without_attorney.at(kXMLExetuiveCompany)
        .as_object()
        .at(kXMLExetuiveCompanyInfo)
        .as_object();
    UpdateGrantorCompanyInfo(ex_company_info, *executive_company);
    result.executive_company = std::move(executive_company);
  }
  // switch (executive) {
  //    case SoleExecutive::kCompany:
  //       TODO(Oleg)
  //      break;
  //    case SoleExecutive::kIP:
  //      // TODO(Oleg)
  //      break;
  //    case SoleExecutive::kPerson:
  //      // TODO(Oleg)
  //      break;
  //    default:
  //      throw std::runtime_error(parse_err);
  //  }
  std::cout << "\n\n"
            << "Grantor result\n\n"
            << boost::json::serialize(result.ToJson()) << "\n";
  return result;
}

}  // namespace mrpa::utils
