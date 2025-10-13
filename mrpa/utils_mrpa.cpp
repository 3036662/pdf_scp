#include "utils_mrpa.hpp"

#include <algorithm>
#include <boost/algorithm/string/trim.hpp>
#include <boost/json.hpp>
#include <boost/json/object.hpp>
#include <boost/json/serialize.hpp>
#include <boost/lexical_cast.hpp>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "common_utils.hpp"
#include "grantors.hpp"
#include "logger_utils.hpp"
#include "mrpa_defs.hpp"

// ------------------------------------------
// region: for internal usage
namespace mrpa {
namespace {

using ChildrenMap =
  std::unordered_map<std::string, std::vector<boost::json::value>>;

std::optional<boost::json::value> NodeToJson(const xmlpp::Node* node,
                                             size_t recursion_level = 0);

/// @brief put children to map (name -> vector<json::value>)
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

/**
 * @brief parse one <УдЛичнФЛ> tag
 *
 * @param val
 * @return PersonalID
 */
PersonalID ParseOnePersonalID(const boost::json::object& val) {
  PersonalID res;
  res.doc_number = val.at(kPersonalIDdocNumber).as_string().c_str();
  res.date_issued = val.at(kPersonalIDdocDate).as_string().c_str();
  if (val.contains(kPersonalIDdocIssuer)) {
    res.issuer.emplace(val.at(kPersonalIDdocIssuer).as_string().c_str());
  }
  if (val.contains(kPersonalIDdocIssuerID)) {
    res.issuer_id.emplace(val.at(kPersonalIDdocIssuerID).as_string().c_str());
  }
  return res;
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
 * @brief parse one <СведФЛТип> tag
 * @param [in] val
 * @param [out] PhysicalPerson
 */
void ParsePersonalInfoDetails(const boost::json::object& person_details,
                              PhysicalPerson& res) {
  if (person_details.contains(kPersonSex)) {
    const std::string sex_str(
      person_details.at(kPersonSex).as_string().c_str());
    if (sex_str == "1") {
      res.sex.emplace(Sex::kMale);
    } else if (sex_str == "2") {
      res.sex.emplace(Sex::kFemale);
    }
  }
  if (person_details.contains(kPersonCitizenship)) {
    const std::string citizen_str(
      person_details.at(kPersonCitizenship).as_string().c_str());
    if (citizen_str == "1") {
      res.citizenship.emplace(Citizenship::kRussia);
    } else if (citizen_str == "2") {
      res.citizenship.emplace(Citizenship::kForeign);
    } else if (citizen_str == "3") {
      res.citizenship.emplace(Citizenship::kNoCitizenship);
    }
  }
  if (person_details.contains(kPersonEgrn)) {
    res.egrn.emplace(person_details.at(kPersonEgrn).as_string().c_str());
  }
  if (person_details.contains(kPersonBithDate)) {
    res.birth_date.emplace(
      person_details.at(kPersonBithDate).as_string().c_str());
  }
  if (person_details.contains(kPersonBithPlace)) {
    res.birth_place.emplace(
      person_details.at(kPersonBithPlace).as_string().c_str());
  }
  if (person_details.contains(kPersonCitizenshipCountry)) {
    res.citizenship_country.emplace(
      person_details.at(kPersonCitizenshipCountry).as_string().c_str());
  }
  if (person_details.contains(kPhone)) {
    res.phone.emplace(person_details.at(kPhone).as_string().c_str());
  }
  if (person_details.contains(kEmail)) {
    res.email.emplace(person_details.at(kEmail).as_string().c_str());
  }
  // <ФИО>
  const auto& person_name_full =
    person_details.at(kXMLPersonNameStruct).as_object();
  res.name = person_name_full.at(kPersonName).as_string().c_str();
  res.last_name = person_name_full.at(kPersonLastName).as_string().c_str();
  if (person_name_full.contains(kPersonPatronymic)) {
    res.patronymic.emplace(
      person_name_full.at(kPersonPatronymic).as_string().c_str());
  }
  // <АдрМЖ>
  if (person_details.contains(kXMLPersonalAddress)) {
    res.address.emplace(ParseRegistrationAddress(
      person_details.at(kXMLPersonalAddress).as_object()));
  }
  // <УдЛичнФЛ>
  if (person_details.contains(kXMLPersonalIDinfo)) {
    res.personal_id_doc.emplace(
      ParseOnePersonalID(person_details.at(kXMLPersonalIDinfo).as_object()));
  }
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

/**
 * @brief Parse one <СвФЛТип> tag
 * @param obj
 * @return PhysicalPerson
 */
PhysicalPerson ParseOnePerson(const boost::json::object& obj) {
  PhysicalPerson res;
  if (obj.contains(kNotarialMemberStatus)) {
    res.member_status.emplace(
      obj.at(kNotarialMemberStatus).as_string().c_str());
  }
  if (obj.contains(kInnPerson)) {
    res.inn_person.emplace(obj.at(kInnPerson).as_string().c_str());
  }
  if (obj.contains(kSnilsPerson)) {
    res.snils_person.emplace(obj.at(kSnilsPerson).as_string().c_str());
  }
  if (obj.contains(kPersonalDuty)) {
    res.duty.emplace(obj.at(kPersonalDuty).as_string().c_str());
  }
  // <ДокПдтв> AuthorityConfirmationDoc
  if (obj.contains(kXMLAuthorityDoc)) {
    res.authority_confirmation_doc.emplace(
      ParseAuthorityConfirmationDoc(obj.at(kXMLAuthorityDoc).as_object()));
  }
  // <СведФЛТип>
  if (obj.contains(kXMLPersonInfoDetails)) {
    const auto& person_details = obj.at(kXMLPersonInfoDetails).as_object();
    ParsePersonalInfoDetails(person_details, res);
  }
  return res;
}

/**
 * @brief Parse one <СвИп> tag
 *
 * @param val
 * @return Grantor
 */
Grantor ParseOneIp(const boost::json::object& val) {
  Grantor executive_ip;
  executive_ip.type = GrantorType::kIP;
  executive_ip.orgn_ip.emplace(val.at(kOrgnIP).as_string().c_str());
  executive_ip.inn_ip.emplace(val.at(kInnPerson).as_string().c_str());
  executive_ip.snils_ip.emplace(val.at(kSnilsPerson).as_string().c_str());
  if (val.contains(kNotarialStatus)) {
    executive_ip.notarial_status.emplace(
      val.at(kNotarialStatus).as_string().c_str());
  }
  if (val.contains(kIPTitle)) {
    executive_ip.ip_name.emplace(val.at(kIPTitle).as_string().c_str());
  }
  executive_ip.persons.emplace_back(
    ParseOnePerson(val.at(kXMLPersonInfoDetails).as_object()));
  if (val.contains(kXMLAuthorityDoc)) {
    executive_ip.authority_confirmation_doc.emplace(
      ParseAuthorityConfirmationDoc(val.at(kXMLAuthorityDoc).as_object()));
  }
  executive_ip.all_persons = executive_ip.persons;
  return executive_ip;
}

/**
 * @brief Parse all <СвИп> in the given object
 *
 * @param obj
 * @param result
 */
std::vector<Grantor> ParseIPs(const boost::json::object& obj) {
  if (!obj.contains(kXMLIpInfo)) {
    return {};
  }
  std::vector<Grantor> result;
  if (obj.at(kXMLIpInfo).is_object()) {
    result.emplace_back(ParseOneIp(obj.at(kXMLIpInfo).as_object()));
  }
  return result;
  // only one ip is expected here
  // if (obj.at(kXMLIpInfo).is_array()) {
  //   const auto& ip_arr = obj.at(kXMLIpInfo).as_array();
  //   std::transform(ip_arr.cbegin(), ip_arr.cend(),
  //   std::back_inserter(result),
  //                  [](const boost::json::value& ip_val) {
  //                    return ParseOneIp(ip_val.as_object());
  //                  });
  // }
  // return result;
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
    result.department_reg_number.emplace(
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
 * @brief Parse all <СвФЛ> in the given object
 * @param obj
 * @return std::vector<PhysicalPerson>
 */
std::vector<PhysicalPerson> ParsePhysicalPersons(
  const boost::json::object& obj) {
  if (!obj.contains(kXMLPersonInfo)) {
    return {};
  }
  std::vector<PhysicalPerson> result;

  // only one person for now is expected
  // if (obj.at(kXMLPersonInfo).is_array()) {
  //   const auto& persons_arr = obj.at(kXMLPersonInfo).as_array();
  //   std::transform(persons_arr.cbegin(), persons_arr.cend(),
  //                  std::back_inserter(result),
  //                  [](const boost::json::value& val) {
  //                    return ParseOnePerson(val.as_object());
  //                  });
  //   return result;
  // }

  if (obj.at(kXMLPersonInfo).is_object()) {
    result.emplace_back(ParseOnePerson(obj.at(kXMLPersonInfo).as_object()));
  }
  return result;
}

/**
 * @brief Parse one <СВЮЛ>
 *
 * @param val
 * @return Grantor
 */
Grantor ParseOneExecutiveCompany(const boost::json::object& val) {
  Grantor executive_company;
  executive_company.type = GrantorType::kCompany;
  if (!val.contains(kXMLExetuiveCompanyInfo) || !val.contains(kXMLPersonInfo)) {
    throw std::runtime_error(
      "[ParseOneExecutiveCompany] invalid exectutive company data");
  }
  // <СвЮЛЕИО> tag
  const auto& ex_company_info = val.at(kXMLExetuiveCompanyInfo).as_object();
  UpdateGrantorCompanyInfo(ex_company_info, executive_company);
  // parse grantor persons of the executive company
  executive_company.persons = ParsePhysicalPersons(val);
  executive_company.all_persons = executive_company.persons;
  return executive_company;
}

/**
 * @brief Parse all <СВЮЛ> of given object;
 *
 * @param val
 * @return std::vector<Grantor>
 */
std::vector<Grantor> ParseExecutiveCompanies(const boost::json::object& val) {
  if (!val.contains(kXMLExetuiveCompany)) {
    return {};
  }
  std::vector<Grantor> result;
  if (val.at(kXMLExetuiveCompany).is_object()) {
    result.emplace_back(
      ParseOneExecutiveCompany(val.at(kXMLExetuiveCompany).as_object()));
  }
  return result;
  // only one executive company is expeced here
  // if (val.at(kXMLExetuiveCompany).is_array()) {
  //   const auto& ex_company_arr = val.at(kXMLExetuiveCompany).as_array();
  //   std::transform(ex_company_arr.cbegin(), ex_company_arr.cend(),
  //                  std::back_inserter(result),
  //                  [](const boost::json::value& one_ex_val) {
  //                    return ParseOneExecutiveCompany(one_ex_val.as_object());
  //                  });
  // }
  // return result;
}

/**
 * @brief Parse one <ЛицоБезДов>
 *
 * @param executive
 * @param obj
 * @param result
 */
void ParseOneEntityWithoutAttorney(SoleExecutive executive,
                                   const boost::json::object& obj,
                                   Grantor& result) {
  constexpr const char* expl_one_person =
    "[ParseOneEntityWithoutAttorney] only one person or company can act on "
    "behalf of this legal entity";
  const bool many_persons = obj.at(kManyPersons).as_string() == "2";

  // if there is executive company, parse the "СВЮЛ"
  if (executive == SoleExecutive::kCompany &&
      obj.contains(kXMLExetuiveCompany)) {
    auto arr = ParseExecutiveCompanies(obj);
    if (arr.size() > 1 && !many_persons) {
      throw std::runtime_error(expl_one_person);
    }
    std::for_each(arr.begin(), arr.end(), [&result](Grantor& val) {
      result.executive_companies.emplace_back(std::move(val));
    });
  }
  // Executive is a person
  if (executive == SoleExecutive::kPerson && obj.contains(kXMLPersonInfo)) {
    auto arr = ParsePhysicalPersons(obj);
    if (arr.size() > 1 && !many_persons) {
      throw std::runtime_error(expl_one_person);
    }
    if (!arr.empty()) {
      result.persons.push_back(std::move(arr[0]));
    }
  }
  if (executive == SoleExecutive::kIP && obj.contains(kXMLIpInfo)) {
    auto arr = ParseIPs(obj);
    if (arr.size() > 1 && !many_persons) {
      throw std::runtime_error(expl_one_person);
    }
    std::for_each(arr.begin(), arr.end(), [&result](Grantor& val) {
      result.executive_ips.emplace_back(std::move(val));
    });
  }
}

/**
 * @brief Parse all <ЛицоБезДов> of given object
 *
 * @param [in] executive
 * @param [in] obj
 * @param [out] result
 */
void ParseEntitiesWithoutAttorney(SoleExecutive executive,
                                  const boost::json::object& obj,
                                  Grantor& result) {
  if (!obj.contains(kXMLEntityWithoutAttorney)) {
    return;
  }
  if (obj.at(kXMLEntityWithoutAttorney).is_object()) {
    const auto& entity_without_attorney =
      obj.at(kXMLEntityWithoutAttorney).as_object();
    ParseOneEntityWithoutAttorney(executive, entity_without_attorney, result);
  }
  if (obj.at(kXMLEntityWithoutAttorney).is_array()) {
    const auto& ent_arr = obj.at(kXMLEntityWithoutAttorney).as_array();
    std::for_each(ent_arr.cbegin(), ent_arr.cend(),
                  [executive, &result](const boost::json::value& ent) {
                    ParseOneEntityWithoutAttorney(executive, ent.as_object(),
                                                  result);
                  });
  }
}

std::vector<PhysicalPerson> GatherAllPersons(const Grantor& grantor) {
  std::vector<PhysicalPerson> res;
  std::for_each(
    grantor.executive_companies.cbegin(), grantor.executive_companies.cend(),
    [&res](const Grantor& ex_company) {
      std::copy(ex_company.all_persons.cbegin(), ex_company.all_persons.cend(),
                std::back_inserter(res));
    });
  std::for_each(grantor.executive_ips.cbegin(), grantor.executive_ips.cend(),
                [&res](const Grantor& ex_ip) {
                  std::copy(ex_ip.all_persons.cbegin(),
                            ex_ip.all_persons.cend(), std::back_inserter(res));
                });
  std::copy(grantor.persons.cbegin(), grantor.persons.cend(),
            std::back_inserter(res));
  return res;
}

/**
 * @brief Parse <СвУпПред>
 *
 * @param obj
 * @return PhysicalPerson
 * @throws
 */
std::vector<PhysicalPerson> ParseRepresentativePersons(
  const boost::json::object& obj) {
  if (!obj.contains(kRepresentativeType) ||
      !obj.contains(kXMLRepresentativeNested)) {
    throw std::runtime_error("[ParseOneRepresentativePerson] invalid data");
  }
  if (obj.at(kRepresentativeType).as_string() != "3") {
    // throw std::runtime_error(
    //   "[ParseOneRepresentativePerson] the representative is not a physical "
    //   "person");
    // TODO(Oleg) handle companites and ips
    return {};
  }
  if (!obj.contains(kXMLRepresentativeNested)) {
    return {};
  }
  const auto& repr_nested = obj.at(kXMLRepresentativeNested).as_object();
  if (!repr_nested.contains(kXMLRepresentativePersonInfo)) {
    return {};
  }
  const auto& repr = repr_nested.at(kXMLRepresentativePersonInfo);
  std::vector<PhysicalPerson> result;
  if (repr.is_object()) {
    result.emplace_back(ParseOnePerson(repr.as_object()));
  }
  // Only one person is expexted here
  // if (repr.is_array()) {
  //   const auto& arr = repr.as_array();
  //   std::transform(arr.cbegin(), arr.cend(), std::back_inserter(result),
  //                  [](const boost::json::value& val) {
  //                    return ParseOnePerson(val.as_object());
  //                  });
  // }
  return result;
}

}  // namespace
}  // namespace mrpa
// region_end: for internal usage
// ------------------------------------------

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
 * @brief Get the Attorney object
 *
 * @param val json::value of MRPA
 * @return const boost::json::object& Attorney
 * @throws
 */
const boost::json::object& GetAttorneyObj(
  const std::optional<boost::json::value>& json_val) {
  if (!json_val || !json_val->is_object()) {
    throw std::runtime_error(
      "[Mrpa::GetAttorneyObj] JSON representation is empty");
  }
  const auto& root = json_val->as_object();
  if (!root.contains(kXMLDoc) || !root.at(kXMLDoc).is_object()) {
    throw std::runtime_error("[Mrpa::GetAttorneyObj] Document node not found");
  }
  const auto& doc = root.at(kXMLDoc).as_object();
  if (!doc.contains(kXMLAttorney) || !doc.at(kXMLAttorney).is_object()) {
    throw std::runtime_error("[Mrpa::GetAttorneyObj] Attorney node not found");
  }
  const auto& attorney = doc.at(kXMLAttorney).as_object();
  if (!attorney.contains(kXMLGrantorInfoTop) ||
      !attorney.at(kXMLGrantorInfoTop).is_object()) {
    throw std::runtime_error(
      "[Mrpa::GetAttorneyObj] Grantor top node not found");
  }
  return attorney;
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

/**
 * @brief Parse grantors for a russian company
 *
 * @param grantor_top
 * @return std::vector<Grantor>
 * @details <РосОргДовер> xml tag
 * @throws
 */
Grantor ParseCompanyGrantor(const boost::json::object& grantor) {
  constexpr const char* parse_err = "[ParseCompanyGrantors] parse failed";
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
  // company info <СвРосОрг> tag
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
  // Parse all <ЛицоБезДов>
  ParseEntitiesWithoutAttorney(executive, grantor, result);
  // All Persons from all nesting objects
  result.all_persons = GatherAllPersons(result);
  return result;
}

/**
 * @brief  Parse grantor for a foreign company
 * @param grantor
 * @return Grantor
 * @details xml <ИнОргДовер> tag
 * @throw
 */
Grantor ParseForeignCompanyGrantor(const boost::json::object& grantor) {
  constexpr const char* expl_invalid =
    "[ParseForeignCompanyGrantor] invalid <ИнОргДовер>";
  if (!grantor.contains(kXMLForeignCompanyInfo)) {
    throw std::runtime_error(expl_invalid);
  }
  Grantor result;
  result.type = GrantorType::kForeignCompany;
  const auto& for_comp_info = grantor.at(kXMLForeignCompanyInfo).as_object();
  if (!for_comp_info.contains(kForeignCompanyTitle)) {
    throw std::runtime_error(expl_invalid);
  }
  result.company_name.emplace(
    for_comp_info.at(kForeignCompanyTitle).as_string().c_str());
  if (for_comp_info.contains(kNotarialStatus)) {
    result.notarial_status.emplace(
      for_comp_info.at(kNotarialStatus).as_string().c_str());
  }
  if (for_comp_info.contains(kINNle)) {
    result.inn_le.emplace(for_comp_info.at(kINNle).as_string().c_str());
  }
  if (for_comp_info.contains(kKPP)) {
    result.kpp.emplace(for_comp_info.at(kKPP).as_string().c_str());
  }
  if (for_comp_info.contains(kPhone)) {
    result.phone.emplace(for_comp_info.at(kPhone).as_string().c_str());
  }
  if (for_comp_info.contains(kEmail)) {
    result.email.emplace(for_comp_info.at(kEmail).as_string().c_str());
  }
  if (for_comp_info.contains(kXMLForeignCompanyInfoAddressRu)) {
    result.reg_address.emplace(ParseRegistrationAddress(
      for_comp_info.at(kXMLForeignCompanyInfoAddressRu).as_object()));
  }
  // TODO(Oleg) <НЗА>,<СтрРег>,<НаимРегОрг>,<РегНомер>,<КодНПРег>,<АдрСтрРег>
  result.persons.emplace_back(
    ParseOnePerson(grantor.at(kXMLForeignCompanyBoss).as_object()));
  result.all_persons = GatherAllPersons(result);
  return result;
}

/**
 * @brief  Parse grantor for a IP
 * @param grantor
 * @return Grantor
 * @details xml <ИПДовер> tag
 * @throws
 */
Grantor ParseIPGrantor(const boost::json::object& grantor) {
  return ParseOneIp(grantor);
}

/**
 * @brief  Parse grantor for a IP
 * @param grantor
 * @return Grantor
 * @details xml <ФЛДовер> tag
 * @throws
 */
Grantor ParsePersonGrantor(const boost::json::object& grantor) {
  Grantor result;
  result.type = GrantorType::kPerson;
  result.persons.push_back({});
  PhysicalPerson& person = result.persons[0];
  // result.snils_ip = grantor.at(kSnilsPerson).as_string().c_str();

  if (grantor.contains(kInnPerson)) {
    person.inn_person.emplace(grantor.at(kInnPerson).as_string().c_str());
  }
  if (grantor.contains(kSnilsPerson)) {
    result.snils_person.emplace(grantor.at(kSnilsPerson).as_string().c_str());
  }
  if (grantor.contains(kNotarialMemberStatus)) {
    result.notarial_status =
      grantor.at(kNotarialMemberStatus).as_string().c_str();
  }
  if (grantor.contains(kLegalCapacitySign)) {
    person.has_legal_capacity.emplace(
      grantor.at(kLegalCapacitySign).as_string().c_str());
  }
  if (grantor.contains(kHasRepresentativeFlag)) {
    person.has_representative.emplace(
      grantor.at(kHasRepresentativeFlag).as_string().c_str());
  }
  if (grantor.contains(kPersonIncapacityDoc)) {
    person.incapacity_doc.emplace(
      grantor.at(kPersonIncapacityDoc).as_string().c_str());
  }

  if (grantor.contains(kXMLPersonInfoDetails) &&
      grantor.at(kXMLPersonInfoDetails).is_object()) {
    ParsePersonalInfoDetails(grantor.at(kXMLPersonInfoDetails).as_object(),
                             person);
  }
  const bool no_legal_capacity = person.has_legal_capacity.has_value() &&
                                 person.has_legal_capacity.value() == "0";
  if (person.has_representative && person.has_representative.value() == "1" &&
      grantor.contains(kXMLIncapPersonRepr)) {
    std::cout << "HAS reperesntative\n";
    if (no_legal_capacity) {
      result.persons.clear();
    };
    result.persons.emplace_back(ParseOnePerson(grantor.at(kXMLIncapPersonRepr)
                                                 .as_object()
                                                 .at(kXMLPersonInfo)
                                                 .as_object()));
  }

  result.all_persons = result.persons;
  return result;
}

/**
 * @brief Parse all  <СвУпПред> of given object
 * @param val
 * @return std::vector<PhysicalPerson>
 * @throws
 */
std::vector<PhysicalPerson> ParseAllRepresentativePersons(
  const boost::json::object& val) {
  if (!val.contains(kXMLRepresentativeInfo)) {
    return {};
  }
  std::vector<PhysicalPerson> res;
  const auto parse_one = [&res](const boost::json::object& repr_obj) {
    auto arr_persons = ParseRepresentativePersons(repr_obj);
    std::for_each(
      arr_persons.begin(), arr_persons.end(),
      [&res](PhysicalPerson& person) { res.emplace_back(std::move(person)); });
  };
  if (val.at(kXMLRepresentativeInfo).is_object()) {
    // <СвУпПредТип>
    const auto& repr_obj = val.at(kXMLRepresentativeInfo).as_object();
    parse_one(repr_obj);
  }
  // Only one is expected for now
  // if (val.at(kXMLRepresentativeInfo).is_array()) {
  //   const auto& arr = val.at(kXMLRepresentativeInfo).as_array();
  //   std::for_each(arr.cbegin(), arr.cend(),
  //                 [&parse_one](const boost::json::value& val) {
  //                   parse_one(val.as_object());
  //                 });
  // }
  return res;
}

time_t ParseXMLDate(const std::string& val) {
  std::tm time = {};
  std::istringstream str(val);
  str >> std::get_time(&time, "%Y-%m-%d");
  if (str.fail()) {
    throw std::runtime_error("Failed to parse date and time");
  };
  const std::time_t time_stamp = mktime(&time);
  if (time_stamp == std::numeric_limits<int64_t>::max()) {
    throw std::runtime_error("Failed to parse date and time");
  }
  return time_stamp;
}

/**
 * @brief Extract signer's name, surname and a certificate serial
 * @param check_res Signature check result
 * @return SignaturePersonInfo simple struct with three opional fields
 */
SignaturePersonInfo ExtractSignerInfo(
  const PtrSigCheckRes& check_res,
  const std::shared_ptr<spdlog::logger>& logger) {
  if (!check_res) {
    return {};
  }
  SignaturePersonInfo res;
  // extract the signer's certificate info
  const std::string serial =
    ::pdfcsp::utils::VecBytesStringRepresentation(pdfcsp::csp::BytesVector(
      check_res->cert_serial,
      check_res->cert_serial + check_res->cert_serial_size));
  // certificate JSON
  const auto signers_cert_info =
    utils::SignersCertJson(check_res->cert_chain_json, serial);
  if (!signers_cert_info) {
    if (logger) {
      logger->error(
        "[MRPA::setSignature] Signers certificate info was not found");
    }
    return res;
  }
  // try to find this signer in the representatives list
  // extract the INN if exists
  if (signers_cert_info->contains("subject_dname") &&
      signers_cert_info->at("subject_dname").as_object().contains("inn")) {
    res.signer_inn = signers_cert_info->at("subject_dname")
                       .as_object()
                       .at("inn")
                       .as_string()
                       .c_str();
  }
  // extract the lastname and name
  if (signers_cert_info->contains("subject_dname") &&
      signers_cert_info->at("subject_dname").as_object().contains("surname") &&
      signers_cert_info->at("subject_dname")
        .as_object()
        .contains("givenName")) {
    res.signer_surname = signers_cert_info->at("subject_dname")
                           .as_object()
                           .at("surname")
                           .as_string()
                           .c_str();
    res.signer_given_name = signers_cert_info->at("subject_dname")
                              .as_object()
                              .at("givenName")
                              .as_string()
                              .c_str();
  }
  return res;
}

boost::json::object ToJson(const SignaturePersonInfo& pers_info) {
  boost::json::object res;
  if (pers_info.signer_given_name) {
    res["given_name"] = pers_info.signer_given_name.value();
  }
  if (pers_info.signer_surname) {
    res["surname"] = pers_info.signer_surname.value();
  }
  if (pers_info.signer_inn) {
    res["inn"] = pers_info.signer_inn.value();
  }
  return res;
}

}  // namespace mrpa::utils
