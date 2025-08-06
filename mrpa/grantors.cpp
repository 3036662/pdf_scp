#include "grantors.hpp"

#include <algorithm>
#include <boost/json/array.hpp>
#include <boost/json/object.hpp>
#include <iterator>

namespace mrpa {

boost::json::object AuthorityConfirmationDoc::ToJson() const {
  boost::json::object res;
  if (doc_name) {
    res["doc_name"] = *doc_name;
  }
  if (date_issued) {
    res["date_issued"] = *date_issued;
  }
  if (issuer) {
    res["issuer"] = *issuer;
  }
  if (doc_info) {
    res["doc_info"] = *doc_info;
  }
  return res;
}

// boost::json::object Address::ToJson() const {
//   boost::json::object res;
//   res["region"] = region;
//   if (address) {
//     res["address"] = *address;
//   }
//   if (fias) {
//     res["fias"] = *address;
//   }
//   if (id_fias) {
//     res["id_fias"] = *id_fias;
//   }
//   return res;
// }

boost::json::object PersonalID::ToJson() const {
  boost::json::object res;
  res["doc_number"] = doc_number;
  res["date_issued"] = date_issued;
  if (issuer) {
    res["issuer"] = *issuer;
  }
  if (issuer_id) {
    res["issuer_id"] = *issuer_id;
  }
  return res;
}

boost::json::object PhysicalPerson::ToJson() const {
  boost::json::object res;
  res["last_name"] = last_name;
  res["name"] = name;
  if (patronymic) {
    res["patronymic"] = *patronymic;
  }
  if (sex) {
    res["sex"] = sex.value() == Sex::kMale ? "Male" : "Female";
  }
  if (citizenship) {
    switch (*citizenship) {
      case mrpa::Citizenship::kRussia:
        res["citizenship"] = "Russia";
        break;
      case mrpa::Citizenship::kForeign:
        res["citizenship"] = "Foreign";
        break;
      case mrpa::Citizenship::kNoCitizenship:
        res["citizenship"] = "NoCitizenShip";
        break;
    }
  }
  if (citizenship_country) {
    res["citizenship_country"] = *citizenship_country;
  }
  if (egrn) {
    res["egrn"] = *egrn;
  }
  if (birth_date) {
    res["birth_date"] = *birth_date;
  }
  if (birth_place) {
    res["birth_place"] = *birth_place;
  }
  if (phone) {
    res["phone"] = *phone;
  }
  if (email) {
    res["email"] = *email;
  }
  if (address) {
    res["address"] = address->ToJson();
  }
  if (personal_id_doc) {
    res["personal_id_doc"] = personal_id_doc->ToJson();
  }
  if (member_status) {
    res["member_status"] = *member_status;
  }
  if (inn_person) {
    res["inn_person"] = *inn_person;
  }
  if (snils_person) {
    res["snils_person"] = *snils_person;
  }
  if (duty) {
    res["duty"] = *duty;
  }
  if (has_legal_capacity) {
    res["has_legal_capacity"] = *has_legal_capacity;
  }
  if (has_representative) {
    res["has_representative"] = *has_representative;
  }
  if (incapacity_doc) {
    res["incapacity_doc"] = *incapacity_doc;
  }
  if (authority_confirmation_doc) {
    res["authority_confirmation_doc"] = authority_confirmation_doc->ToJson();
  }
  return res;
}

boost::json::object RegistrationAddress::ToJson() const {
  boost::json::object res;
  res["region"] = region;
  if (fias_id) {
    res["fias_id"] = *fias_id;
  }
  if (address) {
    res["address"] = *address;
  }
  if (fias_address) {
    res["fias_address"] = *fias_address;
  }
  return res;
}

boost::json::object Grantor::ToJson() const {
  boost::json::object res;
  res["type"] = ToString(type);
  if (company_name) {
    res["company_name"] = *company_name;
  }
  if (ip_name) {
    res["ip_name"] = *ip_name;
  }
  if (inn_le) {
    res["inn_le"] = *inn_le;
  }
  if (inn_ip) {
    res["inn_ip"] = *inn_ip;
  }
  if (snils_ip) {
    res["snils_ip"] = *snils_ip;
  }
  if (snils_person) {
    res["snils_person"] = *snils_person;
  }
  if (kpp) {
    res["kpp"] = *kpp;
  }
  if (ogrn) {
    res["ogrn"] = *ogrn;
  }
  if (orgn_ip) {
    res["ogrn_ip"] = *orgn_ip;
  }
  if (deparment_reg_number) {
    res["deparment_reg_number"] = *deparment_reg_number;
  }
  if (incorp_doc) {
    res["incorp_doc"] = *incorp_doc;
  }
  if (phone) {
    res["phone"] = *phone;
  }
  if (email) {
    res["email"] = *email;
  }
  if (notarial_status) {
    res["notarial_status"] = *notarial_status;
  }
  if (authority_confirmation_doc) {
    res["authority_confirmation_doc"] = authority_confirmation_doc->ToJson();
  }
  if (reg_address) {
    res["reg_address"] = reg_address->ToJson();
  }
  if (!executive_companies.empty()) {
    boost::json::array ex_comps;
    std::transform(executive_companies.cbegin(), executive_companies.cend(),
                   std::back_inserter(ex_comps),
                   [](const Grantor& ex_cmp) { return ex_cmp.ToJson(); });
    res["executive_companies"] = std::move(ex_comps);
  }
  if (!executive_ips.empty()) {
    boost::json::array ex_ips;
    std::transform(executive_ips.cbegin(), executive_ips.cend(),
                   std::back_inserter(ex_ips),
                   [](const Grantor& ex_ip) { return ex_ip.ToJson(); });
    res["executive_ips"] = std::move(ex_ips);
  }
  if (!persons.empty()) {
    boost::json::array pers;
    std::transform(persons.cbegin(), persons.cend(), std::back_inserter(pers),
                   [](const PhysicalPerson& val) { return val.ToJson(); });
    res["persons"] = std::move(pers);
  }
  if (!all_persons.empty()) {
    boost::json::array pers;
    std::transform(all_persons.cbegin(), all_persons.cend(),
                   std::back_inserter(pers),
                   [](const PhysicalPerson& val) { return val.ToJson(); });
    res["all_persons"] = std::move(pers);
  }

  return res;
}

std::string ToString(GrantorType type) {
  switch (type) {
    case mrpa::GrantorType::kCompany:
      return "Company";
    case mrpa::GrantorType::kForeignCompany:
      return "ForeignCompany";
    case mrpa::GrantorType::kIP:
      return "IP";
    case mrpa::GrantorType::kUnknown:
      return "Unknown";
    case mrpa::GrantorType::kPerson:
      return "Person";
  }
}

/// @brief compare with a SignaturePersonInfo
bool PhysicalPerson::operator==(
  const SignaturePersonInfo& pers_info) const noexcept {
  std::string givenname = name;
  if (patronymic) {
    givenname.reserve(givenname.size() + patronymic.value().size() + 2);
    givenname += " ";
    givenname += patronymic.value();
  }
  // match by inn or (surname + given_name)
  return inn_person == pers_info.signer_inn ||
         (last_name == pers_info.signer_surname &&
          givenname == pers_info.signer_givenname);
}

}  // namespace mrpa