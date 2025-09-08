#pragma once
#include <boost/json/object.hpp>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "mrpa_typedefs.hpp"

namespace mrpa {

enum class Sex : uint8_t { kMale = 1, kFemale = 2 };

enum class Citizenship : uint8_t {
  kRussia = 1,
  kForeign = 2,
  kNoCitizenship = 3
};

using OptionalStr = std::optional<std::string>;

struct AuthorityConfirmationDoc {
  OptionalStr doc_name;
  OptionalStr date_issued;
  OptionalStr issuer;
  /// information about the identification of the document
  OptionalStr doc_info;

  [[nodiscard]] boost::json::object ToJson() const;
};

// struct Address {
//   std::string region;
//   OptionalStr address;
//   OptionalStr fias;
//   OptionalStr id_fias;

//   [[nodiscard]] boost::json::object ToJson() const;
// };

struct RegistrationAddress {
  std::string region;
  OptionalStr address;
  OptionalStr fias_id;
  OptionalStr fias_address;
  [[nodiscard]] boost::json::object ToJson() const;
};

/// @brief ID - passport,etc.
struct PersonalID {
  std::string doc_number;
  std::string date_issued;
  OptionalStr issuer;
  OptionalStr issuer_id;

  [[nodiscard]] boost::json::object ToJson() const;
};

///@brief Physical person info
struct PhysicalPerson {
  std::string last_name;
  std::string name;
  OptionalStr patronymic;
  std::optional<Sex> sex;
  std::optional<Citizenship> citizenship;
  OptionalStr citizenship_country;
  OptionalStr egrn;
  OptionalStr birth_date;
  OptionalStr birth_place;
  OptionalStr phone;
  OptionalStr email;
  std::optional<RegistrationAddress> address;
  std::optional<PersonalID> personal_id_doc;
  /// The status of the participant of the notarial action
  OptionalStr member_status;
  OptionalStr inn_person;
  OptionalStr snils_person;
  OptionalStr duty;
  // A sign of full civil legal capacity
  OptionalStr has_legal_capacity;
  OptionalStr has_representative;
  OptionalStr incapacity_doc;
  std::optional<AuthorityConfirmationDoc> authority_confirmation_doc;

  [[nodiscard]] boost::json::object ToJson() const;

  /// @brief compare with a SignaturePersonInfo
  [[nodiscard]] bool operator==(
    const SignaturePersonInfo& pers_info) const noexcept;
};

enum class GrantorType : uint8_t {
  kCompany = 1,
  kForeignCompany = 2,
  kIP = 3,
  kPerson = 4,
  kUnknown = 255
};

std::string ToString(GrantorType type);

/// @brief the sole executive body
enum class SoleExecutive : uint8_t {
  kCompany = 1,
  kIP = 3,
  kPerson = 4,
  kUnknown = 255
};

inline SoleExecutive makeExecutive(bool is_company, bool is_ip,
                                   bool is_person) noexcept {
  // only one value can be true
  if ((is_company || is_ip) && is_person) {
    return SoleExecutive::kUnknown;
  }
  if (is_company) {
    return SoleExecutive::kCompany;
  }
  if (is_ip) {
    return SoleExecutive::kIP;
  }
  if (is_person) {
    return SoleExecutive::kPerson;
  }
  return SoleExecutive::kUnknown;
}

struct Grantor {
  GrantorType type = GrantorType::kUnknown;
  OptionalStr company_name;
  OptionalStr ip_name;
  OptionalStr inn_le;
  OptionalStr inn_ip;
  OptionalStr snils_ip;
  OptionalStr snils_person;
  OptionalStr kpp;
  OptionalStr ogrn;
  OptionalStr orgn_ip;
  OptionalStr department_reg_number;
  /// incorporation papers
  OptionalStr incorp_doc;
  OptionalStr phone;
  OptionalStr email;
  /// The status of the participant of the notarial action
  OptionalStr notarial_status;
  /// A document confirming the authority of a person acting without a power of
  /// attorney
  std::optional<AuthorityConfirmationDoc> authority_confirmation_doc;
  std::optional<RegistrationAddress> reg_address;
  std::vector<Grantor> executive_companies;
  std::vector<Grantor> executive_ips;
  std::vector<PhysicalPerson> persons;
  std::vector<PhysicalPerson> all_persons;

  [[nodiscard]] boost::json::object ToJson() const;
};

}  // namespace mrpa