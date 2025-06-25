#include <cstdint>
#include <optional>
#include <string>

namespace mrpa {

enum class Sex : uint8_t { kMale = 1, kFemale = 2 };

enum class Citizenship : uint8_t {
  kRussia = 1,
  kForeign = 2,
  kNoCitizenship = 3
};

struct Address {
  std::string region;
  std::optional<std::string> address;
  std::optional<std::string> fias;
  std::optional<std::string> id_fias;
};

/// @brief ID - passport,etc.
struct PersonalID {
  std::string doc_number;
  std::string date_issued;
  std::optional<std::string> issuer;
  std::optional<std::string> issuer_id;
};

///@brief Physical person info
struct PhysicalPerson {
  std::string last_name;
  std::string name;
  std::optional<std::string> patronymic;
  std::optional<Sex> sex;
  std::optional<Citizenship> citizenship;
  std::optional<std::string> citizenship_country;
  std::optional<std::string> egrn;
  std::optional<std::string> birth_date;
  std::optional<std::string> birth_place;
  std::optional<std::string> phone;
  std::optional<std::string> email;
  std::optional<Address> address;
  std::optional<PersonalID> personal_id_doc;
};

}  // namespace mrpa