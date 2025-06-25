#pragma once
#include <libxml++/libxml++.h>

#include <bitset>
#include <boost/json.hpp>
#include <boost/json/basic_parser.hpp>
#include <boost/json/object.hpp>
#include <boost/json/serialize.hpp>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "logger_utils.hpp"
#include "physical_person.hpp"

namespace mrpa {

/**
 * @brief Represents a machine readable power attorney
 * @throw doest not throw on construct
 */
class Mrpa final {
 public:
  Mrpa() : logger_(pdfcsp::logger::InitLog()) {};
  explicit Mrpa(const std::string& filename) noexcept;

  /// @brief set signature file
  void setSignature(const std::string& sig_filename) noexcept;

  /// @brief true if the MRPA is valid
  [[nodiscard]] bool IsValid() const noexcept {
    return is_valid_ && flags_valid_ && name_valid_ && header_valid_;
  }

  /// @brief true if a valid signature was set
  [[nodiscard]] bool IsValidSignature() const noexcept { return sig_valid_; }

  /// @brief get the MRPA JSON representation
  [[nodiscard]] std::optional<std::string> toJson() const noexcept {
    if (!json_val) {
      return std::nullopt;
    }
    return boost::json::serialize(*json_val);
  }

  /**
   * @brief Parse grantors
   * @details called on non-default construct
   * @throws runtime_error if no json_val is set
   */
  void ParseGrantors();

  [[nodiscard]] const std::vector<PhysicalPerson>& getGrantors()
    const noexcept {
    return grantors_;
  }

 private:
  void ParseFlags();
  void ParseName();
  void CheckHeader();

  std::string filename_;
  std::shared_ptr<spdlog::logger> logger_;
  std::bitset<8> flags_;  //  requirements for mandatory format elements
  bool is_valid_ = false;
  bool flags_valid_ = false;
  bool name_valid_ = false;
  bool header_valid_ = false;
  bool sig_valid_ = false;
  bool signer_valid_ = false;
  std::optional<std::string> err_string_;
  std::unique_ptr<xmlpp::DomParser> dom_parser;
  xmlpp::Document* doc_ = nullptr;
  std::optional<boost::json::value> json_val;
  std::vector<PhysicalPerson> grantors_;
};

}  // namespace mrpa