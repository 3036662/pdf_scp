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
#include <vector>

#include "grantors.hpp"
#include "logger_utils.hpp"
#include "pod_structs.hpp"

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
  void setSignature(
    const std::shared_ptr<pdfcsp::c_bridge::CPodResult>& check_result) noexcept;

  /// @brief true if the MRPA is valid
  [[nodiscard]] bool IsValid() const noexcept {
    return is_valid_ && flags_valid_ && name_valid_ && header_valid_;
  }

  /// @brief true if a valid signature was set
  [[nodiscard]] bool IsValidSignature() const noexcept {
    return sig_valid_ && signer_valid_;
  }

  [[nodiscard]] bool IsTimeValid() const noexcept { return time_valid_; }

  [[nodiscard]] const std::optional<boost::json::value>& GetRawJson()
    const noexcept {
    return json_val_;
  }

  /// @brief get the MRPA JSON representation
  [[nodiscard]] std::optional<std::string> toJson() const noexcept {
    if (!json_val_) {
      return std::nullopt;
    }
    return boost::json::serialize(*json_val_);
  }

  /**
   * @brief Parse grantors
   * @details called on non-default construct
   * @throws runtime_error
   */
  void ParseGrantors();

  /**
   * @brief Parse representatives
   * @details called on non-default construct
   * @throws runtime_error
   */
  void ParseRepresentatives();

  /**
   * @brief Parse issue date,expire date
   * @details called on non-default construct
   * @throws runtime_error
   */
  void ParseTime();

  [[nodiscard]] const std::optional<Grantor>& getGrantor() const noexcept {
    return grantor_;
  }

  [[nodiscard]] const std::vector<PhysicalPerson>& getRepresentatives()
    const noexcept {
    return persons_representative_;
  }

 private:
  void ParseFlags();
  void ParseName();
  void CheckHeader();

  /// @brief add notaries to grantor.all_persons
  void ParseNotaries();

  std::string filename_;
  std::shared_ptr<spdlog::logger> logger_;
  std::bitset<8> flags_;       //  requirements for mandatory format elements
  bool is_valid_ = false;      // basic validity of the MRPA
  bool flags_valid_ = false;   // correctness of <ПрЭлФорм> element
  bool name_valid_ = false;    // correctness of the MRPA filename
  bool header_valid_ = false;  // correctness of first line
  bool sig_valid_ = false;     // basic correctness of the signature
  bool signer_valid_ = false;  // result of signer matching
  bool time_valid_ = false;
  std::optional<std::string> err_string_;
  std::unique_ptr<xmlpp::DomParser> dom_parser;
  xmlpp::Document* doc_ = nullptr;
  std::optional<boost::json::value> json_val_;
  std::optional<boost::json::object> signers_cert_info_;
  std::optional<Grantor> grantor_;
  std::vector<PhysicalPerson> persons_representative_;
};

}  // namespace mrpa