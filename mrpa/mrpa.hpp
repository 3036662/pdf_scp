#pragma once
#include <libxml++/libxml++.h>

#include <bitset>
#include <boost/json.hpp>
#include <boost/json/object.hpp>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

#include "logger_utils.hpp"

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
};

/// @brief get the MRPA uid from XML
std::optional<std::string> GetMRPAGuid(xmlpp::Document* doc) noexcept;

/**
 * @brief Convert xml document to JSON format
 */
std::optional<std::string> XmlToJson(xmlpp::Document* doc);

/**
 * @brief Extract json object holding the signer's certificate
 * @param chain_info json string with chains
 * @param serial signer's certificate serial number
 * @return std::optional<boost::json::object>
 * @throws  does not throw
 */
std::optional<boost::json::object> SignersCertJson(
  std::string_view chain_info, std::string_view serial) noexcept;

}  // namespace mrpa