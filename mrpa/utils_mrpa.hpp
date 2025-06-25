#pragma once

#include <libxml++/document.h>

#include <boost/json.hpp>
#include <optional>

namespace mrpa::utils {

/// @brief get the MRPA uid from XML
std::optional<std::string> GetMRPAGuid(xmlpp::Document* doc) noexcept;

std::optional<boost::json::value> MrpaToJsonObject(xmlpp::Document* doc);

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

}  // namespace mrpa::utils