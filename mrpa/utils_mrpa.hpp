#pragma once

#include <libxml++/document.h>

#include <boost/json.hpp>
#include <boost/json/object.hpp>
#include <optional>
#include <string>
#include <vector>

#include "grantors.hpp"

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

/**
 * @brief Parse grantors for a russian company
 *
 * @param grantor_top
 * @return std::vector<Grantor>
 * @throws
 */
Grantor ParseCompanyGrantor(const boost::json::object& grantor_top);

/**
 * @brief  Parse grantor for a foreign company
 * @param grantor
 * @return Grantor
 * @details xml <ИнОргДовер> tag
 */
Grantor ParseForeignCompanyGrantor(const boost::json::object& grantor);

/**
 * @brief  Parse grantor for a IP
 * @param grantor
 * @return Grantor
 * @details xml <ИПДовер> tag
 */
Grantor ParseIPGrantor(const boost::json::object& grantor);

/**
 * @brief  Parse grantor for a IP
 * @param grantor
 * @return Grantor
 * @details xml <ФЛДовер> tag
 */
Grantor ParsePersonGrantor(const boost::json::object& grantor);

}  // namespace mrpa::utils