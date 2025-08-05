#pragma once

#include <libxml++/document.h>
#include <spdlog/logger.h>

#include <boost/json.hpp>
#include <boost/json/object.hpp>
#include <optional>
#include <string>
#include <vector>

#include "grantors.hpp"
#include "mrpa_typedefs.hpp"

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
 * @brief Get the Attorney object
 *
 * @param val json::value of MRPA
 * @return const boost::json::object& Attorney
 * @throws
 */
const boost::json::object& GetAttorneyObj(
  const std::optional<boost::json::value>& json_val);

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
 * @throws
 */
Grantor ParseForeignCompanyGrantor(const boost::json::object& grantor);

/**
 * @brief  Parse grantor for a IP
 * @param grantor
 * @return Grantor
 * @details xml <ИПДовер> tag
 * @throws
 */
Grantor ParseIPGrantor(const boost::json::object& grantor);

/**
 * @brief  Parse grantor for a IP
 * @param grantor
 * @return Grantor
 * @details xml <ФЛДовер> tag
 * @throws
 */
Grantor ParsePersonGrantor(const boost::json::object& grantor);

/**
 * @brief Parse all  <СвУпПред> of given object
 * @param val
 * @return std::vector<PhysicalPerson>
 * @throws
 */
std::vector<PhysicalPerson> ParseAllRepresentativePersons(
  const boost::json::object& val);

/// @brief parse "YYYY-MM-DD"
/// @throws std::runtime_error on fail
time_t ParseXMLDate(const std::string& val);

/**
 * @brief Extract signer's name, surname and a certificate serial
 * @param check_res Signature check result
 * @return SignaturePersonInfo simple struct with three opional fields
 */
SignaturePersonInfo ExtractSignerInfo(
  const PtrSigCheckRes& check_res,
  const std::shared_ptr<spdlog::logger>& logger);

}  // namespace mrpa::utils