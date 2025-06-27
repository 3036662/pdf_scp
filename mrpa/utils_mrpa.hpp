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
 * @brief Parse the authority confirmation document
 *
 * @param authority_doc "ДокПдтвТип" object
 * @return AuthorityConfirmationDoc
 */
AuthorityConfirmationDoc ParseAuthorityConfirmationDoc(
  const boost::json::object& authority_doc);

/**
 * @brief Parse the registration addres
 *
 * @param reg_addr "АдрРег" object
 * @return RegistrationAddress
 */
RegistrationAddress ParseRegistrationAddress(
  const boost::json::object& reg_addr);

/**
 * @brief Update Grantor's company info
 *
 * @param [in] company_info "СвОргТип"
 * @param [out] result update Grantor object
 * @throws
 */
void UpdateGrantorCompanyInfo(const boost::json::object& company_info,
                              Grantor& result);

/**
 * @brief Parse grantors for a russian company
 *
 * @param grantor_top
 * @return std::vector<Grantor>
 * @throws
 */
Grantor ParseCompanyGrantor(const boost::json::object& grantor_top);

}  // namespace mrpa::utils