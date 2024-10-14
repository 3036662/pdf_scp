#pragma once
#include "certificate.hpp"
#include "t_structs.hpp"
#include <boost/json.hpp>
#include <string>

namespace pdfcsp::csp::checks::check_utils {

namespace json = boost::json;

/**
 * @brief Build complete json string with all validation result for TSP stamps
 *
 * @param data - vector of CheckOneCadesTSPResult
 * @return std::string - json string
 */
[[nodiscard]] std::string
BuildJsonTSPResult(const std::vector<CheckOneCadesTSPResult> &data);

[[nodiscard]] json::value TSPresToJson(const CheckOneCadesTSPResult &data);

[[nodiscard]] json::value TSTInfoToJSON(const asn::TSTInfo &data);

[[nodiscard]] json::object
BuildJsonOCSPResult(const OcspCheckParams &ocsp_params);

[[nodiscard]] json::object
BasicOCSPResponseToJSON(const asn::BasicOCSPResponse &basic_response);

[[nodiscard]] json::object
ResponseDataToJSON(const asn::ResponseData &resp_data);

[[nodiscard]] json::object
SingleResponseToJson(const asn::SingleResponse &single_resp);

} // namespace pdfcsp::csp::checks::check_utils