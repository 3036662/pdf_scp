/* File: check_utils.hpp  
Copyright (C) Basealt LLC,  2024
Author: Oleg Proskurin, <proskurinov@basealt.ru>

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with this program; if not, write to the Free Software Foundation,
Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/


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