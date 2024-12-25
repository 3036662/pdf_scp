/* File: check_utils.cpp
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

#include "check_utils.hpp"

#include <boost/json.hpp>
#include <boost/json/array.hpp>
#include <boost/json/object.hpp>
#include <boost/json/parse.hpp>
#include <boost/json/serialize.hpp>
#include <stdexcept>
#include <string>

#include "ocsp.hpp"
#include "store_hanler.hpp"
#include "utils.hpp"

namespace pdfcsp::csp::checks::check_utils {

namespace json = boost::json;

[[nodiscard]] std::string BuildJsonTSPResult(
  const std::vector<CheckOneCadesTSPResult> &data) {
  json::array result;
  for (const auto &one_result : data) {
    result.push_back(TSPresToJson(one_result));
  }
  return json::serialize(result);
}

json::value TSPresToJson(const CheckOneCadesTSPResult &data) {
  boost::json::object res;
  res["result"] = data.result;
  boost::json::array arr_chains;
  for (const auto &one_chain : data.chain_json_obj) {
    boost::json::value chain_parsed = boost::json::parse(one_chain);
    arr_chains.push_back(std::move(chain_parsed));
  }
  res["chains"] = std::move(arr_chains);
  if (data.tst_content.has_value()) {
    res["tst_content"] = TSTInfoToJSON(data.tst_content.value());
  }
  return res;
}

json::value TSTInfoToJSON(const asn::TSTInfo &data) {
  json::object res;
  res["version"] = data.version;
  res["policy"] = data.policy;
  res["serial"] = VecBytesStringRepresentation(data.serialNumber);
  const ParsedTime parsed_time = GeneralizedTimeToTimeT(data.genTime);
  ;
  res["gen_time"] = parsed_time.time + parsed_time.gmt_offset;
  res["gen_time_readable"] =
    TimeTToString(parsed_time.time + parsed_time.gmt_offset);

  return res;
}

json::object BuildJsonOCSPResult(const OcspCheckParams &ocsp_params) {
  json::object result;
  if (ocsp_params.p_time_tsp == nullptr) {
    throw std::runtime_error("[BuildJsonOCSPResult] p_time = nullptr");
  }
  auto filetime = TimetToFileTime(*ocsp_params.p_time_tsp);
  const std::string chain_info = ocsp_params.p_ocsp_cert->ChainInfo(
    &filetime, ocsp_params.p_additional_store->RawHandler(), true);
  auto chain_info_json = json::parse(chain_info);
  if (chain_info_json.is_array()) {
    result["ocsp_chains"] = chain_info_json.as_array();
  }
  result["tbs_response_data"] =
    BasicOCSPResponseToJSON(*ocsp_params.p_response);
  return result;
}

json::object BasicOCSPResponseToJSON(
  const asn::BasicOCSPResponse &basic_response) {
  return ResponseDataToJSON(basic_response.tbsResponseData);
}

json::object ResponseDataToJSON(const asn::ResponseData &resp_data) {
  json::object result;
  const ParsedTime pardes_time = GeneralizedTimeToTimeT(resp_data.producedAt);
  result["produced_at"] = pardes_time.time + pardes_time.gmt_offset;
  result["produced_at_readable"] =
    TimeTToString(pardes_time.gmt_offset + pardes_time.time);
  json::array responses;
  for (const auto &resp : resp_data.responses) {
    responses.push_back(SingleResponseToJson(resp));
  }
  result["responses"] = std::move(responses);
  return result;
}

json::object SingleResponseToJson(const asn::SingleResponse &single_resp) {
  json::object result;
  result["cert_serial"] =
    VecBytesStringRepresentation(single_resp.certID.serialNumber);
  switch (single_resp.certStatus) {
    case asn::CertStatus::kGood:
      result["cert_status"] = "good";
      break;
    case (asn::CertStatus::kRevoked):
      result["cert_status"] = "revoked";
      break;
    case (asn::CertStatus::kUnknown):
      result["cert_status"] = "unknown";
      break;
  }
  const ParsedTime pardes_time = GeneralizedTimeToTimeT(single_resp.thisUpdate);
  result["this_update"] = pardes_time.time + pardes_time.gmt_offset;
  result["this_update_readable"] =
    TimeTToString(pardes_time.gmt_offset + pardes_time.time);
  return result;
}

}  // namespace pdfcsp::csp::checks::check_utils