#include "check_utils.hpp"
#include "utils.hpp"

#include <boost/json/array.hpp>
#include <boost/json/object.hpp>
#include <boost/json/serialize.hpp>

namespace pdfcsp::csp::checks::check_utils {

namespace json = boost::json;

[[nodiscard]] std::string
BuildJsonTSPResult(const std::vector<CheckOneCadesTSPResult> &data) {
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

} // namespace pdfcsp::csp::checks::check_utils