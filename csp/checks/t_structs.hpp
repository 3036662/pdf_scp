#pragma once
#include "asn_tsp.hpp"
#include "check_result.hpp"
#include <vector>

namespace pdfcsp::csp::checks {

struct CheckAllSignaturesInTspResult {
  bool result = false;
  std::vector<CheckResult> tsp_check_result;
};

struct CheckTspContentResult {
  bool result = false;
  std::optional<asn::TSTInfo> tst_content;
};

struct CheckOneCadesTSPResult {
  bool result = false;
  std::vector<std::string> chain_json_obj;
  std::optional<asn::TSTInfo> tst_content;
};

} // namespace pdfcsp::csp::checks