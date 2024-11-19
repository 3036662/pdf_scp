#include "c_bridge.hpp"
#include "pod_structs.hpp"

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

TEST_CASE("CertList") {
  pdfcsp::c_bridge::CPodParam params;
  auto *res = pdfcsp::c_bridge::CGetCertList(params);
  REQUIRE(res != nullptr);
  REQUIRE(res->user_certifitate_list_json != nullptr);
  const std::string json_res = res->user_certifitate_list_json;
  REQUIRE_FALSE(json_res.empty());
  std::cout << json_res << "\n";
  pdfcsp::c_bridge::CFreeResult(res);
}