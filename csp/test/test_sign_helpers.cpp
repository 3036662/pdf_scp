#include "cert_common_info.hpp"
#include "utils_cert.hpp"
#include <boost/json/serialize.hpp>
#include <vector>
#define CATCH_CONFIG_MAIN
#include "altcsp.hpp"
#include <catch2/catch.hpp>
#include <utils.hpp>
#include <utils_msg.hpp>

using namespace pdfcsp::csp;
using namespace pdfcsp::csp::asn;
using namespace pdfcsp::csp::utils::message;

constexpr const char *const test_file_dir = TEST_FILES_DIR;
const std::string test_dir = std::string(test_file_dir) + "valid_files/";

TEST_CASE("CetList") {
  Csp csp;
  REQUIRE_NOTHROW(csp.GetCertList());
  auto cert_list = csp.GetCertList();
  REQUIRE_FALSE(cert_list.empty());
  auto js_array = utils::cert::CertListToJSONArray(cert_list);
  REQUIRE(js_array);
  REQUIRE_FALSE(js_array->empty());
  std::cout << boost::json::serialize(*js_array);
};