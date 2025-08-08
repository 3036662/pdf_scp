#include <boost/json/array.hpp>
#include <boost/json/serialize.hpp>
#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

#include "doc_archive_public.hpp"

const std::string archive_real1 =
  std::string(TEST_FILES_DIR) +
  "mrpa/sensitive/Счет_на_оплату_№_1513_от_30_июня_2025_г_pdf.zip";

const std::string archive_real2 =
  std::string(TEST_FILES_DIR) + "mrpa/sensitive/bugzilla_54258_CP866.zip";

TEST_CASE("Basic") {
  // JSON array of paths
  boost::json::array arr;
  arr.emplace_back(archive_real1);
  arr.emplace_back(archive_real2);
  const std::string js_list = boost::json::serialize(arr);

  // create Tree
  pdfcsp::DocTree tree;
  // add files
  auto res = tree.AddFilesJsonList(js_list);
  REQUIRE(res.has_value());
  // build the net
  res = tree.BuildTree();
  REQUIRE(res.has_value());
  std::cout << res.value() << "\n";
}