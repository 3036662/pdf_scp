/* File: test_cbridge.cpp
Copyright (C) Basealt LLC,  2025
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

#include <algorithm>
#include <cstddef>
#include <memory>
#include <vector>

#include "c_bridge.hpp"
#include "pod_structs.hpp"

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

TEST_CASE("CertList") {
  pdfcsp::c_bridge::CPodParam params;
  auto* res = pdfcsp::c_bridge::CGetCertList(params);
  REQUIRE(res != nullptr);
  REQUIRE(res->user_certificate_list_json != nullptr);
  const std::string json_res = res->user_certificate_list_json;
  REQUIRE_FALSE(json_res.empty());
  std::cout << json_res << "\n";
  pdfcsp::c_bridge::CFreeResult(res);
}

TEST_CASE("TaskBatch") {
  auto p_butch = std::make_unique<pdfcsp::c_bridge::TaskBatch>();

  // create command
  pdfcsp::c_bridge::CPodParam params;
  params.command = "user_cert_list";
  params.command_size = 14;

  // put this command to array (3 times)
  std::vector<pdfcsp::c_bridge::CPodParam*> params_arr;
  params_arr.push_back(&params);
  params_arr.push_back(&params);
  params_arr.push_back(&params);

  // save it to TaskBatch
  p_butch->params = params_arr.data();
  p_butch->params_size = params_arr.size();

  const auto* result = pdfcsp::c_bridge::ExecuteTaskBatch(p_butch.get());
  REQUIRE(result);
  REQUIRE(result->results != nullptr);
  REQUIRE(result->results_size == 3);

  const bool all_ok =
    std::all_of(result->results, result->results + (result->results_size - 1),
                [](const pdfcsp::c_bridge::CPodResult* res) {
                  return res != nullptr && res->common_execution_status;
                });
  REQUIRE(all_ok);
  std::for_each(
    result->results, result->results + result->results_size,
    [](const auto* res) {
      REQUIRE_FALSE(std::string(res->user_certificate_list_json).empty());
      std::cout << res->user_certificate_list_json << "\n";
    });
  pdfcsp::c_bridge::FreeTaskBatchResult(result);
}

TEST_CASE("TaskBatch_create_files") {
  auto p_butch = std::make_unique<pdfcsp::c_bridge::TaskBatch>();

  const std::string src = std::string(TEST_FILES_DIR) + "text_file_to_sign.txt";
  const std::string dest_val1 = std::string(TEST_DIR) + "detached5.sig";
  const std::string dest_val2 = std::string(TEST_DIR) + "attached6.sig";

  const std::string subj(USER_CERT_SUBJECT);
  const std::string serial(USER_CERT_SERIAL);
  const std::string command("create_signature_file");
  const std::string tsp_url = "http://pki.tax.gov.ru/tsp/tsp.srf";
  // create command
  pdfcsp::c_bridge::CPodParam params1;
  params1.command = command.c_str();
  params1.command_size = command.size();
  params1.file_path = src.c_str();
  params1.file_path_size = src.size();
  params1.sig_file_path = dest_val1.c_str();
  params1.sig_file_path_size = dest_val1.size();
  params1.cert_subject = subj.c_str();
  params1.cert_serial = serial.c_str();
  params1.cades_type = "CADES_XLT1";
  params1.tsp_link = tsp_url.c_str();
  params1.create_attached = false;
  params1.create_base_64_encoded = true;

  pdfcsp::c_bridge::CPodParam params2(params1);
  params1.sig_file_path = dest_val2.c_str();
  params1.sig_file_path_size = dest_val2.size();
  params1.create_attached = true;
  params1.create_base_64_encoded = true;

  // put this command to array (3 times)
  std::vector<pdfcsp::c_bridge::CPodParam*> params_arr;
  params_arr.push_back(&params1);
  params_arr.push_back(&params2);

  // save it to TaskBatch
  p_butch->params = params_arr.data();
  p_butch->params_size = params_arr.size();

  const auto* result = pdfcsp::c_bridge::ExecuteTaskBatch(p_butch.get());
  REQUIRE(result);
  REQUIRE(result->results != nullptr);
  REQUIRE(result->results_size == 2);

  const bool all_ok =
    std::all_of(result->results, result->results + (result->results_size - 1),
                [](const pdfcsp::c_bridge::CPodResult* res) {
                  return res != nullptr && res->common_execution_status;
                });
  REQUIRE(all_ok);
  pdfcsp::c_bridge::SeparateSignatureParams params3{dest_val1.c_str(),
                                                    dest_val1.size()};
  REQUIRE_FALSE(pdfcsp::c_bridge::IsMessageAttached(&params3));
  pdfcsp::c_bridge::SeparateSignatureParams params4{dest_val2.c_str(),
                                                    dest_val2.size()};
  REQUIRE(pdfcsp::c_bridge::IsMessageAttached(&params4));
  pdfcsp::c_bridge::FreeTaskBatchResult(result);
}