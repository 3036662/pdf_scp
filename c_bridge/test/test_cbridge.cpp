/* File: test_cbridge.cpp
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
  REQUIRE(res->user_certifitate_list_json != nullptr);
  const std::string json_res = res->user_certifitate_list_json;
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
      REQUIRE_FALSE(std::string(res->user_certifitate_list_json).empty());
      std::cout << res->user_certifitate_list_json << "\n";
    });
  pdfcsp::c_bridge::FreeTaskBatchResult(result);
}