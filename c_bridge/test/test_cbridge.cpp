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