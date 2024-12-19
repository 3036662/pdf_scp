/* File: t_structs.hpp  
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