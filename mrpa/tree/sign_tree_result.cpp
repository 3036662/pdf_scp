/* File: sign_tree_result.cpp
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

#include "sign_tree_result.hpp"

#include <algorithm>
#include <boost/json/array.hpp>
#include <boost/json/object.hpp>
#include <boost/json/string.hpp>
#include <iterator>

namespace mrpa {

boost::json::object SignTreeResult::ToJson() const {
  boost::json::object res;
  boost::json::array files;
  std::transform(result_files.cbegin(), result_files.cend(),
                 std::back_inserter(files),
                 [](const auto& str) { return boost::json::string(str); });
  res["files"] = std::move(files);
  boost::json::array wrn;
  std::transform(warnings.cbegin(), warnings.cend(), std::back_inserter(wrn),
                 [](const auto& str) { return boost::json::string(str); });
  res["warnings"] = std::move(wrn);
  res["final_dir"] = final_dir;
  return res;
}

};  // namespace mrpa
