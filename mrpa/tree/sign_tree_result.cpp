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
