#pragma once

#include <boost/json/object.hpp>

#include "tree_defs.hpp"

namespace mrpa {

struct SignTreeResult {
  VecStrings result_files;
  VecStrings warnings;
  std::string final_dir;

  [[nodiscard]] boost::json::object ToJson() const;
};

}  // namespace mrpa