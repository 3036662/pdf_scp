#pragma once

#include "node.hpp"

namespace mrpa {

class TreeContext {
 public:
  TreeContext();

  [[nodiscard]] bool AddFile(const std::string& path) noexcept;

 private:
  PtrNode root_;
};

}  // namespace mrpa