#pragma once

#include "node.hpp"

namespace mrpa {

class TreeContext {
 public:
  TreeContext();

 private:
  PtrNode root_;
};

}  // namespace mrpa