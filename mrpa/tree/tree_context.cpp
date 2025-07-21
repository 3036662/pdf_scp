#include "tree_context.hpp"

#include <memory>

#include "node.hpp"

namespace mrpa {

TreeContext::TreeContext() : root_(std::make_shared<DirNode>()) {
  root_->id = 0;
  root_->type = NodeType::kRoot;
}

}  // namespace mrpa