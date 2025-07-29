#pragma once
#include "mrpa_typedefs.hpp"
#include "tree_context.hpp"
#ifdef TEST_BUILD

namespace mrpa {
class TestTreePrivate {
 public:
  static bool EmptyRootToJson() {
    TreeContext tree;
    tree.root_ = nullptr;
    return tree.ToJson().empty();
  }

  static bool EmptyRootBuildTables() {
    TreeContext tree;
    tree.root_ = nullptr;
    tree.BuildIdLookupTables();
    return tree.lookup_tables_.all_nodes.empty();
  }

  static PtrNode GetNodeByID(TreeContext& tree, NodeId node_id) {
    return tree.GetNode(node_id);
  }

  static PtrNode GetParent(TreeContext& tree, NodeId node_id) {
    return tree.GetParent(node_id);
  }

  static VecNodes GetChilds(const PtrNode& node) {
    return TreeContext::GetChilds(node);
  }

  static VecNodes GetSiblings(const TreeContext& tree, NodeId node_id) {
    return tree.GetSiblings(node_id);
  }

  static void ExpireAll(TreeContext& tree) { tree.root_->children.clear(); }

  static NodeId FirstChildId(TreeContext& tree) {
    return tree.root_->children.empty() ? 0 : tree.root_->children.at(0)->id;
  }

  static const IdMaps& getLookUpTables(TreeContext& tree) {
    return tree.lookup_tables_;
  }
};

}  // namespace mrpa
#endif
