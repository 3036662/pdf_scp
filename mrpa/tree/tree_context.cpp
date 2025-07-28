#include "tree_context.hpp"

#include <algorithm>
#include <exception>
#include <iostream>
#include <memory>
#include <vector>

#include "mrpa_typedefs.hpp"
#include "node.hpp"
#include "tree/utils_tree.hpp"
#include "tree/visitor.hpp"

namespace mrpa {

std::atomic_uint64_t TreeContext::counter_ = 0;

TreeContext::TreeContext()
  : root_(std::make_shared<DirNode>("", NodeType::kRoot, 0, false)),
    logger_{pdfcsp::logger::InitLog()} {}

bool TreeContext::AddFile(const std::string& path) noexcept {
  if (path.empty()) {
    return false;
  }
  try {
    auto node = NodeFromFileFactory(path, NextId());
    if (!node) {
      return false;
    }
    node->parent_id = 0;
    root_->children.emplace_back(std::move(node));
    BuildIdLookupTables();
    BuildContext();
  } catch (const std::exception& ex) {
    logger_->error("[TreeContext::AddFile] {}", ex.what());
    return false;
  }
  return true;
};

void TreeContext::BuildIdLookupTables() {
  if (!root_) {
    return;
  }
  // build the lookup tables
  {
    LookupTablesBuilder builder;
    root_->AcceptVisitor(builder);
    lookup_tables_ = builder.getTables();
  }
}

void TreeContext::BuildContext() { BindDetachedSignatures(); }

PtrNode TreeContext::GetNode(NodeId node_id) const {
  if (lookup_tables_.all_nodes.count(node_id) == 0) {
    logger_->warn("[GetNode] node not found,id: {}", node_id);
    return {};
  }
  const PtrAssocNode& wp_node = lookup_tables_.all_nodes.at(node_id);
  if (wp_node.expired()) {
    logger_->warn("[GetNode] the node has expired,id: {}", node_id);
    return {};
  }
  return wp_node.lock();
}

PtrNode TreeContext::GetParent(const PtrNode& node) const {
  if (!node) {
    logger_->warn("[GetParent] node not found, id: {}", node->id);
    return {};
  }
  const auto& parent_id = node->parent_id;
  if (parent_id) {
    return GetNode(parent_id.value());
  }
  logger_->warn("[GetParent] no parent exist for the root node", node->id);
  return {};
}

PtrNode TreeContext::GetParent(NodeId node_id) const {
  const PtrNode node = GetNode(node_id);
  return GetParent(node);
}

/// @brief get child nodes
VecNodes TreeContext::GetChilds(const PtrNode& node) {
  if (node->type == NodeType::kDir) {
    return std::static_pointer_cast<DirNode>(node)->children;
  }
  if (node->type == NodeType::kZip) {
    return std::static_pointer_cast<ZipNode>(node)->children;
  }
  if (node->type == NodeType::kAsig) {
    VecNodes result;
    result.push_back(std::static_pointer_cast<AsigNode>(node)->child_);
    return result;
  }
  return {};
}

VecNodes TreeContext::GetSiblings(NodeId node_id) const {
  const PtrNode node = GetNode(node_id);
  const PtrNode parent = GetParent(node);
  if (!parent) {
    logger_->warn("[GetSiblingsIds] Parent node was not found for node:",
                  node_id);
    return {};
  }
  VecNodes siblings = GetChilds(parent);
  const auto it_last = std::remove_if(siblings.begin(), siblings.end(),
                                      [node_id](const PtrNode& child) {
                                        return child && (child->id == node_id);
                                      });
  siblings.erase(it_last, siblings.end());
  return siblings;
}

void TreeContext::BindDetachedSignatures() const {
  // for each signature
  std::for_each(lookup_tables_.sig_nodes.begin(),
                lookup_tables_.sig_nodes.end(), [this](const auto& sig_p) {
                  if (sig_p.second.expired()) {
                    return;
                  }
                  // get all siblings
                  const VecNodes siblings = GetSiblings(sig_p.first);
                  logger_->debug("Sibling count for node {} : {}", sig_p.first,
                                 siblings.size());
                });
}

}  // namespace mrpa