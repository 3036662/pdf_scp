#include "tree_context.hpp"

#include <algorithm>
#include <boost/algorithm/string/predicate.hpp>
#include <exception>
#include <filesystem>
#include <iostream>
#include <iterator>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "c_bridge.hpp"
#include "mrpa_typedefs.hpp"
#include "node.hpp"
#include "tree/utils_tree.hpp"
#include "tree/visitor.hpp"

namespace mrpa {

std::atomic_uint64_t TreeContext::counter_ = 0;

TreeContext::TreeContext()
  : root_(std::make_shared<DirNode>("", NodeType::kRoot, 0, false)),
    logger_{pdfcsp::logger::InitLog()} {}

[[nodiscard]] boost::json::object TreeContext::ToJson() const {
  if (!root_) {
    logger_->warn("[TreeContext::ToJson] called with empty tree");
    return {};
  }
  return root_->ToJson();
}

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

void TreeContext::BuildContext() {
  BuildIdLookupTables();
  BindDetachedSignatures();
  CheckDetachedSignatures();
  CheckAttachedSignatures();
  // CheckOnlyMrpaSigs();
  BindMrpaSigners();
}

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
    logger_->warn("[GetParent] node not found");
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
  // remove curr node from siblings
  const auto it_last = std::remove_if(siblings.begin(), siblings.end(),
                                      [node_id](const PtrNode& child) {
                                        return child && (child->id == node_id);
                                      });
  siblings.erase(it_last, siblings.end());
  return siblings;
}

void TreeContext::BindDetachedSignatures() {
  // for each signature
  for (const auto& sig_p : lookup_tables_.sig_nodes) {
    if (sig_p.second.expired()) {
      return;
    }
    const auto curr_sig_node =
      std::static_pointer_cast<SigNode>(sig_p.second.lock());
    // clear the connections
    curr_sig_node->refs.clear();
    // get all siblings
    VecNodes sibling_files = GetSiblings(sig_p.first);
    // remove directories
    auto it_last = std::remove_if(
      sibling_files.begin(), sibling_files.end(),
      [](const auto& node) { return !node || node->type == NodeType::kDir; });
    sibling_files.erase(it_last, sibling_files.end());
    // possible matches for the current node
    // A signature filename must begin with a matching file name.
    const std::string curr_sig_filename =
      std::filesystem::path(curr_sig_node->file_stat.name.value_or(""))
        .filename()
        .string();
    std::for_each(
      sibling_files.cbegin(), sibling_files.cend(),
      [&curr_sig_filename, &curr_sig_node](const PtrNode& sibling_node) {
        if (!sibling_node) {
          return;
        }
        auto file_node = std::static_pointer_cast<FileNode>(sibling_node);
        const std::string curr_file_name =
          std::filesystem::path(file_node->file_stat.name.value())
            .stem()
            .string();
        if (file_node->file_stat.name && !file_node->file_stat.name->empty() &&
            boost::starts_with(curr_sig_filename, curr_file_name)) {
          curr_sig_node->refs.emplace(sibling_node->id,
                                      sibling_node->weak_from_this());
        }
      });
    logger_->debug("Possible mathes found for signature :{} = {}",
                   curr_sig_filename, curr_sig_node->refs.size());
  }
}

void TreeContext::CheckDetachedSignatures() {
  std::for_each(
    lookup_tables_.sig_nodes.begin(), lookup_tables_.sig_nodes.end(),
    [](const auto& sig_p) {
      if (sig_p.second.expired()) {
        return;
      };
      CheckOneSigNode(std::static_pointer_cast<SigNode>(sig_p.second.lock()));
    });
}

void TreeContext::CheckOnlyMrpaSigs() {
  for (const auto& [sig_id, sig_wp] : lookup_tables_.sig_nodes) {
    if (sig_wp.expired()) {
      return;
    };
    auto sig_node = std::static_pointer_cast<SigNode>(sig_wp.lock());
    const bool is_mrpa_sig = std::any_of(
      sig_node->refs.cbegin(), sig_node->refs.cend(), [this](const auto& ref) {
        return lookup_tables_.mrpa_nodes.count(ref.first) > 0;
      });
    if (is_mrpa_sig) {
      CheckOneSigNode(sig_node);
    }
  }
}

void TreeContext::CheckAttachedSignatures() {
  std::for_each(lookup_tables_.asig_nodes.begin(),
                lookup_tables_.asig_nodes.end(), [](const auto& asig_pr) {
                  const auto& [asig_id, asig_wp] = asig_pr;
                  if (asig_wp.expired()) {
                    return;
                  }
                  CheckOneAttachedSigNode(
                    std::static_pointer_cast<AsigNode>(asig_wp.lock()));
                });
}

void TreeContext::BindMrpaSigners() {
  std::for_each(lookup_tables_.mrpa_nodes.begin(),
                lookup_tables_.mrpa_nodes.end(), [](const auto& pr_mrpa) {
                  if (pr_mrpa.second.expired()) {
                    return;
                  }
                  BindOneMrpaSigners(
                    std::static_pointer_cast<MrpaNode>(pr_mrpa.second.lock()));
                });
}

}  // namespace mrpa