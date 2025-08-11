#include "tree_context.hpp"

#include <algorithm>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/json.hpp>
#include <boost/json/parse.hpp>
#include <boost/json/serialize.hpp>
#include <catch2/catch.hpp>
#include <cstdint>
#include <exception>
#include <filesystem>
#include <memory>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <string>
#include <tuple>
#include <unordered_map>
#include <vector>

#include "grantors.hpp"
#include "mrpa_typedefs.hpp"
#include "node.hpp"
#include "tree/utils_tree.hpp"
#include "tree/visitor.hpp"
#include "utils_mrpa.hpp"

namespace mrpa {

std::atomic_uint64_t TreeContext::counter_ = 0;

TreeContext::TreeContext()
  : root_(std::make_shared<DirNode>("", NodeType::kRoot, 0, false)),
    logger_{pdfcsp::logger::InitLog()} {}

[[nodiscard]] boost::json::object TreeContext::ToJson() const {
  std::shared_lock lock(mtx_, std::defer_lock);
  if (!lock.try_lock()) {
    logger_->warn("[ToJson] context is busy, cancel");
    return {};
  }
  if (!root_) {
    logger_->warn("[TreeContext::ToJson] called with empty tree");
    return {};
  }
  return root_->ToJson();
}

bool TreeContext::AddFile(const std::string& path, bool build_context,
                          bool lock_ctx) noexcept {
  std::unique_lock lock(mtx_, std::defer_lock);
  if (lock_ctx && !lock.try_lock()) {
    logger_->warn("[AddFile] context is busy, cancel");
    return false;
  }
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
    if (build_context) {
      if (lock_ctx) {
        lock.unlock();
      }
      BuildContext();
    }
  } catch (const std::exception& ex) {
    logger_->error("[TreeContext::AddFile] {}", ex.what());
    return false;
  }
  return true;
};

bool TreeContext::RemoveNode(NodeId node_id, bool build_context,
                             bool lock_ctx) noexcept {
  std::unique_lock lock(mtx_, std::defer_lock);
  // root node can't be removed
  if (node_id == 0) {
    return false;
  }
  if (lock_ctx && !lock.try_lock()) {
    logger_->warn("[RemoveNode] context is busy, cancel");
    return false;
  }
  try {
    // only root children can be removed
    auto parent = GetParent(node_id);
    if (parent->type != NodeType::kRoot) {
      logger_->warn("[RemoveNode] only top nodes can be removed");
      return false;
    }
    auto& children = root_->children;
    auto it_last = std::remove_if(
      children.begin(), children.end(),
      [&node_id](const PtrNode& child) { return child->id == node_id; });
    children.erase(it_last, children.end());
    if (build_context) {
      if (lock_ctx) {
        lock.unlock();
      }
      BuildContext();
    }
  } catch (const std::exception& ex) {
    logger_->error("[RemoveNode] {}", ex.what());
    return false;
  }
  return true;
}

bool TreeContext::Reset() noexcept {
  if (!root_) {
    return true;
  }
  std::unique_lock lock(mtx_, std::defer_lock);
  if (!lock.try_lock()) {
    logger_->warn("[TreeContext::Reset] context is busy, cancel");
    return false;
  }
  root_->children.clear();
  lock.unlock();
  BuildContext();
  return true;
}

bool TreeContext::AddFileListJson(const std::string& json_list) noexcept {
  if (json_list.empty()) {
    return false;
  }
  constexpr const char* func_name = "[TreeContext::AddFileListJson]";
  std::unique_lock lock(mtx_, std::defer_lock);
  if (!lock.try_lock()) {
    logger_->warn("{} Context is busy, failed", func_name);
    return false;
  }
  try {
    auto json_val = boost::json::parse(json_list);
    if (!json_val.is_array()) {
      logger_->error("{} JSON list is not an array", func_name);
      return false;
    }
    const auto& json_arr = json_val.as_array();
    const bool res =
      std::all_of(json_arr.cbegin(), json_arr.cend(), [this](const auto& path) {
        return AddFile(path.as_string().c_str(), false, false);
      });
    if (!res) {
      logger_->error("{} add files failed:", func_name);
    }
    return res;
  } catch (const std::exception& ex) {
    logger_->error("{} {}", func_name, ex.what());
  }
  return false;
}

bool TreeContext::RemoveNodesJsonList(const std::string& json_list) noexcept {
  if (json_list.empty()) {
    return false;
  }
  constexpr const char* func_name = "[TreeContext::RemoveNodesJsonList]";
  std::unique_lock lock(mtx_, std::defer_lock);
  if (!lock.try_lock()) {
    logger_->warn("{} Context is busy, failed", func_name);
    return false;
  }
  try {
    auto json_val = boost::json::parse(json_list);
    if (!json_val.is_array()) {
      logger_->error("{} JSON list is not an array", func_name);
      return false;
    }
    const auto& json_arr = json_val.as_array();
    const bool res = std::all_of(json_arr.begin(), json_arr.end(),
                                 [this](const boost::json::value& node_id) {
                                   uint64_t uint_id = 0;
                                   if (node_id.is_number()) {
                                     uint_id = node_id.to_number<uint64_t>();
                                   }
                                   return RemoveNode(uint_id, false, false);
                                 });
    if (!res) {
      logger_->error("{} remove files failed:", func_name);
    }
    return res;
  } catch (const std::exception& ex) {
    logger_->error("{} {}", func_name, ex.what());
  }
  return false;
}

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

bool TreeContext::BuildContext() {
  std::unique_lock lock(mtx_, std::defer_lock);
  if (!lock.try_lock()) {
    logger_->warn("[BuildContext] context is busy, cancel");
    return false;
  }
  // visit all nodes and save lookup tables
  BuildIdLookupTables();
  // find possible src files for detached signature
  BindDetachedSignatures();
  CheckDetachedSignatures();
  CheckAttachedSignatures();
  // Check all [mrpa->sig] connections, remove invalid connections
  BindMrpaSigners();
  // Create a map of representatives
  BuildRepresentativesMap();
  // build [file signature -> mrpa] +  [signed file => mrpa] connentions
  BindSignaturesToMRPA();
  return true;
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
  if (node->type == NodeType::kDir || node->type == NodeType::kRoot) {
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
  std::for_each(lookup_tables_.sig_nodes.begin(),
                lookup_tables_.sig_nodes.end(), [this](const auto& sig_p) {
                  if (sig_p.second.expired()) {
                    return;
                  };
                  CheckOneSigNode(
                    std::static_pointer_cast<SigNode>(sig_p.second.lock()),
                    logger_);
                });
}

void TreeContext::CheckOnlyMrpaSigs() {
  for (const auto& [sig_id, sig_wp] : lookup_tables_.sig_nodes) {
    if (sig_wp.expired()) {
      continue;
      ;
    };
    auto sig_node = std::static_pointer_cast<SigNode>(sig_wp.lock());
    const bool is_mrpa_sig = std::any_of(
      sig_node->refs.cbegin(), sig_node->refs.cend(), [this](const auto& ref) {
        return lookup_tables_.mrpa_nodes.count(ref.first) > 0;
      });
    if (is_mrpa_sig) {
      CheckOneSigNode(sig_node, logger_);
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

/**
 * @brief Check all [mrpa->sig] connections, remove invalid connections
 * @details A connection will be removed if  a signature check failed or
 * signer person is invalid
 */
void TreeContext::BindMrpaSigners() {
  std::for_each(lookup_tables_.mrpa_nodes.begin(),
                lookup_tables_.mrpa_nodes.end(), [this](const auto& pr_mrpa) {
                  if (pr_mrpa.second.expired()) {
                    return;
                  }
                  BindOneMrpaSigners(
                    std::static_pointer_cast<MrpaNode>(pr_mrpa.second.lock()),
                    logger_);
                });
}

/**
 * @brief Creates a map of representatives [mrpa_id => vector<PhysicalPerson>]
 * @details Takes into account only those MRPAs that are signed
 */
void TreeContext::BuildRepresentativesMap() {
  representatives_.clear();
  for (const auto& [id_mrpa, wp_mrpa] : lookup_tables_.mrpa_nodes) {
    if (wp_mrpa.expired()) {
      continue;
    }
    const auto& mrpa_node = std::static_pointer_cast<MrpaNode>(wp_mrpa.lock());
    if (!mrpa_node || mrpa_node->refs.empty() || !mrpa_node->mrpa) {
      logger_->debug("[BuildRepresentativesMap] skipping the MRPA {}", id_mrpa);
      continue;
    }
    representatives_.insert_or_assign(id_mrpa,
                                      mrpa_node->mrpa->getRepresentatives());
    logger_->debug(
      "[BuildRepresentativesMap] {} representatives found for MRPA ID: {}",
      representatives_.at(id_mrpa).size(), id_mrpa);
  };
}

/**
 * @brief build [file signature -> mrpa] +  [signed file => mrpa] connentions
 * @details If a file signer matches the MRPA's representative person, a [file
 * signature → MRPA] and [signed file => mrpa] connection will be added.
 */
void TreeContext::BindSignaturesToMRPA() {
  logger_->info(
    "[BindSignaturesToMRPA] number of signed MRPAs with representatives:{}",
    representatives_.size());
  // attached signatures
  for (auto& [id_asig, wp_asig] : lookup_tables_.asig_nodes) {
    if (wp_asig.expired()) {
      continue;
    }
    auto asig_node = std::static_pointer_cast<AsigNode>(wp_asig.lock());
    if (!asig_node) {
      continue;
      ;
    }
    BindOneAsigToMrpa(*asig_node);
  };
  // detached signatures
  for (auto& [id_sig, wp_sig] : lookup_tables_.sig_nodes) {
    if (wp_sig.expired()) {
      continue;
    }
    auto sig_node = std::static_pointer_cast<SigNode>(wp_sig.lock());
    if (!sig_node) {
      continue;
    }
    BindOneSigToMrpa(*sig_node);
  }
};

void TreeContext::BindOneAsigToMrpa(AsigNode& asig_node) {
  if (!asig_node.check_res) {
    return;
  }
  asig_node.signer_person_info =
    utils::ExtractSignerInfo(asig_node.check_res, logger_);
  SaveRefsToMrpa(asig_node);
  // put mrpa info to child
  if (asig_node.child_ && asig_node.child_->refs.count(asig_node.id) > 0) {
    asig_node.child_->mrpa_refs = asig_node.mrpa_refs;
  }
}

void TreeContext::BindOneSigToMrpa(SigNode& sig_node) {
  // the signature can contain check results for 0 to n files
  // we should take first non-null result, the signer will be same for all of
  // them
  auto it_check_res =
    std::find_if(sig_node.check_res.cbegin(), sig_node.check_res.cend(),
                 [](const auto& pr_check_res) {
                   const auto& [id_file, check_res] = pr_check_res;
                   return check_res != nullptr;
                 });
  if (it_check_res == sig_node.check_res.cend()) {
    return;
  }
  sig_node.signer_person_info =
    utils::ExtractSignerInfo(it_check_res->second, logger_);
  SaveRefsToMrpa(sig_node);
  // put MRPA refs to signed files
  for (const auto& [file_id, wp_file] : sig_node.refs) {
    if (wp_file.expired()) {
      continue;
    }
    const auto file_node = std::static_pointer_cast<FileNode>(wp_file.lock());
    if (!file_node || file_node->refs.count(sig_node.id) == 0) {
      continue;
    }
    file_node->mrpa_refs = sig_node.mrpa_refs;
  }
}

///@brief look for valid MRPAs for this particular signer
std::vector<NodeId> TreeContext::FindMrpaForSigner(
  const SignaturePersonInfo& pers_info) {
  std::vector<NodeId> res;
  // the represantives map contains only persons from valid signed MRPAs.
  std::for_each(representatives_.cbegin(), representatives_.cend(),
                [&res, &pers_info](const auto& pr_mrpa_persons) {
                  const auto& [mrpa_id, persons] = pr_mrpa_persons;
                  if (std::any_of(persons.cbegin(), persons.cend(),
                                  [pers_info](const PhysicalPerson& person) {
                                    return person == pers_info;
                                  })) {
                    res.push_back(mrpa_id);
                  };
                });
  return res;
}

/**
 * @brief Saves the list of MRPA IDs in a signature's mrpa_refs field
 *
 * @tparam AsigNode or SignNode
 * @param node TNode Attaced or Detached signature node
 */
template <typename TNode, std::enable_if_t<std::is_same_v<TNode, AsigNode> ||
                                             std::is_same_v<TNode, SigNode>,
                                           bool>>
void TreeContext::SaveRefsToMrpa(TNode& node) {
  if (!node.signer_person_info) {
    return;
  }
  node.mrpa_refs.clear();
  auto mrpa_ids = FindMrpaForSigner(node.signer_person_info.value());
  logger_->info("{} MRPA(s) found for signature {}", mrpa_ids.size(), node.id);
  // place references to MRPA objects
  for (auto mrpa_id : mrpa_ids) {
    if (lookup_tables_.mrpa_nodes.count(mrpa_id) > 0) {
      node.mrpa_refs.emplace(mrpa_id, lookup_tables_.mrpa_nodes.at(mrpa_id));
    }
  }
}

PtrSigCheckRes TreeContext::GetSigCeckResult(NodeId sig_node_id,
                                             NodeId file_node_id) noexcept {
  std::shared_lock lock(mtx_, std::defer_lock);
  constexpr const char* func_name = "[TreeContext::GetSigCeckResult] ";
  logger_->debug("{} signature id: {},file id: {}", func_name, sig_node_id,
                 file_node_id);
  if (!lock.try_lock()) {
    logger_->warn("{} context is busy, cancel", func_name);
    return {};
  }
  if (!root_) {
    logger_->warn("{} called with empty tree", func_name);
    return {};
  }
  auto sig_node = GetNode(sig_node_id);
  if (!sig_node ||
      (sig_node->type != NodeType::kSig && sig_node->type != NodeType::kAsig)) {
    logger_->error("{} Node {} was not found or not a signature node",
                   func_name, sig_node_id);
    return {};
  }
  // for detached signature
  if (sig_node->type == NodeType::kSig) {
    auto det_sig_node = std::static_pointer_cast<SigNode>(sig_node);
    if (det_sig_node->check_res.count(file_node_id) == 0 ||
        !det_sig_node->check_res.at(file_node_id)) {
      logger_->error("{} No result found for FileNode {}", func_name,
                     file_node_id);
      return {};
    }
    return det_sig_node->check_res.at(file_node_id);
  }
  // attached signature
  if (sig_node->type == NodeType::kAsig) {
    auto att_sig_node = std::static_pointer_cast<AsigNode>(sig_node);
    if (!att_sig_node->child_ || att_sig_node->child_->id != file_node_id ||
        !att_sig_node->check_res) {
      logger_->error("{} No result found for FileNode {}", func_name,
                     file_node_id);
      return {};
    }
    return att_sig_node->check_res;
  }
  return {};
}

}  // namespace mrpa