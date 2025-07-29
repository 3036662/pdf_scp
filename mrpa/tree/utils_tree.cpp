#include "utils_tree.hpp"

#include <algorithm>
#include <array>
#include <boost/json/object.hpp>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <filesystem>
#include <iostream>
#include <iterator>
#include <memory>
#include <string_view>
#include <tuple>
#include <unordered_map>
#include <unordered_set>

#include "c_bridge.hpp"
#include "file_stat.hpp"
#include "mrpa.hpp"
#include "mrpa_typedefs.hpp"
#include "node.hpp"
#include "tree/tree_context.hpp"
#include "zip_cpp.hpp"

namespace mrpa {

namespace {
constexpr std::array<std::string_view, 5> possible_sig_ext{
  ".sign", ".sig", ".sgn", ".p7s", ".bin"};

constexpr std::string_view kPossibleMrpaExt = ".xml";
constexpr std::string_view kPossibleArchiveExt = ".zip";

/// 0 - detached, 1 - attached, -1 parse error(not a signature)
int IfSigAttached(const std::string& path) {
  const std::string ext = std::filesystem::path(path).extension().string();
  const bool ext_not_supported = std::none_of(
    possible_sig_ext.cbegin(), possible_sig_ext.cend(),
    [&ext](const auto& allowed_ext) { return allowed_ext == ext; });
  if (ext_not_supported) {
    return -1;
  }
  pdfcsp::c_bridge::SeparateSignatureParams cparams{};
  cparams.sig_file_path = path.c_str();
  cparams.sig_file_path_size = path.size();
  return pdfcsp::c_bridge::IsMessageAttached(&cparams);
}

bool isValidZip(const std::string& path) {
  const std::string ext = std::filesystem::path(path).extension().string();
  if (ext != kPossibleArchiveExt) {
    return false;
  }
  try {
    const zip_cpp::Zip zip{path};
  } catch (const std::exception&) {
    return false;
  }
  return true;
}

bool isValidMrpa(const std::string& path) {
  const std::string ext = std::filesystem::path(path).extension().string();
  if (ext != kPossibleMrpaExt) {
    return false;
  }
  return Mrpa(path).IsValid();
}

}  // namespace

/**
 * @brief Create a Node from file
 *
 * @param path path to file
 * @param node_id node_id (@see TreeContext::NextId())
 * @return PtrNode or null for Folder, folders are ignored
 * @throws runtime_error propagated from Node constructors
 * @details can be run recursively by the ZipNode object to create child nodes
 */
PtrNode NodeFromFileFactory(const std::string& path, uint64_t node_id) {
  if (path.empty() || !std::filesystem::exists(path) ||
      !std::filesystem::is_regular_file(path)) {
    return nullptr;
  }
  // determine the file type: File,Sig,Asig,Zip
  PtrNode result_node;
  const int sig_flag = IfSigAttached(path);
  // detached message
  if (sig_flag == 0) {
    result_node =
      std::make_shared<SigNode>(path, NodeType::kSig, node_id, false);
    result_node->type = NodeType::kSig;
  }
  // an attached message
  else if (sig_flag == 1) {
    result_node =
      std::make_shared<AsigNode>(path, NodeType::kAsig, node_id, false);
    result_node->type = NodeType::kAsig;
  }
  // zip file
  else if (isValidZip(path)) {
    result_node =
      std::make_shared<ZipNode>(path, NodeType::kZip, node_id, false);
    result_node->type = NodeType::kZip;
  }
  // mrpa file
  else if (isValidMrpa(path)) {
    result_node =
      std::make_shared<MrpaNode>(path, NodeType::kZip, node_id, false);
    result_node->type = NodeType::kMrpa;
  }
  // regular file
  else {
    result_node =
      std::make_shared<FileNode>(path, NodeType::kFile, node_id, false);
  }
  return result_node;
}

/**
 * @brief Normalize node paths
 *
 * @param vec_nodes
 * @return VecNodes normalized
 * @details If a node has a path looking like dir1/dir2/file.txt,
 * It will be normalized to the dir1 -> dir2 -> file.txt node tree.
 */
VecNodes NormalizeNodeDirs(VecNodes vec_nodes) {
  if (vec_nodes.empty()) {
    return vec_nodes;
  }
  std::unordered_map<std::string, std::shared_ptr<DirNode>> created_dirs;
  std::unordered_set<std::string> nested_dirs;
  for (PtrNode& node : vec_nodes) {
    const std::string node_path =
      std::static_pointer_cast<FileNode>(node)->file_stat.name.value_or("");
    std::filesystem::path fs_path(node_path);
    if (!fs_path.has_parent_path()) {
      continue;
    }
    // most nested dir for the current file (dir1/dir2/dir3)
    const auto curr_node_parent = fs_path.parent_path().string();
    // current file name ( filename.ext )
    const auto curr_node_filename = fs_path.filename().string();
    // put dir pathes to vector ["dir1/dir2/dir3","dir1/dir2","dir1"]
    size_t iter_counter = 0;
    std::vector<std::string> dir_pathes;
    while (fs_path.has_parent_path() && iter_counter < 1000) {
      fs_path = fs_path.parent_path();
      dir_pathes.emplace_back(fs_path.string());
      ++iter_counter;
    }
    // the shortest path will be first
    // put dir pathes to vector ["dir1","dir1/dir2","dir1/dir2/dir3"]
    std::reverse(dir_pathes.begin(), dir_pathes.end());
    // for each path from the shortest to the longest
    for (const std::string& curr_dir_path : dir_pathes) {
      // create current dir node if not exists
      if (created_dirs.count(curr_dir_path) == 0) {
        auto created_dir_node = std::make_shared<DirNode>(
          curr_dir_path, NodeType::kDir, TreeContext::NextId(), false);
        created_dirs[curr_dir_path] = created_dir_node;
        // if current node is nested add it to the parent's children
        const std::filesystem::path fs_curr_dir(curr_dir_path);
        created_dir_node->file_stat.name = fs_curr_dir.filename();
        if (fs_curr_dir.has_parent_path() &&
            created_dirs.count(fs_curr_dir.parent_path()) != 0) {
          auto parrent_dir_node = created_dirs.at(fs_curr_dir.parent_path());
          created_dir_node->parent_id = parrent_dir_node->id;
          parrent_dir_node->children.emplace_back(std::move(created_dir_node));
          // register the current dir as nested directory
          nested_dirs.emplace(curr_dir_path);
        }
      }
    }
    // now all directories are created as DirNodes
    // it is time to move the file_node to the most nested dir
    if (created_dirs.count(curr_node_parent) != 0) {
      std::static_pointer_cast<FileNode>(node)->file_stat.name =
        curr_node_filename;
      // move the current node to it's parent
      node->parent_id = created_dirs.at(curr_node_parent)->id;
      created_dirs.at(curr_node_parent)->children.emplace_back(std::move(node));
      node.reset();  // just to be sure
    }
  }
  // all nested dirs and file nodes now are owned by their parents
  VecNodes result;
  // first copy nodes that was not moved
  std::copy_if(vec_nodes.cbegin(), vec_nodes.cend(), std::back_inserter(result),
               [](const PtrNode& node) { return node != nullptr; });
  // than copy DirNodes that are not nested to other dirs
  std::for_each(created_dirs.cbegin(), created_dirs.cend(),
                [&nested_dirs, &result](const auto& pr_created_dir) {
                  if (nested_dirs.count(pr_created_dir.first) == 0) {
                    result.emplace_back(pr_created_dir.second);
                  }
                });
  return result;
};

}  // namespace mrpa
