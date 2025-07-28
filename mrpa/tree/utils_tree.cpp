#include "utils_tree.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <exception>
#include <filesystem>
#include <iostream>
#include <memory>
#include <string_view>
#include <tuple>

#include "c_bridge.hpp"
#include "file_stat.hpp"
#include "mrpa.hpp"
#include "node.hpp"
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
#ifdef TEST_BUILD
  std::cout << "[Debug][NodeFromFileFactory] create node OK:"
            << result_node->ToString() << "\n";
#endif

  return result_node;
}

// NOLINTBEGIN

/**
 * @brief Normalize node pathes
 *
 * @param vec_nodes
 * @return VecNodes normalized
 * @details If a node has a path looking like dir1/dir2/file.txt,
 * It will be normalized to the dir1 -> dir2 -> file.txt node tree.
 */
VecNodes NormalizeNodeDirs(VecNodes&& vec_nodes) {
  // TODO(Oleg) normalize the nodes
  return vec_nodes;
};

// NOLINTEND

// VecNodes childs_with_dirs;
// std::unordered_map<std::string, PtrNode> created_dirs;
// std::for_each(
//   children.cbegin(), children.cend(),
//   [&childs_with_dirs, &created_dirs](const PtrNode& child) {
//     if (!child) {
//       return;
//     }
//     auto child_file = std::static_pointer_cast<FileNode>(child);
//     std::string child_stat_name = child_file->file_stat.name.value_or("");
//     if (child_stat_name.empty()) {
//       return;
//     }
//     // remove first "/" if exists
//     if (child_stat_name.front() == '/') {
//       child_stat_name.erase(0, 1);
//     }
//     std::cout << "CHILD STAT NAME: " << child_stat_name << "\n";
//     std::cout << "CHILD FULL INFO: " << child_file->ToString() << "\n\n";
//     // dirs to be created
//     std::vector<std::string> dirs;
//     boost::split(
//       dirs, child_stat_name, [](char symbol) { return symbol == '/'; },
//       boost::algorithm::token_compress_on);
//     dirs.pop_back();
//     std::cout << "dirs to be created:\n";
//     // for each dir starting with most outer
//     for (size_t i = 0; i < dirs.size(); ++i) {
//       std::cout << "DIR:" << dirs[i] << "\n";
//       PtrNode dir;
//       std::string key =
//         std::accumulate(dirs.cbegin(), dirs.cbegin() + i + 1, std::string(),
//                         [](const std::string& init, const std::string val) {
//                           std::string res;
//                           res.reserve(init.size() + val.size() + 1);
//                           res += init;
//                           if (!res.empty()) {
//                             res += "/";
//                           }
//                           res += val;
//                           return res;
//                         });
//       std::cout << "KEY:" << key << "\n";
//       if (created_dirs.count(key) == 0) {
//         created_dirs[key] = std::make_shared<DirNode>(
//           key, NodeType::kDir, TreeContext::NextId(), false);
//         std::cout << "CREATED DIR NODE:" << created_dirs[key]->ToString()
//                   << "\n";
//       }
//     }
//   });

}  // namespace mrpa
