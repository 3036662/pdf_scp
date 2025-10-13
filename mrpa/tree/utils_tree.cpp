#include "utils_tree.hpp"

#include <algorithm>
#include <array>
#include <boost/algorithm/string/erase.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/json/object.hpp>
#include <boost/uuid/random_generator.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <exception>
#include <filesystem>
#include <iostream>
#include <iterator>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include "c_bridge.hpp"
#include "file_stat.hpp"
#include "mrpa.hpp"
#include "mrpa_typedefs.hpp"
#include "node.hpp"
#include "tree/tree_context.hpp"
#include "tree_defs.hpp"
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
    // put dir paths to vector ["dir1/dir2/dir3","dir1/dir2","dir1"]
    size_t iter_counter = 0;
    std::vector<std::string> dir_paths;
    while (fs_path.has_parent_path() && iter_counter < 1000) {
      fs_path = fs_path.parent_path();
      dir_paths.emplace_back(fs_path.string());
      ++iter_counter;
    }
    // the shortest path will be first
    // put dir paths to vector ["dir1","dir1/dir2","dir1/dir2/dir3"]
    std::reverse(dir_paths.begin(), dir_paths.end());
    // for each path from the shortest to the longest
    for (const std::string& curr_dir_path : dir_paths) {
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
          auto parent_dir_node = created_dirs.at(fs_curr_dir.parent_path());
          created_dir_node->parent_id = parent_dir_node->id;
          parent_dir_node->children.emplace_back(std::move(created_dir_node));
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

// NOLINTBEGIN(readability-function-cognitive-complexity)

/**
 * @brief Check signatures for one detached signature node
 * @param sig_node shared pointer
 * @details the results will be stored in sig_node->check_res
 */
void CheckOneSigNode(const std::shared_ptr<SigNode>& sig_node,
                     const std::shared_ptr<spdlog::logger>& logger) {
  if (!sig_node) {
    return;
  }
  const std::string sig_node_filepath = sig_node->full_path.value_or("");
  if (sig_node_filepath.empty() ||
      !std::filesystem::exists(sig_node_filepath)) {
    return;
  }
  if (logger) {
    logger->debug("[CheckOneSigNode] start signature check {}",
                  sig_node_filepath);
  }
  // remove expired refs
  for (auto it = sig_node->refs.begin(); it != sig_node->refs.end();) {
    if (it->second.expired()) {
      it = sig_node->refs.erase(it);
    } else {
      ++it;
    }
  }
  // save check result for each associated file
  for (const auto& ref_src_file : sig_node->refs) {
    const auto src_file =
      std::static_pointer_cast<FileNode>(ref_src_file.second.lock());
    const std::string src_file_pathpath = src_file->full_path.value_or("");
    if (sig_node->check_res.count(src_file->id) == 0 && !src_file->embedded &&
        !src_file_pathpath.empty() &&
        std::filesystem::exists(src_file_pathpath)) {
      pdfcsp::c_bridge::CPodParam params{};
      params.sig_file_path = sig_node_filepath.c_str();
      params.sig_file_path_size = sig_node_filepath.size();
      params.file_path = src_file_pathpath.c_str();
      params.file_path_size = src_file_pathpath.size();
      auto check_res =
        PtrSigCheckRes(pdfcsp::c_bridge::CheckSimpleDetached(params),
                       pdfcsp::c_bridge::CFreeResult);
      if (!check_res && logger) {
        logger->error("[CheckOneSigNode] check signature failed for {}",
                      sig_node->full_path.value_or(""));
      }
      if (check_res) {
        sig_node->check_res.insert_or_assign(src_file->id,
                                             std::move(check_res));
      }
    }
  }
  // if we have more than 1 associated file for this signature
  // like file.sig -> file.xml , file.doc
  // Remove associations with bad check status; consider these associations
  // were made by mistake.
  if (sig_node->refs.size() > 1) {
    for (auto it = sig_node->refs.begin(); it != sig_node->refs.cend();) {
      // if no result for the file or result is bad
      const bool to_be_removed =
        sig_node->check_res.count(it->first) == 0 ||
        !sig_node->check_res.at(it->first)->bres.check_summary ||
        it->second.expired();
      // remove the reference and the check result for this node
      if (to_be_removed) {
        sig_node->check_res.erase(sig_node->check_res.find(it->first));
        it = sig_node->refs.erase(it);
        continue;
      }
      ++it;
    }
  }
  // Now when the signature has a connection to the file, we need to add a
  // connection file -> signature.
  for (const auto& file_ref : sig_node->refs) {
    if (file_ref.second.expired()) {
      continue;
    }
    const auto file_node =
      std::static_pointer_cast<FileNode>(file_ref.second.lock());
    // if a file has no reference to this signature
    // and the signature has check result for this file
    if (file_node->refs.count(sig_node->id) == 0 &&
        sig_node->check_res.count(file_node->id) > 0 &&
        sig_node->check_res.at(file_node->id) != nullptr) {
      file_node->refs.emplace(sig_node->id, sig_node->weak_from_this());
    }
  }
}

// NOLINTEND(readability-function-cognitive-complexity)

/**
 * @brief Check one attached signature node
 * @param sig_node shared pointer
 * @details the results will be stored in sig_node->check_res
 */
void CheckOneAttachedSigNode(const std::shared_ptr<AsigNode>& sig_node) {
  if (!sig_node || sig_node->check_res != nullptr) {
    return;
  }
  const std::string sig_node_filepath = sig_node->full_path.value_or("");
  if (sig_node_filepath.empty() ||
      !std::filesystem::exists(sig_node_filepath)) {
    return;
  }
  pdfcsp::c_bridge::CPodParam params{};
  params.sig_file_path = sig_node_filepath.c_str();
  params.sig_file_path_size = sig_node_filepath.size();
  sig_node->check_res =
    PtrSigCheckRes(CheckSimpleAttached(params), pdfcsp::c_bridge::CFreeResult);
  if (sig_node->check_res && sig_node->child_) {
    sig_node->child_->refs.emplace(sig_node->id, sig_node->weak_from_this());
    sig_node->refs.emplace(sig_node->child_->id,
                           sig_node->child_->weak_from_this());
  }
}

void BindOneMrpaSigners(const std::shared_ptr<MrpaNode>& mrpa_node,
                        const std::shared_ptr<spdlog::logger>& logger) {
  if (!mrpa_node) {
    return;
  }
  // register connection that should be removed
  std::vector<NodeId> refs_to_be_removed;
  // for each connection [mrpa => signature]
  for (const auto& [ref_id, rew_wp] : mrpa_node->refs) {
    // remove if expired
    if (rew_wp.expired()) {
      refs_to_be_removed.emplace_back(ref_id);
      continue;
    }
    auto ref_node = rew_wp.lock();
    if (!ref_node || ref_node->type != NodeType::kSig) {
      continue;
    }
    auto sig_node = std::static_pointer_cast<SigNode>(ref_node);
    // if no check result for this MRPA in signature, break the connection
    if (sig_node->check_res.count(mrpa_node->id) == 0) {
      refs_to_be_removed.emplace_back(sig_node->id);
      if (logger) {
        logger->debug(
          "MRPA {} connection to sig will be removed, no check result in sig "
          "{}",
          mrpa_node->id, sig_node->id);
      }
    }
    // if signature check failed or signer person is invalid, break the
    // connection
    else {
      mrpa_node->mrpa->setSignature(sig_node->check_res.at(mrpa_node->id));
      if (!mrpa_node->mrpa->IsValidSignature()) {
        refs_to_be_removed.emplace_back(sig_node->id);
        if (logger) {
          logger->debug(
            "MRPA {} connection to sig will be removed, bad check status or "
            "invalid signer {}",
            mrpa_node->id, sig_node->id);
        }
      }
    }
  }
  // remove connections [mrpa => signature] if they are invalid
  std::for_each(
    refs_to_be_removed.cbegin(), refs_to_be_removed.cend(),
    [&mrpa_node](const auto ref_id) { mrpa_node->refs.erase(ref_id); });
}

bool IsDestinationDirOK(const std::string& dest) noexcept {
  try {
    const std::filesystem::path pdest(dest);
    if (pdest.empty() || pdest.is_relative() ||
        !std::filesystem::exists(pdest) ||
        !std::filesystem::is_directory(pdest)) {
      return false;
    }
    return access(dest.c_str(), W_OK) == 0;
  } catch (const std::exception&) {
    return false;
  }
}

bool AreSettingsOK(const BatchSignatureSettings& settings) {
  return settings.cert_serial != nullptr && settings.cert_serial[0] != 0x00 &&
         settings.cert_subject != nullptr && settings.cert_subject[0] != 0x00 &&
         settings.cades_type != nullptr && settings.cades_type[0] != 0x00 &&
         settings.sig_extension != nullptr &&
         settings.sig_extension[0] != 0x00 &&
         settings.dest_dir_path != nullptr && settings.dest_dir_path[0] != 0x00;
}

/**
 * @brief Create a Signing Skip List
 * @param nodes
 * @details We dont need to sign an MRPA (if it is already signed);
 * place the MRPA path and it's signature path to the skip list.
 * Also find MRPAs in top - level archives
 * @return std::unordered_set<std::string> list of paths
 */
std::unordered_set<std::string> CreateSigningSkipList(const VecNodes& nodes) {
  std::unordered_set<std::string> res;
  std::for_each(nodes.cbegin(), nodes.cend(), [&res](const PtrNode& node) {
    // add archived MRPAs from top-level zips
    if (node && node->type == NodeType::kZip && node->parent_id == 0) {
      const auto zip_node = std::static_pointer_cast<ZipNode>(node);
      auto zipped_mrpa = CreateSigningSkipList(zip_node->children);
      // if a zip contains only MRPAs - put a zip itself to the skip list
      if (zip_node->children.size() == zipped_mrpa.size()) {
        res.emplace(zip_node->full_path.value_or(""));
      }
      // put the MRPA and it's signature to the skip list
      else {
        std::for_each(zipped_mrpa.begin(), zipped_mrpa.end(),
                      [&res](auto& path) { res.emplace(std::move(path)); });
      }
    }
    if (!node || node->type != NodeType::kMrpa) {
      return;
    }
    // for each MRPA node
    auto mrpa_node = std::static_pointer_cast<MrpaNode>(node);
    // skip unsigned MRPA
    if (mrpa_node->refs.empty() || !mrpa_node->full_path ||
        mrpa_node->full_path->empty()) {
      return;
    }
    // save signature file path to the result
    for (const auto& [sig_id, wp_sig] : mrpa_node->refs) {
      if (wp_sig.expired()) {
        continue;
      }
      const auto sig_node = std::static_pointer_cast<FileNode>(wp_sig.lock());
      if (!sig_node || !sig_node->full_path || sig_node->full_path->empty() ||
          sig_node->file_stat.encrypted) {
        continue;
      }
      res.emplace(sig_node->full_path.value());
    }
    // place the mrpa itself to the result
    if (!res.empty()) {
      res.emplace(mrpa_node->full_path.value());
    }
  });
  return res;
}

std::unordered_set<std::string> CreateMrpaToSignList(const VecNodes& nodes) {
  std::unordered_set<std::string> res;
  std::for_each(nodes.cbegin(), nodes.cend(), [&res](const PtrNode& node) {
    if (!node || node->type != NodeType::kMrpa) {
      return;
    }
    // for each MRPA node
    auto mrpa_node = std::static_pointer_cast<MrpaNode>(node);
    //  skip all signed MRPAs
    if (!mrpa_node->refs.empty() || !mrpa_node->full_path ||
        mrpa_node->full_path->empty()) {
      return;
    }
    res.emplace(mrpa_node->full_path.value_or(""));
  });
  return res;
}

std::string CreateTempDirInDest(const std::string& dest_dir) {
  // create an unique temporary folder
  bool directory_exists = true;
  boost::uuids::random_generator gen;
  std::string res;
  while (directory_exists) {
    const boost::uuids::uuid uuid = gen();
    const auto random_uiid = boost::uuids::to_string(uuid);
    std::string temp_dir = dest_dir;
    if (!boost::ends_with(temp_dir, "/")) {
      temp_dir += "/";
    }
    temp_dir += random_uiid;
    directory_exists = std::filesystem::exists(temp_dir);
    if (!directory_exists) {
      res = std::move(temp_dir);
    }
  }
  std::filesystem::create_directories(res);
  res += "/";
  return res;
}

/**
 * @brief Create a vector CPodParam structure object
 * @param src_dest a map created by @see CreateSrcToDestPathsForSigning
 * @param setting @see BatchSignatureSettings
 * @return std::vector<CPodParam>
 * @details this function is supposed to be called from TreeContext::SignTree
 * to help creating a list of task for CSP library
 */
std::vector<CPodParam> CreateVecCPodParams(
  const MapDestPaths& src_to_dest, const BatchSignatureSettings& settings,
  const std::unordered_set<std::string>& mrpa_to_sign) {
  std::vector<CPodParam> vec_params;
  // Create a CPodParam structure for each file
  std::for_each(
    src_to_dest.cbegin(), src_to_dest.cend(),
    [&vec_params, &settings, &mrpa_to_sign](const auto& pr_src_des) {
      const auto& src_path = pr_src_des.first;
      const DestFilePaths& dest_path = pr_src_des.second;
      vec_params.push_back({});
      CPodParam& param = vec_params.back();
      param.command = kSignIpcCommand;
      param.command_size = 21;
      param.file_path = src_path.c_str();
      param.file_path_size = src_path.size();
      param.cert_serial = settings.cert_serial;
      param.cert_subject = settings.cert_subject;
      param.cades_type = settings.cades_type;
      param.tsp_link = settings.tsp_link;
      param.sig_file_path = dest_path.sig_dest.c_str();
      param.sig_file_path_size = dest_path.sig_dest.size();
      param.create_attached = settings.create_attached;
      param.create_base_64_encoded = settings.create_base_64_encoded;
      // an MRPA file must always be signed with detached signature
      if (mrpa_to_sign.count(src_path) > 0) {
        std::cout << "CREATE DETACHED\n";
        param.create_attached = false;
        param.create_base_64_encoded = false;
      }
    });
  return vec_params;
}

/**
 * @brief Create a vector of pointers, aka CPodParam*.
 * @param tasks created by @see CreateVecCPodParams
 * @return std::vector<CPodParam*>
 */
std::vector<const CPodParam*> TransformToVectorOfPointers(
  const std::vector<CPodParam>& tasks) {
  std::vector<const CPodParam*> res;
  res.reserve(tasks.size());
  std::transform(tasks.cbegin(), tasks.cend(), std::back_inserter(res),
                 [](const auto& task) { return &task; });
  return res;
}

bool AllTasksOK(const UniquePtrTaskBatchResult& res, size_t tasks_count) {
  return res && res->results_size == tasks_count &&
         std::all_of(res->results, res->results + res->results_size,
                     [](const CPodResult* p_one_res) {
                       return p_one_res && p_one_res->common_execution_status;
                     });
}

void ChangeFilePrefix(std::string& fname, uint64_t prefix_old,
                      uint64_t prefix_new) {
  // remove old prefix
  const std::filesystem::path fpath = std::filesystem::path(fname);
  std::string filename_updated = fpath.parent_path().string();
  filename_updated += "/";
  std::string base_filename = fpath.filename().string();
  if (prefix_old > 0) {
    boost::erase_first(base_filename, std::to_string(prefix_old));
  } else {
    base_filename.insert(0, "_");
  }
  base_filename.insert(0, std::to_string(prefix_new));
  filename_updated += base_filename;
  fname = std::move(filename_updated);
}

std::optional<std::string> PackAllToOneZip(
  const std::string& dest_dir, const MapDestPaths& dest_paths, bool attached,
  const MapStringString& mrpa_dest_paths) {
  boost::uuids::random_generator gen;
  const boost::uuids::uuid uuid = gen();
  const auto random_uiid = boost::uuids::to_string(uuid);
  std::string res_path = dest_dir + random_uiid + ".zip";
  zip_cpp::ZipCreator zip_creator(res_path);
  size_t success_counter = 0;
  for (const auto& [_, dest] : dest_paths) {
    // push a signature; if a signature is detached - push a source file too
    if (zip_creator.push_file(dest.sig_dest) &&
        (attached || zip_creator.push_file(dest.src_dest))) {
      ++success_counter;
    }
  }
  for (const auto& [_, dest] : mrpa_dest_paths) {
    if (zip_creator.push_file(dest)) {
      ++success_counter;
    }
  }
  // if all files are successfully pushed to the result ZIP, return a path to
  // file
  if (zip_creator.commit() &&
      (success_counter == dest_paths.size() + mrpa_dest_paths.size())) {
    return res_path;
  }
  return std::nullopt;
}

std::optional<VecStrings> PackToSeparateZips(
  const std::string& dest_dir, const MapDestPaths& dest_paths, bool attached,
  const MapStringString& mrpa_dest_paths) {
  VecStrings res;
  for (const auto& [_, dest] : dest_paths) {
    std::string dest_zip =
      dest_dir + std::filesystem::path(dest.src_dest).filename().string() +
      ".zip";
    zip_cpp::ZipCreator zip_creator(dest_zip);
    const bool push_files_ok =
      zip_creator.push_file(dest.sig_dest) &&
      (attached || zip_creator.push_file(dest.src_dest));
    const bool push_mrpas_ok =
      std::all_of(mrpa_dest_paths.cbegin(), mrpa_dest_paths.cend(),
                  [&zip_creator](const auto& mrpa_dest) {
                    return zip_creator.push_file(mrpa_dest.second);
                  });
    if (push_files_ok && push_mrpas_ok && zip_creator.commit()) {
      res.emplace_back(std::move(dest_zip));
    }
  }
  if (res.size() == dest_paths.size()) {
    return res;
  }
  return std::nullopt;
}

ZipPackResults PackToZip(const BatchSignatureSettings& settings,
                         const MapDestPaths& src_to_dest,
                         const MapStringString& src_dest_skip_list) {
  ZipPackResults res;
  res.zip_tmp_dir = CreateTempDirInDest(settings.dest_dir_path);
  try {
    if (settings.pack_separate_zips) {
      auto result_zip_list =
        PackToSeparateZips(res.zip_tmp_dir, src_to_dest,
                           settings.create_attached, src_dest_skip_list);
      if (result_zip_list.has_value()) {
        res.paths = std::move(result_zip_list.value());
      }
    } else {
      auto result_zip_path =
        PackAllToOneZip(res.zip_tmp_dir, src_to_dest, settings.create_attached,
                        src_dest_skip_list);
      if (result_zip_path) {
        res.paths.emplace_back(std::move(result_zip_path.value()));
      }
    }
  } catch (const std::exception& ex) {
    std::ignore = std::filesystem::remove_all(res.zip_tmp_dir);
    throw;
  }
  return res;
}

}  // namespace mrpa
