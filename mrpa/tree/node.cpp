#include "node.hpp"

#include <algorithm>
#include <filesystem>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <tuple>

#include "c_bridge.hpp"
#include "mrpa.hpp"
#include "pod_structs.hpp"
#include "tree/tree_context.hpp"
#include "tree/utils_tree.hpp"
#include "zip_cpp.hpp"

namespace mrpa {

FileNode::FileNode(std::string path, NodeType node_type, uint64_t node_id,
                   bool is_nested)
  : Node{node_type, node_id}, nested(is_nested), full_path(std::move(path)) {
  // create stat for a regular file
  if (!is_nested && std::filesystem::exists(full_path.value())) {
    const std::filesystem::path fpath(full_path.value());
    file_stat.name = fpath.filename();
    file_stat.size = std::filesystem::file_size(fpath);
    const auto sctp =
      std::chrono::time_point_cast<std::chrono::system_clock::duration>(
        std::filesystem::last_write_time(fpath) -
        std::filesystem::file_time_type::clock::now() +
        std::chrono::system_clock::now());
    file_stat.time_mod = std::chrono::system_clock::to_time_t(sctp);
  }
}

DirNode::DirNode(const std::string& path, NodeType node_type, uint64_t node_id,
                 bool is_nested)
  : FileNode(path, node_type, node_id, is_nested) {}

ZipNode::ZipNode(const std::string& path, NodeType node_type, uint64_t node_id,
                 bool is_nested)
  : FileNode(path, node_type, node_id, is_nested) {
  using FileEntry = zip_cpp::FileEntry;
  if (!is_nested) {
    zip = std::make_unique<zip_cpp::Zip>(path);
    VecChilds& childs_capture = childs;
    std::for_each(
      zip->cbegin(), zip->cend(), [&childs_capture](const FileEntry& entry) {
        std::cout << entry.stat().toString() << "\n\n";
        if (!entry.stat().encrypted) {
          auto unpacked_path = entry.readToTmp();
          if (!unpacked_path) {
            throw std::runtime_error("[ZipNode::ZipNode] unzip file failed");
          }
          childs_capture.emplace_back(
            createNodeFromFile(unpacked_path.value(), TreeContext::NextId()));
        } else {
          // TODO(Oleg) create node for encrypted file
          std::cerr << "[TODO!]\n";
        }
      });
  }
}

ZipNode::~ZipNode() {
  if (zip && !zip->removeTempDirs()) {
    std::cerr << "[ZipNode] remove temporary files failed\n";
  }
}

MrpaNode::MrpaNode(const std::string& path, NodeType node_type,
                   uint64_t node_id, bool is_nested)
  : FileNode(path, node_type, node_id, is_nested) {
  if (!is_nested) {
    mrpa = std::make_shared<Mrpa>(path);
  }
}

SigNode::SigNode(const std::string& path, NodeType node_type, uint64_t node_id,
                 bool is_nested)
  : FileNode(path, node_type, node_id, is_nested) {
  // TODO(Oleg) implement lookup for file and check signature
  // the signature can not be performed until an associated file is found
}

AsigNode::AsigNode(const std::string& path, NodeType node_type,
                   uint64_t node_id, bool is_nested)
  : FileNode(path, node_type, node_id, is_nested) {
  if (!nested && std::filesystem::exists(path)) {
    pdfcsp::c_bridge::CPodParam params{};
    params.sig_file_path = path.c_str();
    params.sig_file_path_size = path.size();
    params.file_path_size = path.size();
    check_res = PtrSigCheckRes(CheckSimpleAttached(params),
                               pdfcsp::c_bridge::CFreeResult);
  }
  // created child with FileNode
  std::string child_path = std::filesystem::path(path).stem().string();
  // std::cout << "CHILD_PATH:" << child_path << "\n";
  auto file_node = std::make_shared<FileNode>(
    std::move(child_path), NodeType::kFile, TreeContext::NextId(), true);
  file_node->parent_id = node_id;
  file_node->file_stat.name = file_node->full_path;
  child_ = std::move(file_node);
}

}  // namespace mrpa