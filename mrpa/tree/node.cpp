#include "node.hpp"

#include <filesystem>
#include <iostream>
#include <memory>

#include "c_bridge.hpp"
#include "mrpa.hpp"
#include "pod_structs.hpp"
#include "tree/tree_context.hpp"

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
  : FileNode(path, node_type, node_id, is_nested) {}

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