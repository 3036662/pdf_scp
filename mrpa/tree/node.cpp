#include "node.hpp"

#include <algorithm>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <chrono>
#include <filesystem>
#include <iostream>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <tuple>

#include "c_bridge.hpp"
#include "mrpa.hpp"
#include "pod_structs.hpp"
#include "tree/tree_context.hpp"
#include "tree/utils_tree.hpp"
#include "zip_cpp.hpp"

namespace mrpa {

std::string ToString(NodeType type) {
  switch (type) {
    case NodeType::kRoot:
      return "Root";
    case NodeType::kAsig:
      return "Asig";
    case NodeType::kDir:
      return "Dir";
    case NodeType::kFile:
      return "File";
    case NodeType::kMrpa:
      return "Mrpa";
    case NodeType::kSig:
      return "Sig";
    case NodeType::kZip:
      return "Zip";
  }
}

std::string Node::ToString() const {
  std::ostringstream builder;
  builder << "type: " << mrpa::ToString(type) << "; id:" << id
          << "; refs number:" << refs.size();
  return builder.str();
}

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

[[nodiscard]] std::string FileNode::ToString() const {
  std::ostringstream builder;
  builder << Node::ToString();
  if (parent_id) {
    builder << "; parent_id = " << parent_id.value();
  }
  builder << "; nested: " << nested;
  if (full_path) {
    builder << "; full path:" << full_path.value();
  }
  builder << "; File stat:" << file_stat.toString();
  return builder.str();
}

DirNode::DirNode(const std::string& path, NodeType node_type, uint64_t node_id,
                 bool is_nested)
  : FileNode(path, node_type, node_id, is_nested) {}

ZipNode::ZipNode(const std::string& path, NodeType node_type, uint64_t node_id,
                 bool is_nested)
  : FileNode(path, node_type, node_id, is_nested) {
  using FileEntry = zip_cpp::FileEntry;
  if (!is_nested) {
    // open the archive
    zip = std::make_unique<zip_cpp::Zip>(path);
    // create an archive
    boost::uuids::random_generator gen;
    const boost::uuids::uuid uuid = gen();
    const auto random_uiid = boost::uuids::to_string(uuid);
    temp_dir = std::filesystem::temp_directory_path().string() + "/csppdf/" +
               std::to_string(node_id) + "_" + random_uiid;
    for (const FileEntry& entry : *zip) {
      // std::cout << entry.stat().toString() << "\n\n";
      if (!entry.stat().encrypted && !entry.isFolder()) {
        auto unpacked_path = entry.readToDir(temp_dir);
        if (!unpacked_path) {
          throw std::runtime_error("[ZipNode::ZipNode] unzip file failed");
        }
        auto created_node =
          NodeFromFileFactory(unpacked_path.value(), TreeContext::NextId());
        if (created_node) {
          childs.emplace_back(std::move(created_node));
        } else {
          std::cout << "ERROR CREATING NODE FOR PATH:"
                    << entry.stat().toString() << "\n";
        }
      }
      if (entry.stat().encrypted) {
        // TODO(Oleg) create node for encrypted file
        std::cerr << "[TODO!]\n";
      }
    }
  }
}

ZipNode::~ZipNode() {
  // std::cout << "[debug] ZipNode destructor removing temporary files\n";
  std::cerr << "TODO(Oleg) remove temporary files\n";
  if (!temp_dir.empty() && !std::filesystem::exists(temp_dir)) {
    std::ignore = std::filesystem::remove_all(temp_dir);
  }
}

std::string ZipNode::ToString() const {
  std::ostringstream builder;
  builder << FileNode::ToString() << " temp_dir:" << temp_dir
          << "; childs number:" << childs.size();
  return builder.str();
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