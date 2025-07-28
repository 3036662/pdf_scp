#include "node.hpp"

#include <algorithm>
#include <boost/algorithm/string/join.hpp>
#include <boost/algorithm/string/split.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <chrono>
#include <cstddef>
#include <filesystem>
#include <iostream>
#include <memory>
#include <numeric>
#include <sstream>
#include <stdexcept>
#include <string>
#include <tuple>
#include <vector>

#include "mrpa.hpp"
#include "mrpa_typedefs.hpp"
#include "tree/tree_context.hpp"
#include "tree/utils_tree.hpp"
#include "tree/visitor.hpp"
#include "zip_cpp.hpp"

namespace mrpa {

// -------------------------------------------------------------
// accept visitor

void FileNode::AcceptVisitor(Visitor& visitor) { visitor.Visit(*this); }

void MrpaNode::AcceptVisitor(Visitor& visitor) { visitor.Visit(*this); }

void SigNode::AcceptVisitor(Visitor& visitor) { visitor.Visit(*this); }

void AsigNode::AcceptVisitor(Visitor& visitor) {
  visitor.Visit(*this);
  if (child_) {
    child_->AcceptVisitor(visitor);
  }
}

void DirNode::AcceptVisitor(Visitor& visitor) {
  visitor.Visit(*this);
  std::for_each(children.begin(), children.end(),
                [&visitor](const PtrNode& child_node) {
                  child_node->AcceptVisitor(visitor);
                });
}

void ZipNode::AcceptVisitor(Visitor& visitor) {
  visitor.Visit(*this);
  std::for_each(children.begin(), children.end(),
                [&visitor](const PtrNode& child_node) {
                  child_node->AcceptVisitor(visitor);
                });
}

// -------------------------------------------------------------
// to string

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

std::string NodeBase::ToString() const {
  std::ostringstream builder;
  builder << "type: " << mrpa::ToString(type) << "; id:" << id
          << "; refs number:" << refs.size();
  return builder.str();
}

[[nodiscard]] std::string FileNode::ToString() const {
  std::ostringstream builder;
  builder << NodeBase::ToString();
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

std::string ZipNode::ToString() const {
  std::ostringstream builder;
  builder << FileNode::ToString() << " temp_dir:" << temp_dir
          << "; number of children:" << children.size();
  return builder.str();
}

// -------------------------------------------------------------

FileNode::FileNode(std::string path, NodeType node_type, uint64_t node_id,
                   bool is_nested)
  : NodeBase{node_type, node_id},
    nested(is_nested),
    full_path(std::move(path)) {
  // create stat for a regular file
  if (!is_nested && std::filesystem::exists(full_path.value()) &&
      std::filesystem::is_regular_file(full_path.value())) {
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

/// @brief unpacks zip archive to a temprorary directory and creates nodes for
/// all files
ZipNode::ZipNode(const std::string& path, NodeType node_type, uint64_t node_id,
                 bool is_nested)
  : FileNode(path, node_type, node_id, is_nested) {
  using FileEntry = zip_cpp::FileEntry;
  if (is_nested) {
    return;
  }
  // open the archive
  zip = std::make_unique<zip_cpp::Zip>(path);
  // create an unique temporary folder
  boost::uuids::random_generator gen;
  const boost::uuids::uuid uuid = gen();
  const auto random_uiid = boost::uuids::to_string(uuid);
  temp_dir = std::filesystem::temp_directory_path().string() + "/csppdf/" +
             std::to_string(node_id) + "_" + random_uiid;
  // unzip every node if not encrypted
  for (const FileEntry& entry : *zip) {
    if (!entry.stat().encrypted && !entry.isFolder()) {
      auto unpacked_path = entry.readToDir(temp_dir);
      if (!unpacked_path) {
        throw std::runtime_error("[ZipNode::ZipNode] unzip file failed");
      }
      auto created_node =
        NodeFromFileFactory(unpacked_path.value(), TreeContext::NextId());
      if (created_node) {
        created_node->parent_id = node_id;
        // use the original stat info from the Zip entry
        std::static_pointer_cast<FileNode>(created_node)->file_stat =
          entry.stat();
        children.emplace_back(std::move(created_node));
      }
    }
    // if current entry is ecnctypted create just a FileNode
    if (entry.stat().encrypted) {
      // path_to_archive/encrypted_file.bin
      std::string file_virtual_full_path =
        path + "/" + entry.stat().name.value_or("");
      auto file_node = std::make_shared<FileNode>(
        std::move(file_virtual_full_path), NodeType::kFile,
        TreeContext::NextId(), true);
      file_node->parent_id = node_id;
      file_node->file_stat = entry.stat();
      children.emplace_back(std::move(file_node));
    }
  }
  children = NormalizeNodeDirs(std::move(children));
}

ZipNode::~ZipNode() {
  if (!temp_dir.empty() && std::filesystem::exists(temp_dir)) {
    std::ignore = std::filesystem::remove_all(temp_dir);
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
  : FileNode(path, node_type, node_id, is_nested) {}

AsigNode::AsigNode(const std::string& path, NodeType node_type,
                   uint64_t node_id, bool is_nested)
  : FileNode(path, node_type, node_id, is_nested) {
  // if (!nested && std::filesystem::exists(path)) {
  //   pdfcsp::c_bridge::CPodParam params{};
  //   params.sig_file_path = path.c_str();
  //   params.sig_file_path_size = path.size();
  //   params.file_path_size = path.size();
  //   check_res = PtrSigCheckRes(CheckSimpleAttached(params),
  //                              pdfcsp::c_bridge::CFreeResult);
  // }
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