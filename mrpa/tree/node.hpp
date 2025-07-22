#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <vector>

#include "c_bridge.hpp"
#include "file_stat.hpp"
#include "pod_structs.hpp"

namespace mrpa {

/// @brief each node knows it's type
enum class NodeType : uint8_t {
  kRoot,  // the top node
  kFile,  // simple file
  kSig,   // detached signature
  kAsig,  // attached signature
  kMrpa,  // MRPA node
  kZip,   // a zip archive
  kDir    // a directory
};

using CPodResult = pdfcsp::c_bridge::CPodResult;
using PtrSigCheckRes = std::shared_ptr<CPodResult>;

struct Node;

// owning refs
using PtrNode = std::shared_ptr<Node>;
using VecChilds = std::vector<PtrNode>;
// non owning reds
using PtrAssocNode = std::weak_ptr<Node>;
using VecRefs = std::vector<PtrAssocNode>;

/**
 * @brief Basic tree node
 */
struct Node {
  NodeType type = NodeType::kFile;
  uint64_t id = 0;
  VecRefs refs;  // non owning references to othe nodes

  Node(NodeType node_type, uint64_t node_id) : type{node_type}, id{node_id} {};
};

/// @brief simple file
struct FileNode : public Node {
  zip_cpp::FileStat file_stat;
  bool nested = false;
  std::optional<std::string> full_path;
  std::optional<uint64_t> parent_id;

  FileNode(std::string path, NodeType node_type, uint64_t node_id,
           bool is_nested);
};

struct DirNode : public FileNode {
  VecChilds childs;
  DirNode(const std::string& path, NodeType node_type, uint64_t node_id,
          bool is_nested);
};

/// @brief zip archive
struct ZipNode : public FileNode {
  VecChilds chids;
  ZipNode(const std::string& path, NodeType node_type, uint64_t node_id,
          bool is_nested);
};

/// @mrpa MRPA node
struct MrpaNode : public FileNode {
  MrpaNode(const std::string& path, NodeType node_type, uint64_t node_id,
           bool is_nested);
};

/// @brief detached signature
struct SigNode : public FileNode {
  PtrSigCheckRes check_res = nullptr;
  SigNode(const std::string& path, NodeType node_type, uint64_t node_id,
          bool is_nested);
};

/// @brief attached signature
/// @details owns one child
struct AsigNode : public FileNode {
  PtrSigCheckRes check_res = nullptr;
  PtrNode child_;
  AsigNode(const std::string& path, NodeType node_type, uint64_t node_id,
           bool is_nested);
};

/// struct SigNode:public

}  // namespace mrpa