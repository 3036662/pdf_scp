#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <vector>

#include "file_stat.hpp"
#include "mrpa.hpp"
#include "pod_structs.hpp"
#include "zip_cpp.hpp"

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

std::string ToString(NodeType type);

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
  std::optional<uint64_t> parent_id;

  Node(NodeType node_type, uint64_t node_id) : type{node_type}, id{node_id} {};
  Node(Node&&) noexcept = default;
  Node& operator=(Node&&) noexcept = default;

  Node() = delete;
  Node(const Node&) = delete;
  Node& operator=(const Node&) = delete;

  [[nodiscard]] virtual std::string ToString() const;

  virtual ~Node() = default;
};

/// @brief simple file
struct FileNode : public Node {
  zip_cpp::FileStat file_stat;
  bool nested = false;  // neseted whithin the an encrypted zip or asig
  std::optional<std::string> full_path;

  FileNode(std::string path, NodeType node_type, uint64_t node_id,
           bool is_nested);
  [[nodiscard]] std::string ToString() const override;
};

struct DirNode : public FileNode {
  VecChilds childs;
  DirNode(const std::string& path, NodeType node_type, uint64_t node_id,
          bool is_nested);
};

/// @brief zip archive
struct ZipNode : public FileNode {
  VecChilds childs;
  std::string temp_dir;

  std::unique_ptr<zip_cpp::Zip> zip;
  ZipNode(const ZipNode&) = delete;
  ZipNode(ZipNode&&) noexcept = default;
  ZipNode& operator=(const ZipNode&) = delete;
  ZipNode& operator=(ZipNode&&) noexcept = delete;

  ZipNode(const std::string& path, NodeType node_type, uint64_t node_id,
          bool is_nested);
  ~ZipNode() override;

  [[nodiscard]] std::string ToString() const override;
};

/// @mrpa MRPA node
struct MrpaNode : public FileNode {
  std::shared_ptr<Mrpa> mrpa;

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