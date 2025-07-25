#pragma once

#include <cstdint>
#include <memory>
#include <optional>

#include "file_stat.hpp"
#include "mrpa.hpp"
#include "mrpa_typedefs.hpp"
#include "pod_structs.hpp"
#include "visitor.hpp"
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

// -------------------------------------------------------------

/**
 * @brief Basic tree node
 * @details A base class for other nodes.
 */
struct NodeBase : public std::enable_shared_from_this<NodeBase> {
  NodeType type = NodeType::kFile;
  uint64_t id = 0;
  VecRefs refs;  // non owning references to othe nodes
  std::optional<uint64_t> parent_id;

  NodeBase(NodeType node_type, uint64_t node_id)
    : type{node_type}, id{node_id} {};
  NodeBase(NodeBase&&) noexcept = default;
  NodeBase& operator=(NodeBase&&) noexcept = default;

  NodeBase() = delete;
  NodeBase(const NodeBase&) = delete;
  NodeBase& operator=(const NodeBase&) = delete;

  // /// @brief accept polymorphic visitor
  virtual void AcceptVisitor(Visitor& visitor) = 0;

  [[nodiscard]] virtual std::string ToString() const;

  virtual ~NodeBase() = default;
};

// -------------------------------------------------------------

/**
 * @brief A file node
 * @details Contains the file information: path, date, size, etc.
 */
struct FileNode : public NodeBase {
  zip_cpp::FileStat file_stat;
  bool nested = false;  // neseted whithin the an encrypted zip or asig
  std::optional<std::string> full_path;

  FileNode(std::string path, NodeType node_type, uint64_t node_id,
           bool is_nested);

  /// @brief accept polymorphic visitor
  void AcceptVisitor(Visitor& visitor) override;

  [[nodiscard]] std::string ToString() const override;
};

// -------------------------------------------------------------

/**
 * @brief A directory node
 * @details May have childs
 */
struct DirNode : public FileNode {
  VecChilds childs;
  DirNode(const std::string& path, NodeType node_type, uint64_t node_id,
          bool is_nested);

  /// @brief accept polymorphic visitor
  void AcceptVisitor(Visitor& visitor) override;
};

// -------------------------------------------------------------

/**
 * @brief  A ZIP archive node
 * @details Unpacking the archive on construction creates child nodes for all
 * unpacked files.
 * @details Removes all temporary files on destruction
 */
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

  /// @brief accept polymorphic visitor
  void AcceptVisitor(Visitor& visitor) override;

  [[nodiscard]] std::string ToString() const override;
};

// -------------------------------------------------------------

/**
 * @brief an MRPA node
 * @details Must be associated with a signature to be considered a full-fledged
 * MRPA
 */
struct MrpaNode : public FileNode {
  std::shared_ptr<Mrpa> mrpa;

  MrpaNode(const std::string& path, NodeType node_type, uint64_t node_id,
           bool is_nested);

  /// @brief accept polymorphic visitor
  void AcceptVisitor(Visitor& visitor) override;
};

// -------------------------------------------------------------

/**
 * @brief a detached signature
 * @details must have an associated file to perform the check
 */
struct SigNode : public FileNode {
  PtrSigCheckRes check_res = nullptr;
  SigNode(const std::string& path, NodeType node_type, uint64_t node_id,
          bool is_nested);

  /// @brief accept polymorphic visitor
  void AcceptVisitor(Visitor& visitor) override;
};

// -------------------------------------------------------------

/**
 * @brief an attached signature
 * @details owns one child
 */
struct AsigNode : public FileNode {
  PtrSigCheckRes check_res = nullptr;
  PtrNode child_;
  AsigNode(const std::string& path, NodeType node_type, uint64_t node_id,
           bool is_nested);

  /// @brief accept polymorphic visitor
  void AcceptVisitor(Visitor& visitor) override;
};

}  // namespace mrpa