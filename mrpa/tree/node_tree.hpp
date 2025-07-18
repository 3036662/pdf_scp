#pragma once

#include <cstdint>
#include <memory>
#include <vector>

#include "zip/file_stat.hpp"

namespace mrpa {

/// @brief each node knows it's type
enum class NodeType : uint8_t {
  kRoot,  // the top node
  kFile,  // simple file
  kSig,   // detached signature
  kAsig,  // attached signature
  kMrpa,  // MRPA node
  kZip,   // a zip archive
};

struct CPodResult;
using PtrSigCheckRes = std::shared_ptr<CPodResult>;

/**
 * @brief Basic tree node
 */
struct Node {
  NodeType type = NodeType::kFile;
  uint64_t id;
};

/// @brief simple file
struct FileNode : public Node {
  zip_cpp::FileStat file_stat;
};

using PtrAssocFile = std::weak_ptr<FileNode>;
using PtrNode = std::shared_ptr<Node>;

/// @brief detached signature
struct SigNode : public FileNode {
  PtrSigCheckRes check_res = nullptr;
  PtrAssocFile assoc_;
};

/// @brief attached signature
struct AsigNode : public FileNode {
  PtrSigCheckRes check_res = nullptr;
  PtrNode child_;
};

struct MrpaNode : public FileNode {
  PtrAssocFile assoc_sig;
};

struct ZipNode : public FileNode {
  std::vector<PtrNode> chids;
};

/// struct SigNode:public

}  // namespace mrpa