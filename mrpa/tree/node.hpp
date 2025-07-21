#pragma once

#include <cstdint>
#include <memory>
#include <vector>

#include "file_stat.hpp"

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

struct CPodResult;
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
  VecRefs refs_;  // non owning references to othe nodes
};

/// @brief simple file
struct FileNode : public Node {
  zip_cpp::FileStat file_stat;
};

struct DirNode : public FileNode {
  VecChilds childs;
};

/// @brief zip archive
struct ZipNode : public FileNode {
  VecChilds chids;
};

/// @mrpa MRPA node
struct MrpaNode : public FileNode {};

/// @brief detached signature
struct SigNode : public FileNode {
  PtrSigCheckRes check_res = nullptr;
};

/// @brief attached signature
/// @details owns one child
struct AsigNode : public FileNode {
  PtrSigCheckRes check_res = nullptr;
  PtrNode child_;
};

/// struct SigNode:public

}  // namespace mrpa