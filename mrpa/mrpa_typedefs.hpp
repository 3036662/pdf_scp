#pragma once

#include <cstdint>
#include <memory>
#include <unordered_map>
#include <vector>

namespace mrpa {

struct NodeBase;
// owning refs
using PtrNode = std::shared_ptr<NodeBase>;
using VecNodes = std::vector<PtrNode>;
// non owning reds
using PtrAssocNode = std::weak_ptr<NodeBase>;
using VecRefs = std::vector<PtrAssocNode>;
using NodeIdMap = std::unordered_map<uint64_t, PtrAssocNode>;
using NodeId = uint64_t;

/**
 * @brief A set of lookup tables
 */
struct IdMaps {
  NodeIdMap all_nodes;
  NodeIdMap file_nodes;
  NodeIdMap mrpa_nodes;
  NodeIdMap sig_nodes;
  NodeIdMap asig_nodes;
};

}  // namespace mrpa