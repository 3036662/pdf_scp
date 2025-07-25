#pragma  once

#include <memory>
#include <unordered_map>
#include <vector>

namespace mrpa{

struct NodeBase;
// owning refs
using PtrNode = std::shared_ptr<NodeBase>;
using VecChilds = std::vector<PtrNode>;
// non owning reds
using PtrAssocNode = std::weak_ptr<NodeBase>;
using VecRefs = std::vector<PtrAssocNode>;
using NodeIdMap =std::unordered_map<uint64_t, PtrAssocNode>;

/**
 * @brief A set of lookup tables
 */
struct IdMaps{
    NodeIdMap all_nodes;
    NodeIdMap file_nodes;
    NodeIdMap mrpa_nodes;
    NodeIdMap sig_nodes;
};

} // namespace mrpa