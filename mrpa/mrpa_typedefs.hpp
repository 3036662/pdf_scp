#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "pod_structs.hpp"

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

using CPodResult = pdfcsp::c_bridge::CPodResult;
using PtrSigCheckRes = std::shared_ptr<CPodResult>;

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

struct SignaturePersonInfo {
  std::optional<std::string> signer_surname;
  std::optional<std::string> signer_givenname;
  std::optional<std::string> signer_inn;
};

}  // namespace mrpa