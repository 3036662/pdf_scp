#pragma once

/* File: mrpa_typedefs.hpp
Copyright (C) Basealt LLC,  2025
Author: Oleg Proskurin, <proskurinov@basealt.ru>

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with this program; if not, write to the Free Software Foundation,
Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

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
using CPodParam = pdfcsp::c_bridge::CPodParam;
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
  std::optional<std::string> signer_given_name;
  std::optional<std::string> signer_inn;
};

}  // namespace mrpa