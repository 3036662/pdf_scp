#pragma once
#include <boost/json/object.hpp>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <unordered_map>

#include "file_stat.hpp"
#include "mrpa_typedefs.hpp"
#include "node.hpp"

namespace mrpa {

/**
 * @brief Create a Node from file
 *
 * @param path path to file
 * @param node_id node_id (@see TreeContext::NextId())
 * @return PtrNode or null for Folder, folders are ignored
 * @throws runtime_error propagated from Node constructors
 * @details can be run recursively by the ZipNode object to create child nodes
 */
PtrNode NodeFromFileFactory(const std::string& path, uint64_t node_id);

/**
 * @brief Normalize node paths
 *
 * @param vec_nodes
 * @return VecNodes normalized
 * @details If a node has a path looking like dir1/dir2/file.txt,
 * It will be normalized to the dir1 -> dir2 -> file.txt node tree.
 */
VecNodes NormalizeNodeDirs(VecNodes vec_nodes);

/**
 * @brief Check one detached signature node
 * @param sig_node shared pointer
 * @details the results will be stored in sig_node->check_res
 */
void CheckOneSigNode(std::shared_ptr<SigNode> sig_node);

/**
 * @brief Check one attached signature node
 * @param sig_node shared pointer
 * @details the results will be stored in sig_node->check_res
 */
void CheckOneAttachedSigNode(const std::shared_ptr<AsigNode>& sig_node);

}  // namespace mrpa