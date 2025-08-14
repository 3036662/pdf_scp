#pragma once
#include <boost/json/object.hpp>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <unordered_map>

#include "file_stat.hpp"
#include "mrpa.hpp"
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
void CheckOneSigNode(const std::shared_ptr<SigNode>& sig_node,
                     const std::shared_ptr<spdlog::logger>& logger);

/**
 * @brief Check one attached signature node
 * @param sig_node shared pointer
 * @details the results will be stored in sig_node->check_res
 */
void CheckOneAttachedSigNode(const std::shared_ptr<AsigNode>& sig_node);

/**
 * @brief For each mrpa check the connenction with the signature
 * @param mrpa_node
 * @param logger
 * @details If a referenced signature has no result for this MRPA or the signer
 * does not match the MRPA's grantor, the connection will be removed.
 */
void BindOneMrpaSigners(const std::shared_ptr<MrpaNode>& mrpa_node,
                        const std::shared_ptr<spdlog::logger>& logger);

/**
 * @brief Check whether the destination is a writable directory.
 * @param dest path to dir
 */
bool IsDestinationDirOK(const std::string& dest) noexcept;

/**
 * @brief Check whether all settings are valid.
 */
bool IsSettingsOK(const BatchSignatureSettings& settings);

/**
 * @brief Create destination paths for file signatures.
 * @param nodes it is supposed to be root->children
 * @param setting @see BatchSignatureSettings
 * @return MapStringString  map [ source file => destination file path ]
 */
MapStringString CreateSrcToDestPathesForSigning(
  const VecNodes& nodes, const BatchSignatureSettings& setting);

/**
 * @brief Create a vector CPodParam structure object
 * @param src_dest a map created by @see CreateSrcToDestPathesForSigning
 * @param setting @see BatchSignatureSettings
 * @return std::vector<CPodParam>
 * @details This function is supposed to be called from the
 * TreeContext::SignTree method to help create a list of tasks for the CSP
 * library.
 */
std::vector<CPodParam> CreateVecCPodParams(
  const MapStringString& src_to_dest, const BatchSignatureSettings& settings);

/**
 * @brief Create a vector of pointers, aka CPodParam*.
 * @param tasks created by @see CreateVecCPodParams
 * @return std::vector<CPodParam*>
 */
std::vector<const CPodParam*> TransformToVectorOfPointers(
  const std::vector<CPodParam>& tasks);

bool AllTasksOK(const UniquePtrTaskBatchResult& res, size_t tasks_count);

}  // namespace mrpa