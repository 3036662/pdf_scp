#pragma once

/* File: utils_tree.hpp
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

#include <boost/json/object.hpp>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <unordered_set>

#include "mrpa_typedefs.hpp"
#include "node.hpp"
#include "tree_defs.hpp"

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
 * @brief For each mrpa check the connection with the signature
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
bool AreSettingsOK(const BatchSignatureSettings& settings);

/**
 * @brief Create a Signing Skip List object
 * @param nodes
 * @details We dont need to sign an MRPA (if it is already signed);
 * place the MRPA path and it's signature path to the skip list.
 * Also find MRPAs in top - level archives
 * @return std::unordered_set<std::string> list of paths
 */
std::unordered_set<std::string> CreateSigningSkipList(const VecNodes& nodes);

std::unordered_set<std::string> CreateMrpaToSignList(const VecNodes& nodes);

std::string CreateTempDirInDest(const std::string& dest_dir);

// clang-format off
/*

  MapDestPaths is a map: [source_file_full_path =>  DestFilePaths]

      struct DestFilePaths{
        src_dest; - destination planned for a source file        
        sig_dest; - destination planned for a signature
      };

*/
// clang-format on

/**
 * @brief Create a vector CPodParam structure object
 * @param src_dest a map created by @see CreateSrcToDestPathsForSigning
 * @param setting @see BatchSignatureSettings
 * @return std::vector<CPodParam>
 * @details This function is supposed to be called from the
 * TreeContext::SignTree method to help create a list of tasks for the CSP
 * library.
 */
std::vector<CPodParam> CreateVecCPodParams(
  const MapDestPaths& src_to_dest, const BatchSignatureSettings& settings,
  const std::unordered_set<std::string>& mrpa_to_sign);

/**
 * @brief Create a vector of pointers, aka CPodParam*.
 * @param tasks created by @see CreateVecCPodParams
 * @return std::vector<CPodParam*>
 */
std::vector<const CPodParam*> TransformToVectorOfPointers(
  const std::vector<CPodParam>& tasks);

bool AllTasksOK(const UniquePtrTaskBatchResult& res, size_t tasks_count);

void ChangeFilePrefix(std::string& fname, uint64_t prefix_old,
                      uint64_t prefix_new);

std::optional<std::string> PackAllToOneZip(
  const std::string& dest_dir, const MapDestPaths& dest_paths, bool attached,
  const MapStringString& mrpa_dest_paths);

std::optional<VecStrings> PackToSeparateZips(
  const std::string& dest_dir, const MapDestPaths& dest_paths, bool attached,
  const MapStringString& mrpa_dest_paths);

/**
 * @brief Creates ZIP archive(s) in a temporary dir
 *
 * @param settings BatchSignatureSettings
 * @param src_to_dest @see CreateSrcToDestPathsForSigning
 * @param src_dest_skip_list @see CreateSrcDestForSkippedMrpas
 * @return ZipPackResults structure
 * @details supposed to be called from
 */
ZipPackResults PackToZip(const BatchSignatureSettings& settings,
                         const MapDestPaths& src_to_dest,
                         const MapStringString& src_dest_skip_list);

}  // namespace mrpa