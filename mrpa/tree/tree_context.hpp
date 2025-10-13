#pragma once

#include <atomic>
#include <boost/json/object.hpp>
#include <memory>
#include <optional>
#include <shared_mutex>
#include <type_traits>
#include <unordered_map>
#include <vector>

#include "grantors.hpp"
#include "mrpa_typedefs.hpp"
#include "node.hpp"
#include "sign_tree_result.hpp"
#include "tree_defs.hpp"

namespace mrpa {

/**
 Tree nodes associations

 Signature file (SIG)  => signed file + (optional) MRPA
 Signature file (ASIG)  => signed file + (optional) MRPA
 Signed file => signature file + (optional) MRPA
 MRPA file => MRPA signature (SIG)

*/

/**
 * @brief The node tree
 * @details  TreeContext  is neither copyable nor movable.
 */
class TreeContext final {
 public:
  /// @brief the tree will be created with one root node
  TreeContext();
  TreeContext(const TreeContext&) = delete;
  TreeContext(TreeContext&&) = delete;
  TreeContext& operator=(const TreeContext&) = delete;
  TreeContext& operator=(TreeContext&&) = delete;
  ~TreeContext() = default;

  /**
   * @brief  add a file to the root node
   *
   * @param path path to file
   * @return true on success
   * @return false on false
   */
  [[nodiscard]] bool AddFile(const std::string& path, bool build_context = true,
                             bool lock_ctx = true) noexcept;

  [[nodiscard]] bool RemoveNode(NodeId node_id, bool build_context = true,
                                bool lock_ctx = true) noexcept;

  [[nodiscard]] bool Reset() noexcept;

  [[nodiscard]] bool AddFileListJson(const std::string& json_list) noexcept;

  [[nodiscard]] bool RemoveNodesJsonList(const std::string& json_list) noexcept;

  [[nodiscard]] boost::json::object ToJson() const;

  [[nodiscard]] PtrSigCheckRes GetSigCheckResult(NodeId sig_node_id,
                                                 NodeId file_node_id) noexcept;

  NodeId static NextId() {
    return counter_.fetch_add(1, std::memory_order_relaxed) + 1;
  }

  /// @brief build the associations from scratch
  [[maybe_unused]] bool BuildContext();

  [[nodiscard]] bool SignTree(const BatchSignatureSettings& settings);

  [[nodiscard]] boost::json::object LastSignResultJson() const;

  [[nodiscard]] std::optional<SignTreeResult> LastSignResult() const noexcept;

 private:
  /// @brief build lookup tables
  void BuildIdLookupTables();

  /**
   * @brief build [sig->file] and [file->sig] associations
   * @details find a signed file for each detached signature
   */
  void BindDetachedSignatures();

  void CheckDetachedSignatures();

  void CheckAttachedSignatures();

  void CheckOnlyMrpaSigs();

  /**
   * @brief Check all [mrpa->sig] connections, remove invalid connections
   * @details A connection will be removed if  a signature check failed or
   * signer person is invalid
   */
  void BindMrpaSigners();

  /**
   * @brief Creates a map of representatives [mrpa_id => vector<PhysicalPerson>]
   * @details Takes into account only those MRPAs that are signed
   */
  void BuildRepresentativesMap();

  /**
   * @brief build [file signature -> mrpa] +  [signed file => mrpa] connections
   * @details If a file signer matches the MRPA's representative person, a [file
   * signature → MRPA] connection will be added.
   */
  void BindSignaturesToMRPA();
  void BindOneAsigToMrpa(AsigNode& asig_node);
  void BindOneSigToMrpa(SigNode& sig_node);

  /**
   * @brief Saves the list of MRPA IDs in a signature's mrpa_refs field
   *
   * @tparam AsigNode or SignNode
   * @param node TNode Attached or Detached signature node
   */
  template <typename TNode, std::enable_if_t<std::is_same_v<TNode, AsigNode> ||
                                               std::is_same_v<TNode, SigNode>,
                                             bool> = true>
  void SaveRefsToMrpa(TNode& node);

  /// @brief get node by ID
  PtrNode GetNode(NodeId node_id) const;

  /// @brief get parent node
  PtrNode GetParent(const PtrNode& node) const;
  PtrNode GetParent(NodeId node_id) const;

  /// @brief get child nodes
  static VecNodes GetChilds(const PtrNode& node);

  VecNodes GetSiblings(NodeId node_id) const;

  ///@brief look for valid MRPAs for this particular signer
  std::vector<NodeId> FindMrpaForSigner(const SignaturePersonInfo& pers_info);

  /**
   * @brief Create destination paths for file signatures.
   * @param nodes it is supposed to be root->children
   * @param setting @see BatchSignatureSettings
   * @param skip_list listed files will be skipped
   * @param temp_dest_dir destination dir
   * @return MapDestPaths  map [ source file => destination file path ]
   */
  MapDestPaths CreateSrcToDestPathsForSigning(
    const VecNodes& nodes, const BatchSignatureSettings& setting,
    const std::unordered_set<std::string>& skip_list,
    const std::string& temp_dest_dir);

  /**
   * @brief Create destination paths for all MRPAs and their signatures
   * @param skip_list list with MRPAs and their signatures
   * @param temp_dest_dir a destination directory
   * @param logger
   * @return MapStringString [ src_path => dest_path ]
   */
  MapStringString CreateSrcDestForSkippedMrpas(
    const SetStrings& skip_list, const std::string& temp_dest_dir);

  void SaveFailResult(const std::string& temp_dir, std::string&& warn) noexcept;

  std::shared_ptr<DirNode> root_;
  std::shared_ptr<spdlog::logger> logger_;
  static std::atomic_uint64_t counter_;
  IdMaps lookup_tables_;
  // mrpa id => list of persons
  std::unordered_map<NodeId, std::vector<PhysicalPerson>> representatives_;
  mutable std::shared_mutex mtx_;

  std::optional<SignTreeResult> sign_res_;

#ifdef TEST_BUILD
  friend class TestTreePrivate;
#endif
};

}  // namespace mrpa