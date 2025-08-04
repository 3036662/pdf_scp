#pragma once

#include <atomic>
#include <boost/json/object.hpp>
#include <unordered_map>

#include "grantors.hpp"
#include "mrpa_typedefs.hpp"
#include "node.hpp"

namespace mrpa {

/**
 * @brief The node tree
 */
class TreeContext {
 public:
  /// @brief the tree will be created with one root node
  TreeContext();

  /**
   * @brief  add a file to the root node
   *
   * @param path path to file
   * @return true on success
   * @return false on false
   */
  [[nodiscard]] bool AddFile(const std::string& path,
                             bool build_context = true) noexcept;

  [[nodiscard]] boost::json::object ToJson() const;

  NodeId static NextId() {
    return counter_.fetch_add(1, std::memory_order_relaxed) + 1;
  }

  /// @brief build the associations from scratch
  void BuildContext();

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
   * @brief build [file signature -> mrpa connention]
   * @details If a file signer matches the MRPA's representative person, a [file
   * signature → MRPA] connection will be added.
   */
  void BindSignaturesToMRPA();

  void BindOneAsigToMrpa(AsigNode& asig_node);

  /// @brief get node by ID
  PtrNode GetNode(NodeId node_id) const;

  /// @brief get parent node
  PtrNode GetParent(const PtrNode& node) const;
  PtrNode GetParent(NodeId node_id) const;

  /// @brief get child nodes
  static VecNodes GetChilds(const PtrNode& node);

  VecNodes GetSiblings(NodeId node_id) const;

  std::shared_ptr<DirNode> root_;
  std::shared_ptr<spdlog::logger> logger_;
  static std::atomic_uint64_t counter_;
  IdMaps lookup_tables_;
  std::unordered_map<NodeId, std::vector<PhysicalPerson>> representatives_;

#ifdef TEST_BUILD
  friend class TestTreePrivate;
#endif
};

/*
TODO(Oleg)

Implement accociations

+- Signature file (SIG)  => signed file + (optional) MRPA
-- Signature file (ASIG)  => signed file + (optional) MRPA
+- Signed file => signature file + (optional) MRPA
+ MRPA file => MRPA signature (SIG)


1. find all sig and check if there any files for them
2. check signatures

3. find all mrpa and find if there any signature associatied with an mrpa file

4. check if the  the mrpa signer is valid grantor

5. associate every signature with some mrpa files if possible

*/

}  // namespace mrpa