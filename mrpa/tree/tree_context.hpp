#pragma once

#include <atomic>
#include <boost/json/object.hpp>
#include <cstdint>

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
  [[nodiscard]] bool AddFile(const std::string& path) noexcept;

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
   * @brief build sig->file and file->sig associations
   * @details find a signed file for each detached signature
   */
  void BindDetachedSignatures();

  void CheckDetachedSignatures();

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

#ifdef TEST_BUILD
  friend class TestTreePrivate;
#endif
};

/*
TODO(Oleg)

Implement accociations

+ sig  -> file
+ File -> sig (after check)
+  Zip  -> sig (after check)
  mrpa -> sig (after check)
sig  -> mrpa

asig -> mrpa

1. find all sig and check if there any files for them
2. check signatures

3. find all mrpa and find if there any signature associatied with an mrpa file

4. check if the  the mrpa signer is valid grantor

5. associate every signature with some mrpa files if possible

*/

}  // namespace mrpa