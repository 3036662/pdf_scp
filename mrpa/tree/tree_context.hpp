#pragma once

#include <atomic>
#include <cstdint>
#include <unordered_map>

#include "logger_utils.hpp"
#include "node.hpp"

namespace mrpa {

using IdLookUpMap = std::unordered_map<uint64_t, PtrAssocNode>;

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

  uint64_t static NextId() {
    return counter_.fetch_add(1, std::memory_order_relaxed) + 1;
  }

  /// @brief build associations
  void BuildContext();

 private:
  void BuildIdLookupTable();

  std::shared_ptr<DirNode> root_;
  std::shared_ptr<spdlog::logger> logger_;
  static std::atomic_uint64_t counter_;
  std::unordered_map<uint64_t, PtrAssocNode> id_lookup_table_;
};

/*
TODO(Oleg)

Implement accociations

File -> sig
Zip  -> sig
mrpa -> sig
sig  -> file
sig  -> mrpa
asig -> mrpa

1. find all sig and check if there any files for them
2. check signatures

3. find all mrpa and find if there any signature associatied with an mrpa file

4. check if the  the mrpa signer is valid grantor

5. associate every signature with some mrpa files if possible

*/

}  // namespace mrpa