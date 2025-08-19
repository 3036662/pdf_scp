#pragma once
#include <memory>
#include <optional>
#include <stdexcept>

#include "context_c.h"
#include "mrpa_typedefs.hpp"
#include "pod_structs.hpp"
/**
 * @brief C++ header using only the C language public interface of the MRPA
 * library. This approach is supposed to protect from any client/library
 * compiler incompatibilities.
 *
 */

namespace pdfcsp {

using PtrCtx = std::unique_ptr<mrpa::TreeContext, void (*)(mrpa::TreeContext*)>;
using PtrJsonString =
  std::unique_ptr<const mrpa::JsonString, void (*)(const mrpa::JsonString*)>;
using CPodResult = c_bridge::CPodResult;

/**
 * @brief Document Tree representation
 *
 */
class DocTree final {
 public:
  DocTree() : ctx_(mrpa::CreateContext(), mrpa::DestroyContext) {
    if (!ctx_) {
      throw std::runtime_error("[DocTree] create context failed");
    }
  }

  // movable
  DocTree(DocTree&&) noexcept = default;
  DocTree& operator=(DocTree&&) = default;
  ~DocTree() = default;

  // non copyable
  DocTree(const DocTree&) = delete;
  DocTree& operator=(const DocTree&) = delete;

  /**
   * @brief Add files with a JSON array
   *
   * @param json_list  JSON array of pathes
   * @return JSON representation of the Tree
   */
  std::optional<std::string> AddFilesJsonList(const std::string& json_list) {
    const PtrJsonString jres(
      mrpa::AddFilesJsonList(ctx_.get(), json_list.c_str()),
      mrpa::FreeJsonString);
    if (!jres) {
      return std::nullopt;
    }
    const char* res = mrpa::GetString(jres.get());
    if (res != nullptr) {
      return res;
    }
    return std::nullopt;
  }

  /**
   * @brief remove Nodes from the context
   *
   * @param json_list  JSON array of Node IDs
   * @return JSON representation of the Tree
   * @details only top Nodes can be removed, node 0 can't be removed
   */
  std::optional<std::string> RemoveFilesJsonList(const std::string& json_list) {
    const PtrJsonString jres(
      mrpa::RemoveFilesJsonList(ctx_.get(), json_list.c_str()),
      mrpa::FreeJsonString);
    if (!jres) {
      return std::nullopt;
    }
    const char* res = mrpa::GetString(jres.get());
    if (res != nullptr) {
      return res;
    }
    return std::nullopt;
  }

  /// @brief reset the Tree
  bool ResetContext() { return mrpa::ResetContext(ctx_.get()) != 0; }

  /**
   * @brief Build a JSON tree with all connections
   *
   * @return std::optional<std::string> JSON tree
   */
  std::optional<std::string> BuildTree() {
    const PtrJsonString jres(mrpa::BuildTree(ctx_.get()), mrpa::FreeJsonString);
    if (!jres) {
      return std::nullopt;
    }
    const char* res = mrpa::GetString(jres.get());
    if (res != nullptr) {
      return res;
    }
    return std::nullopt;
  }

  /**
   * @brief Get the Check Result For Node object
   *
   * @param sig_node_id a signature node ID
   * @param signed_file_id a signed file ID
   * @return const CPodResult* raw CpodResult
   * @details No need to call free; the pointer will be valid until the
   * signature node is destroyed
   */
  const CPodResult* GetCheckResultForNode(mrpa::NodeId sig_node_id,
                                          mrpa::NodeId signed_file_id) {
    return mrpa::GetCheckResultForNode(ctx_.get(), sig_node_id, signed_file_id);
  }

  bool SignTree(const BatchSignatureSettings& settings) {
    return mrpa::SignTree(ctx_.get(), &settings);
  }

  [[nodiscard]] std::optional<std::string> LastSignStatus() const {
    const PtrJsonString jstr(mrpa::LastSignStatus(ctx_.get()),
                             mrpa::FreeJsonString);
    if (!jstr) {
      return std::nullopt;
    }
    const char* res = mrpa::GetString(jstr.get());
    if (res != nullptr) {
      return res;
    }
    return std::nullopt;
  }

 private:
  PtrCtx ctx_;
};

}  // namespace pdfcsp