#include "context_c.h"

#include <boost/json/serialize.hpp>
#include <exception>
#include <iostream>
#include <tuple>

#include "tree_context.hpp"

namespace mrpa {

struct JsonString {
  std::string val;
};

namespace {

JsonString* BuildJson(TreeContext* ctx) noexcept {
  if (ctx == nullptr) {
    return nullptr;
  }
  try {
    std::string json_str_val = boost::json::serialize(ctx->ToJson());
    auto* const res = new JsonString;  // NOLINT
    res->val = std::move(json_str_val);
    return res;
  } catch (const std::exception& ex) {
    std::cerr << "[AddFilesJsonList][error] " << ex.what() << '\n';
    return nullptr;
  }
}

}  // namespace

extern "C" {

TreeContext* CreateContext() {
  try {
    return new TreeContext;  // NOLINT
  } catch (const std::exception& ex) {
    std::cerr << "[CreateContext][error]: " << ex.what() << "\n";
  }
  return nullptr;
}

void DestroyContext(TreeContext* ctx) {
  if (ctx != nullptr) {
    std::ignore = ctx->Reset();
  }
  delete ctx;  // NOLINT
}

const JsonString* AddFilesJsonList(TreeContext* ctx, const char* json_list) {
  if (ctx == nullptr || json_list == nullptr) {
    return nullptr;
  }
  if (!ctx->AddFileListJson(json_list)) {
    return nullptr;
  };
  return BuildJson(ctx);
}

const JsonString* RemoveFilesJsonList(TreeContext* ctx, const char* json_list) {
  if (ctx == nullptr || json_list == nullptr) {
    return nullptr;
  }
  if (!ctx->RemoveNodesJsonList(json_list)) {
    return nullptr;
  };
  return BuildJson(ctx);
}

const char* GetString(const JsonString* jstr) {
  if (jstr == nullptr || jstr->val.empty()) {
    return nullptr;
  }
  return jstr->val.c_str();
}

void FreeJsonString(const JsonString* jstr) {
  delete jstr;  // NOLINT
}

/**
 * @brief Reset all
 * @param ctx
 * @return true on success
 */
int ResetContext(TreeContext* ctx) {
  if (ctx == nullptr) {
    return 0;
  }
  return ctx->Reset() ? 1 : 0;
}

/**
 * @brief Build a JSON tree with all connections
 *
 * @param ctx
 * @return JsonString or nullptr on fail
 */
LIB_API const JsonString* BuildTree(TreeContext* ctx) {
  if (ctx == nullptr) {
    return nullptr;
  }
  if (!ctx->BuildContext()) {
    return nullptr;
  }
  return BuildJson(ctx);
}

/**
 * @brief Sign the whole tree
 * @details  Sign the whole tree. Only top nodes will be signed. Signed MRPAs
 * will not be signed, just copied.
 * @return true on success
 */
LIB_API bool SignTree(TreeContext* ctx,
                      const BatchSignatureSettings* settings) {
  if (ctx == nullptr || settings == nullptr) {
    return false;
  }
  try {
    return ctx->SignTree(*settings);
  } catch (const std::exception& ex) {
    std::cerr << "[SignTree] error" << ex.what() << "\n";
    return false;
  }
}

/**
 * @brief Returns a JSON string with the last sign operation status.
 *
 * @param ctx TreeContext
 * @return JsonString* Status is a JSON string containing a list of all of the
 * result files and also a list of warnings.
 */
LIB_API const JsonString* LastSignStatus(TreeContext* ctx) {
  if (ctx == nullptr) {
    return nullptr;
  }
  const auto last_res = ctx->LastSignResult();
  if (!last_res) {
    return nullptr;
  }
  try {
    return new JsonString{
      boost::json::serialize(last_res->ToJson())};  // NOLINT
  } catch (const std::exception& ex) {
    std::cerr << "[LastSignStatus] error" << ex.what() << "\n";
    return nullptr;
  }
}

/**
 * @brief Get the Check Result For Node object
 * @param ctx TreeContext*
 * @param sig_node_id Signature Node ID (SigNode or AsigNode)
 * @param signed_file_id Signed file ID
 * @return const* CPodResult @see pod_structs.hpp
 * @details No need to call free; the pointer will be valid until the signature
 * node is destroyed.
 */
LIB_API const CPodResult* GetCheckResultForNode(TreeContext* ctx,
                                                uint64_t sig_node_id,
                                                uint64_t signed_file_id) {
  return ctx->GetSigCeckResult(sig_node_id, signed_file_id).get();
}

}  // extern "C"

}  // namespace mrpa