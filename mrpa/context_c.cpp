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

}  // extern "C"

}  // namespace mrpa