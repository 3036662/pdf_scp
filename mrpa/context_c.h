#pragma once

#define LIB_API __attribute__((visibility("default")))
#define LIB_LOCAL __attribute__((visibility("hidden")))

#ifdef __cplusplus
#include "tree_context.hpp"
namespace mrpa {
extern "C" {
#else
typedef struct TreeContext TreeContext;
typedef struct JsonString JsonString;
#endif

struct JsonString;

/**
 * @brief Create a Context object
 * @return TreeContext
 * @details caller must call DestroyContext
 */
LIB_API TreeContext* CreateContext();

/**
 * @brief Free the context
 * @param ctx
 */
LIB_API void DestroyContext(TreeContext* ctx);

/**
 * @brief Add files to context
 *
 * @param ctx
 * @param json_list JSON array of pathes
 * @return JSON object
 */
LIB_API const JsonString* AddFilesJsonList(TreeContext* ctx,
                                           const char* json_list);

/**
 * @brief remove Nodes from the context
 *
 * @param json_list JSON array of Node IDs
 * @return JSON object
 */
LIB_API const JsonString* RemoveFilesJsonList(TreeContext* ctx,
                                              const char* json_list);

/**
 * @brief Reset all
 * @param ctx
 * @return true on success
 */
LIB_API int ResetContext(TreeContext* ctx);

/**
 * @brief Build a JSON tree with all connections
 *
 * @param ctx
 * @return JsonString or nullptr on fail
 */
LIB_API const JsonString* BuildTree(TreeContext* ctx);

/**
 * @brief JSON object to simple string
 *
 * @param jstr JsonString
 * @return const char*
 */
LIB_API const char* GetString(const JsonString* jstr);

/**
 * @brief Free a memory allocated for JsonString.
 * @param jstr JsonString*
 */
LIB_API void FreeJsonString(const JsonString* jstr);

#ifdef __cplusplus
}
}  // namespace mrpa
#endif
