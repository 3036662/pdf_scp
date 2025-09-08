#pragma once

#define LIB_API __attribute__((visibility("default")))
#define LIB_LOCAL __attribute__((visibility("hidden")))

#include "pod_structs.hpp"

#ifdef __cplusplus
#include <cstdint>
#define NAMESPACE_C_BRIDGE pdfcsp::c_bridge::
using CPodResult = pdfcsp::c_bridge::CPodResult;
using BatchSignatureSettings = pdfcsp::c_bridge::BatchSignatureSettings;
namespace mrpa {
extern "C" {
#else
#define NAMESPACE_C_BRIDGE
typedef struct TreeContext TreeContext;
typedef struct JsonString JsonString;
typedef struct CPodResult CPodResult;
typedef struct BatchSignatureSettings BatchSignatureSettings;
#endif

struct JsonString;

#ifdef __cplusplus
class TreeContext;
#endif

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
 * @param json_list JSON array of paths
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
 * @brief Sign the whole tree
 * @details  Sign the whole tree. Only top nodes will be signed. Signed MRPAs
 * will not be signed, just copied.
 * @return true on success
 */
LIB_API bool SignTree(TreeContext* ctx, const BatchSignatureSettings* settings);

/**
 * @brief Returns a JSON string with the last sign operation status.
 *
 * @param ctx TreeContext
 * @return JsonString* Status is a JSON string containing a list of all of the
 * result files and also a list of warnings.
 */
LIB_API const JsonString* LastSignStatus(TreeContext* ctx);

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
                                                uint64_t signed_file_id);

#ifdef __cplusplus
}
}  // namespace mrpa
#endif
