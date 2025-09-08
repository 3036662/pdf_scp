#include <memory>
#include <string>
#include <unordered_map>
#include <unordered_set>

#include "pod_structs.hpp"

#pragma once

namespace mrpa {

struct DestFilePaths {
  std::string src_dest;
  std::string sig_dest;
};

struct ZipPackResults {
  std::vector<std::string> paths;
  std::string zip_tmp_dir;
};

using BatchSignatureSettings = pdfcsp::c_bridge::BatchSignatureSettings;
using TaskBatch = pdfcsp::c_bridge::TaskBatch;
using TaskBatchResult = pdfcsp::c_bridge::TaskBatchResult;
using MapDestPaths = std::unordered_map<std::string, DestFilePaths>;
using UniquePtrTaskBatchResult =
  std::unique_ptr<const TaskBatchResult, void (*)(const TaskBatchResult*)>;

using SetStrings = std::unordered_set<std::string>;
using VecStrings = std::vector<std::string>;

using MapStringString = std::unordered_map<std::string, std::string>;

constexpr const char* kSignIpcCommand = "create_signature_file";

constexpr const char* kWarnInvalidParams = "INVALID_PARAMETERS";
constexpr const char* kWarnInvalidDest = "INVALID_DESTINATION";
constexpr const char* kWarnSignAllFailed = "SIGN_ALL_FILES_FAILED";
constexpr const char* kWarnFileConflicts = "SOME_FILES_WHERE_RENAMED";

}  // namespace mrpa