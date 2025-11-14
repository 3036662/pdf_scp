/* File: tree_defs.hpp
Copyright (C) Basealt LLC,  2025
Author: Oleg Proskurin, <proskurinov@basealt.ru>

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with this program; if not, write to the Free Software Foundation,
Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

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
constexpr const char* kWarnCreateZipFailed = "CREATE_ZIP_FAILED";
constexpr const char* kWarnCopySrcFilesFailed = "COPY_SRC_FILES_FAILED";
constexpr const char* kWarnCopySrcMrpaFilesFailed =
  "COPY_SRC_MRPA_FILES_FAILED";
constexpr const char* kWarnFileConflicts = "SOME_FILES_WHERE_RENAMED";

}  // namespace mrpa