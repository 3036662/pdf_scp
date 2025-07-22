#include "utils_tree.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <exception>
#include <filesystem>
#include <memory>
#include <string_view>
#include <tuple>

#include "c_bridge.hpp"
#include "file_stat.hpp"
#include "mrpa.hpp"
#include "node.hpp"
#include "zip_cpp.hpp"

namespace mrpa {

namespace {
constexpr std::array<std::string_view, 5> possible_sig_ext{
  ".sign", ".sig", ".sgn", ".p7s", ".bin"};

constexpr std::string_view kPossibleMrpaExt = ".xml";
constexpr std::string_view kPossibleArchiveExt = ".zip";

/// 0 - detached, 1 - attached, -1 parse error(not a signature)
int IfSigAttached(const std::string& path) {
  const std::string ext = std::filesystem::path(path).extension().string();
  const bool ext_not_supported = std::none_of(
    possible_sig_ext.cbegin(), possible_sig_ext.cend(),
    [&ext](const auto& allowed_ext) { return allowed_ext == ext; });
  if (ext_not_supported) {
    return -1;
  }
  pdfcsp::c_bridge::SeparateSignatureParams cparams{};
  cparams.sig_file_path = path.c_str();
  cparams.sig_file_path_size = path.size();
  return pdfcsp::c_bridge::IsMessageAttached(&cparams);
}

bool isValidZip(const std::string& path) {
  const std::string ext = std::filesystem::path(path).extension().string();
  if (ext != kPossibleArchiveExt) {
    return false;
  }
  try {
    const zip_cpp::Zip zip{path};
  } catch (const std::exception&) {
    return false;
  }
  return true;
}

bool isValidMrpa(const std::string& path) {
  const std::string ext = std::filesystem::path(path).extension().string();
  if (ext != kPossibleMrpaExt) {
    return false;
  }
  return Mrpa(path).IsValid();
}

}  // namespace

PtrNode createNodeFromFile(const std::string& path, uint64_t node_id) noexcept {
  try {
    if (path.empty() || !std::filesystem::exists(path) ||
        !std::filesystem::is_regular_file(path)) {
      return nullptr;
    }
    // TODO(Oleg) implement create constructor from path for every

    // determine the file type: File,Sig,Asig,Zip
    PtrNode result_node;
    const int sig_flag = IfSigAttached(path);
    // detached message
    if (sig_flag == 0) {
      result_node =
        std::make_shared<SigNode>(path, NodeType::kSig, node_id, false);
      result_node->type = NodeType::kSig;
    }
    // an attached message
    else if (sig_flag == 1) {
      result_node =
        std::make_shared<AsigNode>(path, NodeType::kAsig, node_id, false);
      result_node->type = NodeType::kAsig;
    }
    // zip file
    else if (isValidZip(path)) {
      result_node =
        std::make_shared<ZipNode>(path, NodeType::kZip, node_id, false);
      result_node->type = NodeType::kZip;
    }
    // mrpa file
    else if (isValidMrpa(path)) {
      result_node =
        std::make_shared<MrpaNode>(path, NodeType::kZip, node_id, false);
      result_node->type = NodeType::kMrpa;
    }
    // regular file
    else {
      result_node =
        std::make_shared<FileNode>(path, NodeType::kFile, node_id, false);
    }
    return result_node;
  } catch (const std::exception& ex) {
    return nullptr;
  }
  return nullptr;
}

}  // namespace mrpa