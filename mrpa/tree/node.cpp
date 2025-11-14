/* File: node.cpp
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

#include "node.hpp"

#include <algorithm>
#include <array>
#include <boost/algorithm/string/join.hpp>
#include <boost/algorithm/string/split.hpp>
#include <boost/json/array.hpp>
#include <boost/json/object.hpp>
#include <boost/json/serialize.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <chrono>
#include <cstddef>
#include <exception>
#include <filesystem>
#include <iostream>
#include <iterator>
#include <memory>
#include <numeric>
#include <sstream>
#include <stdexcept>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include "c_bridge.hpp"
#include "grantors.hpp"
#include "mrpa.hpp"
#include "mrpa_typedefs.hpp"
#include "pod_structs.hpp"
#include "tree/tree_context.hpp"
#include "tree/utils_tree.hpp"
#include "tree/visitor.hpp"
#include "utils_mrpa.hpp"
#include "zip_cpp.hpp"

namespace mrpa {

// -------------------------------------------------------------
// accept visitor

void FileNode::AcceptVisitor(Visitor& visitor) { visitor.Visit(*this); }

void MrpaNode::AcceptVisitor(Visitor& visitor) { visitor.Visit(*this); }

void SigNode::AcceptVisitor(Visitor& visitor) { visitor.Visit(*this); }

void AsigNode::AcceptVisitor(Visitor& visitor) {
  visitor.Visit(*this);
  if (child_) {
    child_->AcceptVisitor(visitor);
  }
}

void DirNode::AcceptVisitor(Visitor& visitor) {
  visitor.Visit(*this);

  std::for_each(children.begin(), children.end(),
                [&visitor](const PtrNode& child_node) {
                  child_node->AcceptVisitor(visitor);
                });
}

void ZipNode::AcceptVisitor(Visitor& visitor) {
  visitor.Visit(*this);
  std::for_each(children.begin(), children.end(),
                [&visitor](const PtrNode& child_node) {
                  child_node->AcceptVisitor(visitor);
                });
}

// -------------------------------------------------------------
// to string

std::string ToString(NodeType type) {
  switch (type) {
    case NodeType::kRoot:
      return "Root";
    case NodeType::kAsig:
      return "Asig";
    case NodeType::kDir:
      return "Dir";
    case NodeType::kFile:
      return "File";
    case NodeType::kMrpa:
      return "Mrpa";
    case NodeType::kSig:
      return "Sig";
    case NodeType::kZip:
      return "Zip";
    default:
      return "Unknown";
  }
}

std::string NodeBase::ToString() const {
  std::ostringstream builder;
  builder << "type: " << mrpa::ToString(type) << "; id:" << id
          << "; refs number:" << refs.size()
          << "; MRPA number:" << mrpa_refs.size();
  return builder.str();
}

[[nodiscard]] std::string FileNode::ToString() const {
  std::ostringstream builder;
  builder << NodeBase::ToString();
  if (parent_id) {
    builder << "; parent_id = " << parent_id.value();
  }
  builder << "; nested: " << embedded;
  if (full_path) {
    builder << "; full path:" << full_path.value();
  }
  builder << "; File stat:" << file_stat.toString();
  return builder.str();
}

std::string ZipNode::ToString() const {
  std::ostringstream builder;
  builder << FileNode::ToString() << " temp_dir:" << temp_dir
          << "; number of children:" << children.size();
  return builder.str();
}

// -------------------------------------------------------------
// ToJSON

boost::json::object NodeBase::ToJson() const {
  boost::json::object res;
  res["type"] = ::mrpa::ToString(type);
  res["id"] = id;
  if (parent_id) {
    res["parent_id"] = parent_id.value();
  }
  res["assoc_refs_number"] = refs.size();
  boost::json::array arr_refs;
  std::transform(refs.begin(), refs.end(), std::back_inserter(arr_refs),
                 [](const auto& ref) { return ref.first; });
  res["ref_ids"] = std::move(arr_refs);
  boost::json::array mrpa_ids;
  std::transform(mrpa_refs.begin(), mrpa_refs.end(),
                 std::back_inserter(mrpa_ids),
                 [](const auto& ref) { return ref.first; });
  res["mrpa_ids"] = std::move(mrpa_ids);
  return res;
}

boost::json::object FileNode::ToJson() const {
  boost::json::object res = NodeBase::ToJson();
  res["stat"] = file_stat.toJson();
  res["embedded"] = embedded;
  if (full_path) {
    res["full_path"] = full_path.value();
  }
  return res;
}

boost::json::object DirNode::ToJson() const {
  boost::json::object res = FileNode::ToJson();
  boost::json::array kids;
  std::transform(children.cbegin(), children.cend(), std::back_inserter(kids),
                 [](const PtrNode& kid) { return kid->ToJson(); });
  res["children"] = std::move(kids);
  return res;
}

boost::json::object ZipNode::ToJson() const {
  boost::json::object res = FileNode::ToJson();
  res["temp_dir"] = temp_dir;
  boost::json::array kids;
  std::transform(children.cbegin(), children.cend(), std::back_inserter(kids),
                 [](const PtrNode& kid) { return kid->ToJson(); });
  res["children"] = std::move(kids);
  return res;
}

boost::json::object MrpaNode::ToJson() const {
  boost::json::object res = FileNode::ToJson();
  if (mrpa) {
    auto json_repr = mrpa->GetRawJson();
    if (json_repr) {
      res["mrpa_json_repr"] = json_repr.value();
    }
    auto grantor = mrpa->getGrantor();
    if (grantor) {
      res["grantor"] = grantor->ToJson();
    }
    auto persons = mrpa->getRepresentatives();
    boost::json::array arr_persons;
    std::transform(persons.cbegin(), persons.cend(),
                   std::back_inserter(arr_persons),
                   [](const PhysicalPerson& pers) { return pers.ToJson(); });
    res["representative_persons"] = std::move(arr_persons);
    res["time_valid"] = mrpa->IsTimeValid();
  }
  return res;
}

boost::json::object SigNode::ToJson() const {
  boost::json::object res = FileNode::ToJson();
  res["has_check_result"] = !check_res.empty();
  boost::json::array check_summaries;
  std::transform(
    check_res.cbegin(), check_res.cend(), std::back_inserter(check_summaries),
    [](const auto& pr_check_res) {
      boost::json::object obj;
      obj["file_id"] = pr_check_res.first;
      obj["check_summary"] = pr_check_res.second->bres.check_summary;
      return obj;
    });
  res["check_results"] = std::move(check_summaries);
  if (signer_person_info) {
    res["signer_person"] = utils::ToJson(signer_person_info.value());
  }
  return res;
}

boost::json::object AsigNode::ToJson() const {
  boost::json::object res = FileNode::ToJson();
  res["has_check_result"] = check_res != nullptr;
  boost::json::array kids;
  if (child_) {
    kids.emplace_back(child_->ToJson());
  }
  res["children"] = std::move(kids);
  if (check_res && child_) {
    boost::json::object obj;
    obj["file_id"] = child_->id;
    obj["check_summary"] = check_res->bres.check_summary;
    boost::json::array arr;
    arr.emplace_back(std::move(obj));
    res["check_results"] = std::move(arr);
  }
  if (signer_person_info) {
    res["signer_person"] = utils::ToJson(signer_person_info.value());
  }
  return res;
}

// -------------------------------------------------------------

FileNode::FileNode(std::string path, NodeType node_type, uint64_t node_id,
                   bool is_embedded)
  : NodeBase{node_type, node_id},
    embedded(is_embedded),
    full_path(std::move(path)) {
  // create stat for a regular file
  if (!is_embedded && std::filesystem::exists(full_path.value()) &&
      std::filesystem::is_regular_file(full_path.value())) {
    const std::filesystem::path fpath(full_path.value());
    file_stat.name = fpath.filename();
    file_stat.size = std::filesystem::file_size(fpath);
    const auto sctp =
      std::chrono::time_point_cast<std::chrono::system_clock::duration>(
        std::filesystem::last_write_time(fpath) -
        std::filesystem::file_time_type::clock::now() +
        std::chrono::system_clock::now());
    file_stat.time_mod = std::chrono::system_clock::to_time_t(sctp);
  }
}

DirNode::DirNode(const std::string& path, NodeType node_type, uint64_t node_id,
                 bool is_embedded)
  : FileNode(path, node_type, node_id, is_embedded) {}

/// @brief unpacks zip archive to a temporary directory and creates nodes for
/// all files
ZipNode::ZipNode(const std::string& path, NodeType node_type, uint64_t node_id,
                 bool is_embedded)
  : FileNode(path, node_type, node_id, is_embedded) {
  using FileEntry = zip_cpp::FileEntry;
  if (is_embedded) {
    return;
  }
  // open the archive
  zip = std::make_unique<zip_cpp::Zip>(path);
  // create an unique temporary folder
  boost::uuids::random_generator gen;
  const boost::uuids::uuid uuid = gen();
  const auto random_uiid = boost::uuids::to_string(uuid);
  temp_dir = std::filesystem::temp_directory_path().string() + "/csppdf/" +
             std::to_string(node_id) + "_" + random_uiid;
  // unzip every node if not encrypted
  for (const FileEntry& entry : *zip) {
    if (!entry.stat().encrypted && !entry.isFolder()) {
      auto unpacked_path = entry.readToDir(temp_dir);
      if (!unpacked_path) {
        throw std::runtime_error("[ZipNode::ZipNode] unzip file failed");
      }
      auto created_node =
        NodeFromFileFactory(unpacked_path.value(), TreeContext::NextId());
      if (created_node) {
        created_node->parent_id = node_id;
        // use the original stat info from the Zip entry
        std::static_pointer_cast<FileNode>(created_node)->file_stat =
          entry.stat();
        children.emplace_back(std::move(created_node));
      }
    }
    // if current entry is encrypted create just a FileNode
    if (entry.stat().encrypted) {
      // path_to_archive/encrypted_file.bin
      std::string file_virtual_full_path =
        path + "/" + entry.stat().name.value_or("");
      auto file_node = std::make_shared<FileNode>(
        std::move(file_virtual_full_path), NodeType::kFile,
        TreeContext::NextId(), true);
      file_node->parent_id = node_id;
      file_node->file_stat = entry.stat();
      children.emplace_back(std::move(file_node));
    }
  }
  // Entries in a ZIP archive are placed like "flat" siblings with different
  // paths, so we need to normalize to make them look like a "tree."
  children = NormalizeNodeDirs(std::move(children));
  for (auto& child : children) {
    child->parent_id = node_id;
  }
}

ZipNode::~ZipNode() {
  try {
    if (!temp_dir.empty() && std::filesystem::exists(temp_dir)) {
      std::ignore = std::filesystem::remove_all(temp_dir);
    }
  } catch (const std::exception& ex) {
    std::cerr << "[ZipNode][error] remove the temporary directory failed:"
              << ex.what() << "\n";
  }
}

MrpaNode::MrpaNode(const std::string& path, NodeType node_type,
                   uint64_t node_id, bool is_embedded)
  : FileNode(path, node_type, node_id, is_embedded) {
  if (!is_embedded) {
    mrpa = std::make_shared<Mrpa>(path);
  }
}

SigNode::SigNode(const std::string& path, NodeType node_type, uint64_t node_id,
                 bool is_embedded)
  : FileNode(path, node_type, node_id, is_embedded) {}

AsigNode::AsigNode(const std::string& path, NodeType node_type,
                   uint64_t node_id, bool is_embedded)
  : FileNode(path, node_type, node_id, is_embedded) {
  // extract the child
  boost::uuids::random_generator gen;
  const boost::uuids::uuid uuid = gen();
  const auto random_uiid = boost::uuids::to_string(uuid);
  const std::string temp_dir = std::filesystem::temp_directory_path().string() +
                               "/csppdf/" + std::to_string(node_id) + "_" +
                               random_uiid + "/";
  bool extract_file_res = false;
  std::string child_path =
    temp_dir + std::filesystem::path(path).stem().string();
  if (std::filesystem::create_directories(temp_dir)) {
    created_temp_dir.emplace(temp_dir);
    pdfcsp::c_bridge::SeparateSignatureParams params;
    params.sig_file_path = path.c_str();
    params.sig_file_path_size = path.size();
    params.data_file_path = child_path.c_str();
    params.data_file_path_size = child_path.size();
    extract_file_res = pdfcsp::c_bridge::ExtractFileFromAttachedSig(&params);
  }
  // create child with FileNode, mark as embedded if failed to extract
  auto file_node =
    std::make_shared<FileNode>(std::move(child_path), NodeType::kFile,
                               TreeContext::NextId(), !extract_file_res);
  file_node->parent_id = node_id;
  file_node->file_stat.name = file_node->full_path;
  child_ = std::move(file_node);
}

AsigNode::~AsigNode() {
  try {
    if (created_temp_dir.has_value()) {
      //  std::ignore = std::filesystem::remove_all(created_temp_dir.value());
    }
  } catch (const std::exception& ex) {
    std::cerr << "[AsigNode][error] remove the temporary directory failed "
              << ex.what() << "\n";
  }
}

}  // namespace mrpa