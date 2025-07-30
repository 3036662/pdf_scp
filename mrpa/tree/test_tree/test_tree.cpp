#include <algorithm>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/json/serialize.hpp>
#include <filesystem>
#include <memory>
#include <string>

#include "common_utils.hpp"
#include "mrpa_typedefs.hpp"
#include "node.hpp"
#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

#include "test_tree_private.hpp"
#include "tree_context.hpp"
#include "utils_tree.hpp"

const std::string src_simple_zip =
  std::string(TEST_FILES_DIR) + "mrpa/zip/simple.zip";

const std::string regular_file1 =
  std::string(TEST_FILES_DIR) + "mrpa/zip/рандом.txt";

const std::string attached_invalid_sig1 =
  std::string(TEST_FILES_DIR) + "mrpa/sigs/attached993.sig";

const std::string attached_valid_sig2 =
  std::string(TEST_FILES_DIR) +
  "mrpa/sensitive/task180656/all_sign/signme.pdf_BASE-64_CAdES-BES.sgn";

const std::string mrpa_valid1 =
  std::string(TEST_FILES_DIR) +
  "mrpa/valid/ON_EMCHD_20241203_c61a40df-d38f-4800-9ba4-61a2df016993.xml";

const std::string archive_invalid0 =
  std::string(TEST_FILES_DIR) + "mrpa/zip/non_zip.zip";

const std::string archive_real1 =
  std::string(TEST_FILES_DIR) +
  "mrpa/sensitive/Счет_на_оплату_№_1513_от_30_июня_2025_г_pdf.zip";

const std::string archive_real2 =
  std::string(TEST_FILES_DIR) + "mrpa/sensitive/bugzilla_54258_CP866.zip";

const std::string archive_encrypted2 =
  std::string(TEST_FILES_DIR) + "mrpa/zip/encrypted.zip";

TEST_CASE("Initial") { REQUIRE(true); }

TEST_CASE("DefaultConstructor") { REQUIRE_NOTHROW(mrpa::TreeContext()); }

TEST_CASE("CreateNodeFromFile") {
  SECTION("empty path") {
    REQUIRE(mrpa::NodeFromFileFactory("", mrpa::TreeContext::NextId()) ==
            nullptr);
  }
  SECTION("nonexisting") {
    REQUIRE(mrpa::NodeFromFileFactory("blabla", mrpa::TreeContext::NextId()) ==
            nullptr);
  }
  SECTION("not a file") {
    REQUIRE(mrpa::NodeFromFileFactory("/home", mrpa::TreeContext::NextId()) ==
            nullptr);
  }
  SECTION("Regular file 1") {
    auto node =
      mrpa::NodeFromFileFactory(regular_file1, mrpa::TreeContext::NextId());
    REQUIRE(node);
    REQUIRE(node->id > 0);
    REQUIRE(node->type == mrpa::NodeType::kFile);
    auto file_node = std::static_pointer_cast<mrpa::FileNode>(node);
    REQUIRE(file_node);
    REQUIRE(file_node->file_stat.name);
    REQUIRE(file_node->file_stat.name.value() == "рандом.txt");
    std::cout << file_node->file_stat.toString() << "\n";
  }
  SECTION("Attached_invalid_sig_1") {
    auto node = mrpa::NodeFromFileFactory(attached_invalid_sig1,
                                          mrpa::TreeContext::NextId());
    REQUIRE(node);
    REQUIRE(node->id > 0);
    REQUIRE(node->type == mrpa::NodeType::kAsig);
    auto asig_node = std::static_pointer_cast<mrpa::AsigNode>(node);
    REQUIRE(asig_node);
    REQUIRE(asig_node->file_stat.name);
    REQUIRE(asig_node->file_stat.name.value() == "attached993.sig");
    // check on construct is disabled
    // REQUIRE(asig_node->check_res);
    // REQUIRE(asig_node->check_res->common_execution_status);
    // REQUIRE_FALSE(asig_node->check_res->bres.check_summary);
  }
  SECTION("Attached_valid_asig_2") {
    if (std::filesystem::exists(attached_valid_sig2)) {
      auto node = mrpa::NodeFromFileFactory(attached_valid_sig2,
                                            mrpa::TreeContext::NextId());
      REQUIRE(node);
      REQUIRE(node->id > 0);
      REQUIRE(node->type == mrpa::NodeType::kAsig);
      auto asig_node = std::static_pointer_cast<mrpa::AsigNode>(node);
      REQUIRE(asig_node);
      REQUIRE(asig_node->file_stat.name);
      REQUIRE(asig_node->file_stat.name.value() ==
              "signme.pdf_BASE-64_CAdES-BES.sgn");
      // check on construct is disabled
      // REQUIRE(asig_node->check_res);
      // REQUIRE(asig_node->check_res->common_execution_status);
      // REQUIRE(asig_node->check_res->bres.check_summary);
      REQUIRE(asig_node->child_->id > node->id);
      REQUIRE(asig_node->child_->type == mrpa::NodeType::kFile);
      auto nested_file_node =
        std::static_pointer_cast<mrpa::FileNode>(asig_node->child_);
      REQUIRE(nested_file_node);
      REQUIRE(nested_file_node->type == mrpa::NodeType::kFile);
      REQUIRE(nested_file_node->parent_id == asig_node->id);
      std::cout << "ASigNodeID:" << asig_node->id
                << " NestedChild ID:" << nested_file_node->id << "\n";
      std::cout << nested_file_node->file_stat.name.value() << "\n";
    }
  }

  SECTION("MRPA_valid") {
    REQUIRE(std::filesystem::exists(mrpa_valid1));
    auto node =
      mrpa::NodeFromFileFactory(mrpa_valid1, mrpa::TreeContext::NextId());
    REQUIRE(node);
    REQUIRE(node->type == mrpa::NodeType::kMrpa);
    auto mrpa_node = std::static_pointer_cast<mrpa::MrpaNode>(node);
    REQUIRE(mrpa_node);
    REQUIRE(mrpa_node->id > 0);
    REQUIRE(mrpa_node->type == mrpa::NodeType::kMrpa);
    REQUIRE(mrpa_node->mrpa->IsValid());
  }

  SECTION("InvalidZip") {
    REQUIRE(std::filesystem::exists(archive_invalid0));
    auto node =
      mrpa::NodeFromFileFactory(archive_invalid0, mrpa::TreeContext::NextId());
    REQUIRE(node);
    REQUIRE(node->type == mrpa::NodeType::kFile);
    REQUIRE_THROWS(
      mrpa::ZipNode(archive_invalid0, mrpa::NodeType::kZip, 0, false));
  }
}

TEST_CASE("NodeType_ToString") {
  REQUIRE(mrpa::ToString(mrpa::NodeType::kRoot) == "Root");
  REQUIRE(mrpa::ToString(mrpa::NodeType::kMrpa) == "Mrpa");
  REQUIRE(mrpa::ToString(mrpa::NodeType::kAsig) == "Asig");
  REQUIRE(mrpa::ToString(mrpa::NodeType::kDir) == "Dir");
  REQUIRE(mrpa::ToString(mrpa::NodeType::kFile) == "File");
  REQUIRE(mrpa::ToString(mrpa::NodeType::kSig) == "Sig");
  REQUIRE(mrpa::ToString(mrpa::NodeType::kZip) == "Zip");
}

#ifndef SKIP_SENSITIVE
TEST_CASE("Archive") {
  SECTION("archive_real1") {
    REQUIRE(std::filesystem::exists(archive_real1));
    auto node =
      mrpa::NodeFromFileFactory(archive_real1, mrpa::TreeContext::NextId());
    REQUIRE(node);
    REQUIRE(node->type == mrpa::NodeType::kZip);
    auto zip_node = std::static_pointer_cast<mrpa::ZipNode>(node);
    REQUIRE(zip_node);
    REQUIRE(zip_node->id > 0);
    REQUIRE(zip_node->type == mrpa::NodeType::kZip);
    REQUIRE(zip_node->zip->size() > 0);
  }
}
#endif

TEST_CASE("Archive_enctypted") {
  SECTION("archive_encrypted2") {
    REQUIRE(std::filesystem::exists(archive_encrypted2));
    auto node = mrpa::NodeFromFileFactory(archive_encrypted2,
                                          mrpa::TreeContext::NextId());
    REQUIRE(node);
    REQUIRE(node->type == mrpa::NodeType::kZip);
    auto zip_node = std::static_pointer_cast<mrpa::ZipNode>(node);
    REQUIRE(zip_node);
    REQUIRE(zip_node->id > 0);
    REQUIRE(zip_node->type == mrpa::NodeType::kZip);
    REQUIRE(zip_node->zip->size() > 0);
    REQUIRE(boost::algorithm::contains(zip_node->children.at(0)->ToString(),
                                       "Encrypted:1;"));
    REQUIRE(
      boost::algorithm::contains(zip_node->ToString(), "number of children:1"));
  }
}

TEST_CASE("NormalizeDirs") {
  mrpa::VecNodes vec;
  REQUIRE(mrpa::NormalizeNodeDirs(vec).empty());
  auto node = std::make_shared<mrpa::FileNode>("dir1/dir2/dir3/file.txt",
                                               mrpa::NodeType::kFile, 1, false);
  node->file_stat.name = "dir1/dir2/dir3/file.txt";
  vec.emplace_back(std::move(node));
  node = std::make_shared<mrpa::FileNode>("dir1/dir2/dir4/file2.txt",
                                          mrpa::NodeType::kFile, 1, false);
  node->file_stat.name = "dir1/dir2/dir4/file2.txt";
  vec.emplace_back(std::move(node));
  auto result = mrpa::NormalizeNodeDirs(vec);
  REQUIRE(result.size() == 1);
  REQUIRE(result.at(0)->type == mrpa::NodeType::kDir);
}

#ifndef SKIP_SENSITIVE

TEST_CASE("TreeContextPrivate") {
  // no root exist
  REQUIRE(mrpa::TestTreePrivate::EmptyRootToJson());
  REQUIRE(mrpa::TestTreePrivate::EmptyRootBuildTables());
  mrpa::TreeContext tree;
  // node not found
  REQUIRE(mrpa::TestTreePrivate::GetNodeByID(tree, 100) == nullptr);
  REQUIRE(tree.AddFile(archive_real1));
  auto first_child_id = mrpa::TestTreePrivate::FirstChildId(tree);
  REQUIRE(mrpa::TestTreePrivate::GetNodeByID(tree, first_child_id) != nullptr);
  // expired(deleted) node
  mrpa::TestTreePrivate::ExpireAll(tree);
  REQUIRE(mrpa::TestTreePrivate::GetNodeByID(tree, first_child_id) == nullptr);
  REQUIRE(mrpa::TestTreePrivate::GetParent(tree, first_child_id) == nullptr);
  // no parent
  REQUIRE(mrpa::TestTreePrivate::GetParent(tree, 0) == nullptr);

  REQUIRE(tree.AddFile(archive_real1));
  first_child_id = mrpa::TestTreePrivate::FirstChildId(tree);
  REQUIRE(mrpa::TestTreePrivate::GetNodeByID(tree, first_child_id)->type ==
          mrpa::NodeType::kZip);

  mrpa::PtrNode zip_node =
    mrpa::TestTreePrivate::GetNodeByID(tree, first_child_id);
  REQUIRE_FALSE(mrpa::TestTreePrivate::GetChilds(zip_node).empty());

  // get childs from Asig
  tree = mrpa::TreeContext();
  REQUIRE(tree.AddFile(attached_valid_sig2));
  first_child_id = mrpa::TestTreePrivate::FirstChildId(tree);
  REQUIRE(mrpa::TestTreePrivate::GetNodeByID(tree, first_child_id)->type ==
          mrpa::NodeType::kAsig);

  mrpa::PtrNode asig_node =
    mrpa::TestTreePrivate::GetNodeByID(tree, first_child_id);
  REQUIRE(asig_node);
  REQUIRE(mrpa::TestTreePrivate::GetChilds(asig_node).size() == 1);
  auto file_node = mrpa::TestTreePrivate::GetChilds(asig_node).at(0);
  REQUIRE(file_node);
  REQUIRE(mrpa::TestTreePrivate::GetChilds(file_node).empty());
  REQUIRE(mrpa::TestTreePrivate::GetSiblings(tree, 0).empty());
}

TEST_CASE("TreeContext") {
  mrpa::TreeContext tree;

  REQUIRE(tree.AddFile(archive_real1));
  REQUIRE(mrpa::TestTreePrivate::getLookUpTables(tree).all_nodes.size() == 20);
  REQUIRE(tree.AddFile(attached_valid_sig2));
  REQUIRE(mrpa::TestTreePrivate::getLookUpTables(tree).all_nodes.size() == 22);
  REQUIRE(tree.AddFile(archive_real2));
  REQUIRE(mrpa::TestTreePrivate::getLookUpTables(tree).all_nodes.size() == 228);
  REQUIRE_FALSE(boost::json::serialize(tree.ToJson()).empty());
  REQUIRE_FALSE(tree.AddFile(""));
  // all detched signature must have an associated file
  const auto& sig_table =
    mrpa::TestTreePrivate::getLookUpTables(tree).sig_nodes;
  REQUIRE(std::all_of(sig_table.cbegin(), sig_table.cend(),
                      [](const auto& pair_node) {
                        return !pair_node.second.expired() &&
                               pair_node.second.lock()->refs.size() == 1;
                      }));

  // std::cout << boost::json::serialize(tree.ToJson()) << "\n";

  // const auto& lookup_tables = tree.getLookUpTables();
  // std::cout << "ALL NODES:" << lookup_tables.all_nodes.size() << "\n";
  // std::cout << "FILE NODES:" << lookup_tables.file_nodes.size() << "\n";
  // std::cout << "MRPA NODES:" << lookup_tables.mrpa_nodes.size() << "\n";
  // std::cout << "SIG NODES:" << lookup_tables.sig_nodes.size() << "\n";
}

#endif

TEST_CASE("CheckOneSigNode") {
  const std::string src1 = std::string(TEST_FILES_DIR) + "mrpa/sigs/src1.txt";
  const std::string src1_copy =
    std::string(TEST_FILES_DIR) + "mrpa/sigs/src1_copy.txt";
  const std::string src1_bad_copy =
    std::string(TEST_FILES_DIR) + "mrpa/sigs/src1_bad_copy.txt";
  const std::string sig_file =
    std::string(TEST_FILES_DIR) + "mrpa/sigs/src1.txt.sig";
  REQUIRE(std::filesystem::exists(src1));
  REQUIRE(std::filesystem::exists(src1_copy));
  REQUIRE(std::filesystem::exists(src1_bad_copy));
  REQUIRE(std::filesystem::exists(sig_file));

  SECTION("Two_valid") {
    auto sig_node =
      std::make_shared<mrpa::SigNode>(sig_file, mrpa::NodeType::kSig, 1, false);
    auto file1_node =
      std::make_shared<mrpa::FileNode>(src1, mrpa::NodeType::kFile, 2, false);
    auto file2_node = std::make_shared<mrpa::FileNode>(
      src1_copy, mrpa::NodeType::kFile, 3, false);
    sig_node->refs.emplace_back(file1_node->weak_from_this());
    sig_node->refs.emplace_back(file2_node->weak_from_this());
    mrpa::CheckOneSigNode(sig_node);
    REQUIRE(sig_node->refs.size() == 2);
    REQUIRE(sig_node->check_res.size() == 2);
    REQUIRE(std::all_of(sig_node->check_res.cbegin(),
                        sig_node->check_res.cend(), [](const auto& pr_res) {
                          return pr_res.second &&
                                 pr_res.second->bres.check_summary;
                        }));
  }

  SECTION("Two_valid_plus_one_invalid") {
    auto sig_node =
      std::make_shared<mrpa::SigNode>(sig_file, mrpa::NodeType::kSig, 1, false);
    auto file1_node =
      std::make_shared<mrpa::FileNode>(src1, mrpa::NodeType::kFile, 2, false);
    auto file2_node = std::make_shared<mrpa::FileNode>(
      src1_copy, mrpa::NodeType::kFile, 3, false);
    auto file3_node = std::make_shared<mrpa::FileNode>(
      src1_bad_copy, mrpa::NodeType::kFile, 4, false);
    sig_node->refs.emplace_back(file1_node->weak_from_this());
    sig_node->refs.emplace_back(file2_node->weak_from_this());
    sig_node->refs.emplace_back(file3_node->weak_from_this());
    mrpa::CheckOneSigNode(sig_node);
    // bad association (file3) must be automatically removed
    REQUIRE(sig_node->refs.size() == 2);
    REQUIRE(sig_node->check_res.size() == 2);
    REQUIRE(std::all_of(sig_node->check_res.cbegin(),
                        sig_node->check_res.cend(), [](const auto& pr_res) {
                          return pr_res.second &&
                                 pr_res.second->bres.check_summary;
                        }));
  }
}