#include <boost/json/serialize.hpp>
#include <filesystem>
#include <memory>
#include <string>

#include "common_utils.hpp"
#include "node.hpp"
#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

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
    std::cout << zip_node->children.at(0)->ToString() << "\n";
  }
}

TEST_CASE("TreeContext") {
  mrpa::TreeContext tree;
  REQUIRE_FALSE(tree.AddFile(""));
  REQUIRE_FALSE(tree.AddFile("blabla"));
  if (!std::filesystem::exists(archive_real1) ||
      !std::filesystem::exists(archive_real2) ||
      !std::filesystem::exists(attached_valid_sig2)) {
    return;
  }
  REQUIRE(tree.AddFile(archive_real1));
  REQUIRE(tree.getLookUpTables().all_nodes.size() == 20);
  REQUIRE(tree.AddFile(attached_valid_sig2));
  REQUIRE(tree.getLookUpTables().all_nodes.size() == 22);
  REQUIRE(tree.AddFile(archive_real2));
  REQUIRE(tree.getLookUpTables().all_nodes.size() == 228);

  REQUIRE_FALSE(boost::json::serialize(tree.ToJson()).empty());

  // const auto& lookup_tables = tree.getLookUpTables();
  // std::cout << "ALL NODES:" << lookup_tables.all_nodes.size() << "\n";
  // std::cout << "FILE NODES:" << lookup_tables.file_nodes.size() << "\n";
  // std::cout << "MRPA NODES:" << lookup_tables.mrpa_nodes.size() << "\n";
  // std::cout << "SIG NODES:" << lookup_tables.sig_nodes.size() << "\n";
}