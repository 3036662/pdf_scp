#include <filesystem>
#include <memory>

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

TEST_CASE("Initial") { REQUIRE(true); }

TEST_CASE("DefaultConstructor") { REQUIRE_NOTHROW(mrpa::TreeContext()); }

TEST_CASE("CreateNodeFromFile") {
  SECTION("empty path") {
    REQUIRE(mrpa::createNodeFromFile("", mrpa::TreeContext::NextId()) ==
            nullptr);
  }
  SECTION("nonexisting") {
    REQUIRE(mrpa::createNodeFromFile("blabla", mrpa::TreeContext::NextId()) ==
            nullptr);
  }
  SECTION("not a file") {
    REQUIRE(mrpa::createNodeFromFile("/home", mrpa::TreeContext::NextId()) ==
            nullptr);
  }
  SECTION("Regular file 1") {
    auto node =
      mrpa::createNodeFromFile(regular_file1, mrpa::TreeContext::NextId());
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
    auto node = mrpa::createNodeFromFile(attached_invalid_sig1,
                                         mrpa::TreeContext::NextId());
    REQUIRE(node);
    REQUIRE(node->id > 0);
    REQUIRE(node->type == mrpa::NodeType::kAsig);
    auto asig_node = std::static_pointer_cast<mrpa::AsigNode>(node);
    REQUIRE(asig_node);
    REQUIRE(asig_node->file_stat.name);
    REQUIRE(asig_node->file_stat.name.value() == "attached993.sig");
    REQUIRE(asig_node->check_res);
    REQUIRE(asig_node->check_res->common_execution_status);
    REQUIRE_FALSE(asig_node->check_res->bres.check_summary);
  }
  SECTION("Attached_valid_asig_2") {
    if (std::filesystem::exists(attached_valid_sig2)) {
      auto node = mrpa::createNodeFromFile(attached_valid_sig2,
                                           mrpa::TreeContext::NextId());
      REQUIRE(node);
      REQUIRE(node->id > 0);
      REQUIRE(node->type == mrpa::NodeType::kAsig);
      auto asig_node = std::static_pointer_cast<mrpa::AsigNode>(node);
      REQUIRE(asig_node);
      REQUIRE(asig_node->file_stat.name);
      REQUIRE(asig_node->file_stat.name.value() ==
              "signme.pdf_BASE-64_CAdES-BES.sgn");
      REQUIRE(asig_node->check_res);
      REQUIRE(asig_node->check_res->common_execution_status);
      REQUIRE(asig_node->check_res->bres.check_summary);
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
}