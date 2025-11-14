#include <algorithm>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/json/array.hpp>
#include <boost/json/object.hpp>
#include <boost/json/serialize.hpp>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>
#include <thread>
#include <tuple>

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

const std::string archive_real3 =
  std::string(TEST_FILES_DIR) +
  "mrpa/sensitive/Входящий УПД №0089714952 от 19.05.25.zip";

const std::string archive_real4 =
  std::string(TEST_FILES_DIR) +
  "mrpa/sensitive/Входящий счет №2505-422782-26317 от 14.05.25.zip";

const std::string archive_real5 =
  std::string(TEST_FILES_DIR) + "mrpa/sensitive/1.zip";
const std::string archive_real6 =
  std::string(TEST_FILES_DIR) + "mrpa/sensitive/2.zip";
const std::string archive_real7 =
  std::string(TEST_FILES_DIR) + "mrpa/sensitive/3.zip";
const std::string archive_real8 =
  std::string(TEST_FILES_DIR) + "mrpa/sensitive/4.zip";
const std::string archive_real9 =
  std::string(TEST_FILES_DIR) + "mrpa/sensitive/5.zip";

const std::string detached_valid1 =
  std::string(TEST_FILES_DIR) + "mrpa/sigs/src1.txt.sig";
const std::string detached_valid1_src =
  std::string(TEST_FILES_DIR) + "mrpa/sigs/src1.txt";

const std::string mrpa_valid2 =
  std::string(TEST_FILES_DIR) +
  "mrpa/sensitive/valid_mrpa_real/"
  "ON_EMCHD_20241210_5fd0cfce-3587-4b00-8501-1a6aebcacda9.xml";

const std::string mrpa_valid2_sig =
  std::string(TEST_FILES_DIR) +
  "mrpa/sensitive/valid_mrpa_real/"
  "ON_EMCHD_20241210_5fd0cfce-3587-4b00-8501-1a6aebcacda9.sig";

const std::string mrpa_in_zip =
  std::string(TEST_FILES_DIR) +
  "mrpa/sensitive/valid_mrpa_real/"
  "ON_EMCHD_20241210_5fd0cfce-3587-4b00-8501-1a6aebcacda9.zip";

const std::string mrpa_in_zip_plus_file =
  std::string(TEST_FILES_DIR) +
  "mrpa/sensitive/valid_mrpa_real/"
  "ON_EMCHD_20241210_5fd0cfce-3587-4b00-8501-1a6aebcacda9_with_other_file.zip";

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
    sig_node->refs.emplace(file1_node->id, file1_node->weak_from_this());
    sig_node->refs.emplace(file2_node->id, file2_node->weak_from_this());
    REQUIRE(sig_node->refs.size() == 2);
    mrpa::CheckOneSigNode(sig_node, nullptr);
    REQUIRE(sig_node->refs.size() == 0);
    // expired
    // REQUIRE(sig_node->check_res.size() == 2);
    // REQUIRE(std::all_of(sig_node->check_res.cbegin(),
    //                     sig_node->check_res.cend(), [](const auto& pr_res) {
    //                       return pr_res.second &&
    //                              pr_res.second->bres.check_summary;
    //                     }));
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
    sig_node->refs.emplace(file1_node->id, file1_node->weak_from_this());
    sig_node->refs.emplace(file2_node->id, file2_node->weak_from_this());
    sig_node->refs.emplace(file3_node->id, file3_node->weak_from_this());
    mrpa::CheckOneSigNode(sig_node, nullptr);
    // bad association (file3) must be automatically removed
    // EXPIRED
    // REQUIRE(sig_node->refs.size() == 2);
    // REQUIRE(sig_node->check_res.size() == 2);
    // REQUIRE(std::all_of(sig_node->check_res.cbegin(),
    //                     sig_node->check_res.cend(), [](const auto& pr_res) {
    //                       return pr_res.second &&
    //                              pr_res.second->bres.check_summary;
    //                     }));
    // make sure that files are connected to signatures
    // REQUIRE(file1_node->refs.size() == 1);
    // REQUIRE(file1_node->refs.count(1) == 1);
    // REQUIRE(file2_node->refs.size() == 1);
    // REQUIRE(file2_node->refs.count(1) == 1);
    // REQUIRE(file3_node->refs.empty());
  }
}

#ifndef SKIP_SENSITIVE

TEST_CASE("BindMrpaSigners") {
  const std::string mrpa_file =
    std::string(TEST_FILES_DIR) +
    "mrpa/sensitive/ON_EMCHD_20241210_5fd0cfce-3587-4b00-8501-1a6aebcacda9.xml";
  const std::string sig1_file =
    std::string(TEST_FILES_DIR) +
    "mrpa/sensitive/ON_EMCHD_20241210_5fd0cfce-3587-4b00-8501-1a6aebcacda9.sig";
  const std::string sig2_file_fake =
    std::string(TEST_FILES_DIR) +
    "mrpa/sensitive/"
    "ON_EMCHD_20241210_5fd0cfce-3587-4b00-8501-1a6aebcacda9_FAKE.xml.sig";
  mrpa::TreeContext tree;
  REQUIRE(tree.AddFile(mrpa_file, false));
  REQUIRE(tree.AddFile(sig1_file, false));
  REQUIRE(tree.AddFile(sig2_file_fake, true));  // with context build
  std::cout << boost::json::serialize(tree.ToJson()) << "\n";
  auto lookup_tales = mrpa::TestTreePrivate::getLookUpTables(tree);
  REQUIRE(lookup_tales.all_nodes.size() == 4);
  REQUIRE(lookup_tales.mrpa_nodes.size() == 1);
  auto mrpa_id = lookup_tales.mrpa_nodes.begin()->first;
  REQUIRE(mrpa::TestTreePrivate::GetSiblings(tree, mrpa_id).size() == 2);
  auto mrpa_node = mrpa::TestTreePrivate::GetNodeByID(tree, mrpa_id);
  REQUIRE(mrpa_node);
  REQUIRE(mrpa_node->refs.size() == 1);

  // remove all check results and rebind
  for (const auto& pr_sig : lookup_tales.sig_nodes) {
    std::static_pointer_cast<mrpa::SigNode>(pr_sig.second.lock())
      ->check_res.clear();
  }
  mrpa::TestTreePrivate::BindMrpaSigners(tree);
  REQUIRE(mrpa_node->refs.size() == 0);
}

TEST_CASE("TreeContextPrivate") {
  // no root exist
  {
    REQUIRE(mrpa::TestTreePrivate::EmptyRootToJson());
    REQUIRE(mrpa::TestTreePrivate::EmptyRootBuildTables());
    mrpa::TreeContext tree;
    // node not found
    REQUIRE(mrpa::TestTreePrivate::GetNodeByID(tree, 100) == nullptr);
    REQUIRE(tree.AddFile(archive_real1));
    auto first_child_id = mrpa::TestTreePrivate::FirstChildId(tree);
    REQUIRE(mrpa::TestTreePrivate::GetNodeByID(tree, first_child_id) !=
            nullptr);
    // expired(deleted) node
    mrpa::TestTreePrivate::ExpireAll(tree);
    REQUIRE(mrpa::TestTreePrivate::GetNodeByID(tree, first_child_id) ==
            nullptr);
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
  }
  // get childs from Asig
  mrpa::TreeContext tree;
  REQUIRE(tree.AddFile(attached_valid_sig2));
  auto first_child_id = mrpa::TestTreePrivate::FirstChildId(tree);
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

TEST_CASE("CheckOnlyMrpaSigs") {
  mrpa::TreeContext tree;
  REQUIRE(tree.AddFile(archive_real1, false));
  auto begin = std::chrono::steady_clock::now();
  mrpa::TestTreePrivate::BuildLookupTables(tree);
  mrpa::TestTreePrivate::BindDetachedSignatures(tree);
  mrpa::TestTreePrivate::CheckOnlyMrpaSigs(tree);
  auto end = std::chrono::steady_clock::now();
  const auto lookup_tables = mrpa::TestTreePrivate::getLookUpTables(tree);
  const bool sig_are_checked_for_mrpas =
    // all sig nodes must have check results only for mrpa nodes
    std::all_of(
      lookup_tables.sig_nodes.cbegin(), lookup_tables.sig_nodes.cend(),
      [&lookup_tables](const auto& pr_sig) {
        const auto& [sig_id, sig_wp] = pr_sig;
        if (sig_wp.expired()) {
          return true;
        }
        auto sig_node = std::static_pointer_cast<mrpa::SigNode>(sig_wp.lock());
        return std::all_of(sig_node->check_res.cbegin(),
                           sig_node->check_res.cend(),
                           [&lookup_tables](const auto& pr_res) {
                             const auto& [res_id, res_ptr] = pr_res;
                             return lookup_tables.mrpa_nodes.count(res_id);
                           });
      });
  std::cout << "TIME TO CHECK ONLY MRPAs : "
            << std::chrono::duration_cast<std::chrono::milliseconds>(end -
                                                                     begin)
                 .count()
            << "ms\n";

  REQUIRE(sig_are_checked_for_mrpas);

  mrpa::TestTreePrivate::BindMrpaSigners(tree);
}

TEST_CASE("TreeContext") {
  auto begin = std::chrono::steady_clock::now();
  mrpa::TreeContext tree;
  REQUIRE(tree.AddFile(archive_real1));
  REQUIRE(mrpa::TestTreePrivate::getLookUpTables(tree).all_nodes.size() == 20);
  REQUIRE(tree.AddFile(attached_valid_sig2));
  REQUIRE(mrpa::TestTreePrivate::getLookUpTables(tree).all_nodes.size() == 22);
  REQUIRE(tree.AddFile(archive_real2));
  REQUIRE(mrpa::TestTreePrivate::getLookUpTables(tree).all_nodes.size() == 228);
  REQUIRE_FALSE(boost::json::serialize(tree.ToJson()).empty());
  REQUIRE_FALSE(tree.AddFile(""));
  auto end = std::chrono::steady_clock::now();
  std::cout << "TIME TO BUILD THE TREE: "
            << std::chrono::duration_cast<std::chrono::milliseconds>(end -
                                                                     begin)
                 .count()
            << "ms\n";

  // all detched signature must have an associated file
  const auto& sig_table =
    mrpa::TestTreePrivate::getLookUpTables(tree).sig_nodes;
  REQUIRE(std::all_of(sig_table.cbegin(), sig_table.cend(),
                      [](const auto& pair_node) {
                        return !pair_node.second.expired() &&
                               pair_node.second.lock()->refs.size() == 1;
                      }));

  // all attached signatures must have a check result
  const auto& att_sig_table =
    mrpa::TestTreePrivate::getLookUpTables(tree).asig_nodes;
  REQUIRE(std::all_of(
    att_sig_table.cbegin(), att_sig_table.cend(), [](const auto& pair_node) {
      return !pair_node.second.expired() &&
             std::static_pointer_cast<mrpa::AsigNode>(pair_node.second.lock())
               ->check_res;
    }));

  std::cout << boost::json::serialize(tree.ToJson()) << "\n";

  const auto& lookup_tables = mrpa::TestTreePrivate::getLookUpTables(tree);
  std::cout << "ALL NODES:" << lookup_tables.all_nodes.size() << "\n";
  std::cout << "FILE NODES:" << lookup_tables.file_nodes.size() << "\n";
  std::cout << "MRPA NODES:" << lookup_tables.mrpa_nodes.size() << "\n";
  std::cout << "SIG NODES:" << lookup_tables.sig_nodes.size() << "\n";
}

TEST_CASE("TreeContextReal3") {
  auto begin = std::chrono::steady_clock::now();
  mrpa::TreeContext tree;
  REQUIRE(tree.AddFile(archive_real3));
  // REQUIRE(mrpa::TestTreePrivate::getLookUpTables(tree).all_nodes.size() ==
  // 20);
  auto end = std::chrono::steady_clock::now();
  std::cout << "TIME TO BUILD THE TREE: "
            << std::chrono::duration_cast<std::chrono::milliseconds>(end -
                                                                     begin)
                 .count()
            << "ms\n";

  // all detched signature must have an associated file
  const auto& sig_table =
    mrpa::TestTreePrivate::getLookUpTables(tree).sig_nodes;
  REQUIRE(std::all_of(sig_table.cbegin(), sig_table.cend(),
                      [](const auto& pair_node) {
                        return !pair_node.second.expired() &&
                               pair_node.second.lock()->refs.size() == 1;
                      }));

  // all attached signatures must have a check result
  const auto& att_sig_table =
    mrpa::TestTreePrivate::getLookUpTables(tree).asig_nodes;
  REQUIRE(std::all_of(
    att_sig_table.cbegin(), att_sig_table.cend(), [](const auto& pair_node) {
      return !pair_node.second.expired() &&
             std::static_pointer_cast<mrpa::AsigNode>(pair_node.second.lock())
               ->check_res->bres.check_summary;
    }));

  // none of mrpa must have ref to signature, (mrpa signer's certificate is
  // expired)
  const auto& mrpa_table =
    mrpa::TestTreePrivate::getLookUpTables(tree).asig_nodes;
  REQUIRE(std::none_of(
    mrpa_table.cbegin(), mrpa_table.cend(), [](const auto& pr_mrpa) {
      const auto& [id_mrpa, wp_mrpa] = pr_mrpa;
      return !wp_mrpa.expired() &&
             std::static_pointer_cast<mrpa::MrpaNode>(wp_mrpa.lock())
                 ->refs.size() == 1;
    }));

  std::cout << boost::json::serialize(tree.ToJson()) << "\n";

  const auto& lookup_tables = mrpa::TestTreePrivate::getLookUpTables(tree);
  std::cout << "ALL NODES:" << lookup_tables.all_nodes.size() << "\n";
  std::cout << "FILE NODES:" << lookup_tables.file_nodes.size() << "\n";
  std::cout << "MRPA NODES:" << lookup_tables.mrpa_nodes.size() << "\n";
  std::cout << "SIG NODES:" << lookup_tables.sig_nodes.size() << "\n";
}

TEST_CASE("TreeContextReal4") {
  auto begin = std::chrono::steady_clock::now();
  mrpa::TreeContext tree;
  REQUIRE(tree.AddFile(archive_real4));
  // REQUIRE(mrpa::TestTreePrivate::getLookUpTables(tree).all_nodes.size() ==
  // 20);
  auto end = std::chrono::steady_clock::now();
  std::cout << "TIME TO BUILD THE TREE: "
            << std::chrono::duration_cast<std::chrono::milliseconds>(end -
                                                                     begin)
                 .count()
            << "ms\n";

  // all detched signature must have an associated file
  const auto& sig_table =
    mrpa::TestTreePrivate::getLookUpTables(tree).sig_nodes;
  REQUIRE(std::all_of(sig_table.cbegin(), sig_table.cend(),
                      [](const auto& pair_node) {
                        return !pair_node.second.expired() &&
                               pair_node.second.lock()->refs.size() == 1;
                      }));

  // all attached signatures must have a check result
  const auto& att_sig_table =
    mrpa::TestTreePrivate::getLookUpTables(tree).asig_nodes;
  REQUIRE(std::all_of(
    att_sig_table.cbegin(), att_sig_table.cend(), [](const auto& pair_node) {
      return !pair_node.second.expired() &&
             std::static_pointer_cast<mrpa::AsigNode>(pair_node.second.lock())
               ->check_res->bres.check_summary;
    }));

  // all mrpa must have ref to signature
  const auto& mrpa_table =
    mrpa::TestTreePrivate::getLookUpTables(tree).asig_nodes;
  REQUIRE(std::all_of(
    mrpa_table.cbegin(), mrpa_table.cend(), [](const auto& pr_mrpa) {
      const auto& [id_mrpa, wp_mrpa] = pr_mrpa;
      return !wp_mrpa.expired() &&
             std::static_pointer_cast<mrpa::MrpaNode>(wp_mrpa.lock())
                 ->refs.size() == 1;
    }));

  std::cout << boost::json::serialize(tree.ToJson()) << "\n";

  const auto& lookup_tables = mrpa::TestTreePrivate::getLookUpTables(tree);
  std::cout << "ALL NODES:" << lookup_tables.all_nodes.size() << "\n";
  std::cout << "FILE NODES:" << lookup_tables.file_nodes.size() << "\n";
  std::cout << "MRPA NODES:" << lookup_tables.mrpa_nodes.size() << "\n";
  std::cout << "SIG NODES:" << lookup_tables.sig_nodes.size() << "\n";
}

TEST_CASE("FiveRealArchives") {
  auto begin = std::chrono::steady_clock::now();
  mrpa::TreeContext tree;
  REQUIRE(tree.AddFile(archive_real5, false));
  REQUIRE(tree.AddFile(archive_real6, false));
  REQUIRE(tree.AddFile(archive_real7, false));
  REQUIRE(tree.AddFile(archive_real8, false));
  REQUIRE(tree.AddFile(archive_real9, true));
  auto end = std::chrono::steady_clock::now();
  std::cout << "TIME TO BUILD THE TREE: "
            << std::chrono::duration_cast<std::chrono::milliseconds>(end -
                                                                     begin)
                 .count()
            << "ms\n";

  // all detched signature must have an associated file
  const auto& sig_table =
    mrpa::TestTreePrivate::getLookUpTables(tree).sig_nodes;
  REQUIRE(std::all_of(sig_table.cbegin(), sig_table.cend(),
                      [](const auto& pair_node) {
                        return !pair_node.second.expired() &&
                               pair_node.second.lock()->refs.size() == 1;
                      }));

  // all attached signatures must have a check result
  const auto& att_sig_table =
    mrpa::TestTreePrivate::getLookUpTables(tree).asig_nodes;
  REQUIRE(std::all_of(
    att_sig_table.cbegin(), att_sig_table.cend(), [](const auto& pair_node) {
      return !pair_node.second.expired() &&
             std::static_pointer_cast<mrpa::AsigNode>(pair_node.second.lock())
               ->check_res->bres.check_summary;
    }));

  // all mrpa must have ref to signature
  const auto& mrpa_table =
    mrpa::TestTreePrivate::getLookUpTables(tree).asig_nodes;
  REQUIRE(std::all_of(
    mrpa_table.cbegin(), mrpa_table.cend(), [](const auto& pr_mrpa) {
      const auto& [id_mrpa, wp_mrpa] = pr_mrpa;
      return !wp_mrpa.expired() &&
             std::static_pointer_cast<mrpa::MrpaNode>(wp_mrpa.lock())
                 ->refs.size() == 1;
    }));

  std::cout << boost::json::serialize(tree.ToJson()) << "\n";

  const auto& lookup_tables = mrpa::TestTreePrivate::getLookUpTables(tree);
  std::cout << "ALL NODES:" << lookup_tables.all_nodes.size() << "\n";
  std::cout << "FILE NODES:" << lookup_tables.file_nodes.size() << "\n";
  std::cout << "MRPA NODES:" << lookup_tables.mrpa_nodes.size() << "\n";
  std::cout << "SIG NODES:" << lookup_tables.sig_nodes.size() << "\n";
}

TEST_CASE("Multithreaded") {
  using namespace std::chrono_literals;
  SECTION("getJSONwhilebusy") {
    mrpa::TreeContext tree;
    std::thread th1([&tree]() {
      std::ignore = tree.AddFile(archive_real1);
      std::cout << "[TEST]" << std::this_thread::get_id() << " thread sleep;\n";
      std::this_thread::sleep_for(1000ms);
      std::cout << "[TEST]" << std::this_thread::get_id() << " thread ready;\n";
    });
    std::this_thread::sleep_for(200ms);
    std::cout << "[TEST]" << std::this_thread::get_id() << " read json;\n";
    REQUIRE(tree.ToJson().empty());
    th1.join();
  }
}

TEST_CASE("add_file_while_getting_JSON") {
  SECTION("add_file_while_getting_JSON") {
    using namespace std::chrono_literals;
    mrpa::TreeContext tree;
    REQUIRE(tree.AddFile(archive_real1, false));
    std::thread th1([&tree]() {
      std::cout << "[TEST]" << std::this_thread::get_id() << " read JSON;\n";
      REQUIRE_FALSE(tree.ToJson().empty());
      std::cout << "[TEST]" << std::this_thread::get_id() << " thread sleep;\n";
      mrpa::TestTreePrivate::LockShared(tree);
      std::this_thread::sleep_for(1000ms);
      mrpa::TestTreePrivate::UnlockShared(tree);
      std::cout << "[TEST]" << std::this_thread::get_id() << " thread ready;\n";
    });
    std::this_thread::sleep_for(200ms);
    REQUIRE_FALSE(tree.AddFile(archive_real2));
    std::cout << "[TEST]" << std::this_thread::get_id() << " add_file;\n";
    th1.join();
  }
}

TEST_CASE("build_context_while_getting_JSON") {
  SECTION("add_file_while_getting_JSON") {
    using namespace std::chrono_literals;
    mrpa::TreeContext tree;
    REQUIRE(tree.AddFile(archive_real1, false));
    std::thread th1([&tree]() {
      std::cout << "[TEST]" << std::this_thread::get_id() << " read JSON;\n";
      REQUIRE_FALSE(tree.ToJson().empty());
      std::cout << "[TEST]" << std::this_thread::get_id() << " thread sleep;\n";
      mrpa::TestTreePrivate::LockShared(tree);
      std::this_thread::sleep_for(1000ms);
      mrpa::TestTreePrivate::UnlockShared(tree);
      std::cout << "[TEST]" << std::this_thread::get_id() << " thread ready;\n";
    });
    std::this_thread::sleep_for(200ms);
    REQUIRE_FALSE(tree.AddFile(archive_real2, false));
    REQUIRE_FALSE(tree.BuildContext());
    std::cout << "[TEST]" << std::this_thread::get_id() << " build context;\n";
    th1.join();
  }
}

TEST_CASE("AddFileListJson") {
  SECTION("two files") {
    boost::json::array jarr;
    jarr.emplace_back(archive_real1);
    jarr.emplace_back(archive_real2);
    mrpa::TreeContext tree;
    REQUIRE(tree.AddFileListJson(boost::json::serialize(jarr)));
    REQUIRE(tree.ToJson().at("children").as_array().size() == 2);
  }

  SECTION("empty_JSON") {
    boost::json::array jarr;
    mrpa::TreeContext tree;
    REQUIRE(tree.AddFileListJson(boost::json::serialize(jarr)));
    REQUIRE(tree.ToJson().at("children").as_array().empty());
  }
  SECTION("locked_context") {
    boost::json::array jarr;
    jarr.emplace_back(archive_real1);
    jarr.emplace_back(archive_real2);
    mrpa::TreeContext tree;
    mrpa::TestTreePrivate::Lock(tree);
    REQUIRE_FALSE(tree.AddFileListJson(boost::json::serialize(jarr)));
    mrpa::TestTreePrivate::Unlock(tree);
    REQUIRE(tree.ToJson().at("children").as_array().size() == 0);
  }
  SECTION("json_object") {
    boost::json::object object;
    object["name"] = "ObjectName";
    mrpa::TreeContext tree;
    REQUIRE_FALSE(tree.AddFileListJson(boost::json::serialize(object)));
  }
  SECTION("invalid_json") {
    mrpa::TreeContext tree;
    REQUIRE_FALSE(tree.AddFileListJson("fdsf\\\'"));
  }
  SECTION("empty_string") {
    mrpa::TreeContext tree;
    REQUIRE_FALSE(tree.AddFileListJson(""));
  }
}

TEST_CASE("tree_reset") {
  SECTION("Normal") {
    boost::json::array jarr;
    jarr.emplace_back(archive_real1);
    mrpa::TreeContext tree;
    REQUIRE(tree.AddFileListJson(boost::json::serialize(jarr)));
    REQUIRE(tree.Reset());
    REQUIRE(tree.ToJson().at("children").as_array().size() == 0);
  }
  SECTION("Busy") {
    boost::json::array jarr;
    jarr.emplace_back(archive_real1);
    mrpa::TreeContext tree;
    REQUIRE(tree.AddFileListJson(boost::json::serialize(jarr)));
    mrpa::TestTreePrivate::Lock(tree);
    REQUIRE_FALSE(tree.Reset());
    mrpa::TestTreePrivate::Unlock(tree);
    REQUIRE(tree.ToJson().at("children").as_array().size() == 1);
  }
}

TEST_CASE("RemoveNode") {
  SECTION("Normal") {
    boost::json::array jarr;
    jarr.emplace_back(archive_real1);
    jarr.emplace_back(archive_real2);
    mrpa::TreeContext tree;
    REQUIRE(tree.AddFileListJson(boost::json::serialize(jarr)));
    REQUIRE(tree.BuildContext());
    REQUIRE(tree.ToJson().at("children").as_array().size() == 2);
    auto id_for_remove = mrpa::TestTreePrivate::FirstChildId(tree);
    REQUIRE(tree.RemoveNode(id_for_remove));
    REQUIRE(tree.ToJson().at("children").as_array().size() == 1);
  }
  SECTION("Remove without building context") {
    boost::json::array jarr;
    jarr.emplace_back(archive_real1);
    jarr.emplace_back(archive_real2);
    mrpa::TreeContext tree;
    REQUIRE(tree.AddFileListJson(boost::json::serialize(jarr)));
    REQUIRE(tree.BuildContext());
    REQUIRE(tree.ToJson().at("children").as_array().size() == 2);
    auto id_for_remove = mrpa::TestTreePrivate::FirstChildId(tree);
    auto count_nodes_before =
      mrpa::TestTreePrivate::getLookUpTables(tree).all_nodes.size();
    REQUIRE(tree.RemoveNode(id_for_remove, false));
    auto count_nodes_after =
      mrpa::TestTreePrivate::getLookUpTables(tree).all_nodes.size();
    REQUIRE_FALSE(count_nodes_after + 1 == count_nodes_before);
    tree.BuildContext();
    REQUIRE(tree.ToJson().at("children").as_array().size() == 1);
  }
  SECTION("root") {
    boost::json::array jarr;
    jarr.emplace_back(archive_real1);
    jarr.emplace_back(archive_real2);
    mrpa::TreeContext tree;
    REQUIRE(tree.AddFileListJson(boost::json::serialize(jarr)));
    REQUIRE(tree.BuildContext());
    REQUIRE(tree.ToJson().at("children").as_array().size() == 2);
    REQUIRE_FALSE(tree.RemoveNode(0));
  }

  SECTION("nested") {
    boost::json::array jarr;
    jarr.emplace_back(archive_real1);
    jarr.emplace_back(archive_real2);
    mrpa::TreeContext tree;
    REQUIRE(tree.AddFileListJson(boost::json::serialize(jarr)));
    REQUIRE(tree.BuildContext());
    REQUIRE(tree.ToJson().at("children").as_array().size() == 2);
    mrpa::NodeId id_to_remove = tree.ToJson()
                                  .at("children")
                                  .as_array()
                                  .at(0)
                                  .as_object()
                                  .at("children")
                                  .as_array()
                                  .at(0)
                                  .as_object()
                                  .at("id")
                                  .as_uint64();
    REQUIRE_FALSE(tree.RemoveNode(id_to_remove));
  }

  SECTION("busy") {
    boost::json::array jarr;
    jarr.emplace_back(archive_real1);
    jarr.emplace_back(archive_real2);
    mrpa::TreeContext tree;
    REQUIRE(tree.AddFileListJson(boost::json::serialize(jarr)));
    REQUIRE(tree.BuildContext());
    REQUIRE(tree.ToJson().at("children").as_array().size() == 2);
    auto id_for_remove = mrpa::TestTreePrivate::FirstChildId(tree);
    mrpa::TestTreePrivate::Lock(tree);
    REQUIRE_FALSE(tree.RemoveNode(id_for_remove));
    mrpa::TestTreePrivate::Unlock(tree);
    REQUIRE(tree.ToJson().at("children").as_array().size() == 2);
  }
}

TEST_CASE("RemoveNodesJsonList") {
  SECTION("EmptyString") {
    mrpa::TreeContext tree;
    REQUIRE_FALSE(tree.RemoveNodesJsonList(""));
  }

  SECTION("Busy") {
    boost::json::array jarr;
    jarr.emplace_back(archive_real1);
    mrpa::TreeContext tree;
    REQUIRE(tree.AddFileListJson(boost::json::serialize(jarr)));
    REQUIRE(tree.BuildContext());
    auto node_to_delete = mrpa::TestTreePrivate::FirstChildId(tree);
    boost::json::array to_delete;
    to_delete.emplace_back(node_to_delete);
    mrpa::TestTreePrivate::Lock(tree);
    REQUIRE_FALSE(tree.RemoveNodesJsonList(boost::json::serialize(to_delete)));
    mrpa::TestTreePrivate::Unlock(tree);
  }

  SECTION("Invalid_JSON") {
    boost::json::array jarr;
    jarr.emplace_back(archive_real1);
    mrpa::TreeContext tree;
    REQUIRE(tree.AddFileListJson(boost::json::serialize(jarr)));
    REQUIRE(tree.BuildContext());
    REQUIRE_FALSE(tree.RemoveNodesJsonList("\\\\\'"));
  }

  SECTION("Invalid_JSON_object") {
    boost::json::array jarr;
    jarr.emplace_back(archive_real1);
    mrpa::TreeContext tree;
    REQUIRE(tree.AddFileListJson(boost::json::serialize(jarr)));
    REQUIRE(tree.BuildContext());
    boost::json::object obj;
    obj["name"] = "name";
    REQUIRE_FALSE(tree.RemoveNodesJsonList(boost::json::serialize(obj)));
  }

  SECTION("Normal") {
    boost::json::array jarr;
    jarr.emplace_back(archive_real1);
    mrpa::TreeContext tree;
    REQUIRE(tree.AddFileListJson(boost::json::serialize(jarr)));
    REQUIRE(tree.BuildContext());
    uint64_t node_to_delete = mrpa::TestTreePrivate::FirstChildId(tree);
    boost::json::array to_delete;
    to_delete.emplace_back(node_to_delete);
    std::cout << boost::json::serialize(to_delete) << "\n";
    REQUIRE(tree.RemoveNodesJsonList(boost::json::serialize(to_delete)));
  }
}

TEST_CASE("GetCheckResultByID") {
  SECTION("Asig_Sig") {
    mrpa::TreeContext tree;
    boost::json::array arr;
    arr.emplace_back(attached_valid_sig2);
    arr.emplace_back(detached_valid1);
    arr.emplace_back(detached_valid1_src);
    arr.emplace_back(src_simple_zip);
    REQUIRE(tree.AddFileListJson(boost::json::serialize(arr)));
    REQUIRE(tree.BuildContext());
    std::cout << boost::json::serialize(tree.ToJson()) << "\n";

    // busy
    mrpa::TestTreePrivate::Lock(tree);
    REQUIRE_FALSE(tree.GetSigCheckResult(1, 2));
    mrpa::TestTreePrivate::Unlock(tree);

    // normal
    const auto json_tree = tree.ToJson();
    const auto& children = json_tree.at("children").as_array();
    const auto* it_asig =
      std::find_if(children.cbegin(), children.cend(), [](const auto& child) {
        return child.as_object().at("type").as_string() == "Asig";
      });
    REQUIRE(it_asig != children.cend());
    mrpa::NodeId asig_id = it_asig->as_object().at("id").as_uint64();
    REQUIRE(it_asig->as_object().at("has_check_result").as_bool());
    mrpa::NodeId child_id = it_asig->as_object()
                              .at("children")
                              .as_array()
                              .at(0)
                              .as_object()
                              .at("id")
                              .as_uint64();
    auto check_res = tree.GetSigCheckResult(asig_id, child_id);
    REQUIRE(check_res);

    // non existing
    const auto check_res2 = tree.GetSigCheckResult(100, 5050);
    REQUIRE_FALSE(check_res2);

    // not a signature
    const auto check_res3 = tree.GetSigCheckResult(0, 0);
    REQUIRE_FALSE(check_res3);

    // detached signature
    const auto* it_dsig =
      std::find_if(children.cbegin(), children.cend(), [](const auto& child) {
        return child.as_object().at("type").as_string() == "Sig";
      });
    REQUIRE(it_dsig != children.cend());
    mrpa::NodeId dsig_id = it_dsig->as_object().at("id").as_uint64();
    REQUIRE(it_dsig->as_object().at("has_check_result").as_bool());
    mrpa::NodeId file_id =
      it_dsig->as_object().at("ref_ids").as_array().at(0).as_uint64();

    auto check_res_det = tree.GetSigCheckResult(dsig_id, file_id);
    REQUIRE(check_res_det);

    // not existing result
    auto asig_node = std::static_pointer_cast<mrpa::AsigNode>(
      mrpa::TestTreePrivate::GetNodeByID(tree, asig_id));
    asig_node->check_res = nullptr;
    check_res = tree.GetSigCheckResult(asig_id, child_id);
    REQUIRE_FALSE(check_res);
    auto sig_node = std::static_pointer_cast<mrpa::SigNode>(
      mrpa::TestTreePrivate::GetNodeByID(tree, dsig_id));
    sig_node->check_res.clear();
    check_res_det = tree.GetSigCheckResult(dsig_id, file_id);
    REQUIRE_FALSE(check_res_det);
  }
}

TEST_CASE("Extracted_file_from_attached_sig") {
  mrpa::TreeContext tree;
  REQUIRE(tree.AddFile(attached_valid_sig2));
  std::cout << boost::json::serialize(tree.ToJson()) << "\n";
  const auto& lookup_tables = mrpa::TestTreePrivate::getLookUpTables(tree);
  REQUIRE_FALSE(lookup_tables.asig_nodes.empty());
  auto asig_node = std::static_pointer_cast<mrpa::AsigNode>(
    lookup_tables.asig_nodes.cbegin()->second.lock());
  REQUIRE(asig_node);
  REQUIRE(asig_node->type == mrpa::NodeType::kAsig);
  REQUIRE(asig_node->child_);
  auto file_node = std::static_pointer_cast<mrpa::FileNode>(asig_node->child_);
  REQUIRE(file_node);
  REQUIRE(file_node->full_path);
  std::cout << "File path:" << file_node->full_path.value_or("") << "\n";
  REQUIRE(std::filesystem::exists(file_node->full_path.value_or("")));
}

TEST_CASE("SignTree_simple_file") {
  mrpa::TreeContext tree;
  // add a simple txt file
  REQUIRE(tree.AddFile(detached_valid1_src, false, false));
  REQUIRE(tree.AddFile(regular_file1));
  // create params
  mrpa::BatchSignatureSettings settings{};

  settings.cades_type = "CADES_T";
  settings.cert_serial = USER_CERT_SERIAL;
  settings.cert_subject = USER_CERT_SUBJECT;
  settings.tsp_link = "http://pki.tax.gov.ru/tsp/tsp.srf";
  settings.sig_extension = ".sig";
  settings.create_attached = false;
  settings.create_base_64_encoded = true;
  settings.pack_to_zip = false;
  settings.pack_separate_zips = false;

  // invalid destination
  settings.dest_dir_path = "blablba";
  REQUIRE_FALSE(tree.SignTree(settings));

  // valid destination
  settings.dest_dir_path = TEST_DIR;
  REQUIRE(tree.SignTree(settings));

  std::cout << boost::json::serialize(tree.LastSignResultJson()) << "\n";
  const auto res = tree.LastSignResult();
  REQUIRE(res);
  REQUIRE(res->result_files.size() == 4);
  REQUIRE(res->warnings.size() == 0);
  std::ignore = std::filesystem::remove_all(res->final_dir);
}

TEST_CASE("SignTree_simple_file_with_mrpa_in_root") {
  mrpa::TreeContext tree;
  // add a simple txt file
  REQUIRE(tree.AddFile(detached_valid1_src, false, false));
  REQUIRE(tree.AddFile(mrpa_valid2, false, false));
  REQUIRE(tree.AddFile(mrpa_valid2_sig, false, false));
  REQUIRE(tree.AddFile(regular_file1));

  // create params
  mrpa::BatchSignatureSettings settings{};

  settings.cades_type = "CADES_T";
  settings.cert_serial = USER_CERT_SERIAL;
  settings.cert_subject = USER_CERT_SUBJECT;
  settings.tsp_link = "http://pki.tax.gov.ru/tsp/tsp.srf";
  settings.sig_extension = ".sig";
  settings.create_attached = false;
  settings.create_base_64_encoded = true;
  settings.pack_to_zip = false;
  settings.pack_separate_zips = false;

  // valid destination
  settings.dest_dir_path = TEST_DIR;
  REQUIRE(tree.SignTree(settings));

  std::cout << boost::json::serialize(tree.LastSignResultJson()) << "\n";
  const auto res = tree.LastSignResult();
  REQUIRE(res);
  REQUIRE(res->result_files.size() == 6);
  REQUIRE(res->warnings.size() == 0);
  std::ignore = std::filesystem::remove_all(res->final_dir);
}

TEST_CASE("SignTree_simple_conflicting_src_names") {
  mrpa::TreeContext tree;
  // add a simple txt file
  REQUIRE(tree.AddFile(regular_file1));
  // create a copy of file in an another directory
  std::filesystem::copy(regular_file1, TEST_DIR,
                        std::filesystem::copy_options::skip_existing);
  const std::string file_with_name_confilct =
    std::string(TEST_DIR) +
    std::filesystem::path(regular_file1).filename().string();
  // add this copy to the tree
  REQUIRE(tree.AddFile(file_with_name_confilct));

  // create params
  mrpa::BatchSignatureSettings settings{};

  settings.cades_type = "CADES_T";
  settings.cert_serial = USER_CERT_SERIAL;
  settings.cert_subject = USER_CERT_SUBJECT;
  settings.tsp_link = "http://pki.tax.gov.ru/tsp/tsp.srf";
  settings.sig_extension = ".sig";
  settings.create_attached = false;
  settings.create_base_64_encoded = true;
  settings.pack_to_zip = false;
  settings.pack_separate_zips = false;

  // valid destination
  settings.dest_dir_path = TEST_DIR;
  REQUIRE(tree.SignTree(settings));

  std::cout << boost::json::serialize(tree.LastSignResultJson()) << "\n";
  const auto res = tree.LastSignResult();
  REQUIRE(res);
  REQUIRE(res->result_files.size() == 4);
  REQUIRE(res->warnings.size() == 1);
  std::ignore = std::filesystem::remove_all(res->final_dir);
}

TEST_CASE("SignTree_simple_conflicting_mrpa_names") {
  mrpa::TreeContext tree;
  // add a simple txt file
  REQUIRE(tree.AddFile(regular_file1));
  REQUIRE(tree.AddFile(mrpa_in_zip));
  // create a copy of file in an another directory
  std::filesystem::copy(mrpa_in_zip, TEST_DIR,
                        std::filesystem::copy_options::skip_existing);
  const std::string file_with_name_confilct =
    std::string(TEST_DIR) +
    std::filesystem::path(mrpa_in_zip).filename().string();
  // add this copy to the tree
  REQUIRE(tree.AddFile(file_with_name_confilct));

  // create params
  mrpa::BatchSignatureSettings settings{};

  settings.cades_type = "CADES_T";
  settings.cert_serial = USER_CERT_SERIAL;
  settings.cert_subject = USER_CERT_SUBJECT;
  settings.tsp_link = "http://pki.tax.gov.ru/tsp/tsp.srf";
  settings.sig_extension = ".sig";
  settings.create_attached = false;
  settings.create_base_64_encoded = true;
  settings.pack_to_zip = false;
  settings.pack_separate_zips = false;

  // valid destination
  settings.dest_dir_path = TEST_DIR;
  REQUIRE(tree.SignTree(settings));
}

TEST_CASE("SignTree_simple_file_with_mrpa_in_zip") {
  mrpa::TreeContext tree;
  // add a simple txt file
  REQUIRE(tree.AddFile(detached_valid1_src, false, false));
  REQUIRE(tree.AddFile(mrpa_valid2, false, false));
  REQUIRE(tree.AddFile(mrpa_valid2_sig, false, false));
  REQUIRE(tree.AddFile(regular_file1));
  REQUIRE(tree.AddFile(mrpa_in_zip));

  // create params
  mrpa::BatchSignatureSettings settings{};

  settings.cades_type = "CADES_T";
  settings.cert_serial = USER_CERT_SERIAL;
  settings.cert_subject = USER_CERT_SUBJECT;
  settings.tsp_link = "http://pki.tax.gov.ru/tsp/tsp.srf";
  settings.sig_extension = ".sig";
  settings.create_attached = false;
  settings.create_base_64_encoded = true;
  settings.pack_to_zip = false;
  settings.pack_separate_zips = false;

  // valid destination
  settings.dest_dir_path = TEST_DIR;
  REQUIRE(tree.SignTree(settings));

  std::cout << boost::json::serialize(tree.LastSignResultJson()) << "\n";
  const auto res = tree.LastSignResult();
  REQUIRE(res);
  REQUIRE(res->result_files.size() == 7);
  REQUIRE(res->warnings.size() == 0);
  std::ignore = std::filesystem::remove_all(res->final_dir);
}

TEST_CASE("SignTree_simple_file_with_mrpa_in_zip_witgh_other_file") {
  mrpa::TreeContext tree;
  // add a simple txt file
  REQUIRE(tree.AddFile(detached_valid1_src, false, false));
  REQUIRE(tree.AddFile(regular_file1));
  REQUIRE(tree.AddFile(mrpa_in_zip_plus_file));

  // create params
  mrpa::BatchSignatureSettings settings{};

  settings.cades_type = "CADES_T";
  settings.cert_serial = USER_CERT_SERIAL;
  settings.cert_subject = USER_CERT_SUBJECT;
  settings.tsp_link = "http://pki.tax.gov.ru/tsp/tsp.srf";
  settings.sig_extension = ".sig";
  settings.create_attached = false;
  settings.create_base_64_encoded = true;
  settings.pack_to_zip = false;
  settings.pack_separate_zips = false;

  // valid destination
  settings.dest_dir_path = TEST_DIR;
  REQUIRE(tree.SignTree(settings));

  std::cout << boost::json::serialize(tree.LastSignResultJson()) << "\n";
  const auto res = tree.LastSignResult();
  REQUIRE(res);
  REQUIRE(res->result_files.size() == 8);
  REQUIRE(res->warnings.size() == 0);
  std::ignore = std::filesystem::remove_all(res->final_dir);
}

TEST_CASE("Sign_MRPA_with_settings_attached") {
  mrpa::BatchSignatureSettings settings{};

  settings.cades_type = "CADES_T";
  settings.cert_serial = USER_CERT_SERIAL;
  settings.cert_subject = USER_CERT_SUBJECT;
  settings.tsp_link = "http://pki.tax.gov.ru/tsp/tsp.srf";
  settings.sig_extension = ".sig";
  settings.create_attached = true;
  settings.create_base_64_encoded = true;
  settings.pack_to_zip = false;
  settings.pack_separate_zips = false;
  settings.dest_dir_path = TEST_DIR;

  mrpa::TreeContext tree;
  REQUIRE(tree.AddFile(mrpa_valid2));
  REQUIRE(tree.AddFile(regular_file1));
  REQUIRE(tree.SignTree(settings));

  std::cout << boost::json::serialize(tree.LastSignResultJson()) << "\n";
  const auto res = tree.LastSignResult();
  REQUIRE(res);
  REQUIRE(res->result_files.size() == 3);
  REQUIRE(res->warnings.size() == 0);
  std::ignore = std::filesystem::remove_all(res->final_dir);
}

TEST_CASE("pack_all_to_one_zip1") {
  mrpa::TreeContext tree;
  // add a simple txt file
  REQUIRE(tree.AddFile(detached_valid1_src, false, false));
  // REQUIRE(tree.AddFile(mrpa_valid2, false, false));
  // REQUIRE(tree.AddFile(mrpa_valid2_sig, false, false));
  REQUIRE(tree.AddFile(regular_file1));
  REQUIRE(tree.AddFile(mrpa_in_zip));

  // create params
  mrpa::BatchSignatureSettings settings{};

  settings.cades_type = "CADES_T";
  settings.cert_serial = USER_CERT_SERIAL;
  settings.cert_subject = USER_CERT_SUBJECT;
  settings.tsp_link = "http://pki.tax.gov.ru/tsp/tsp.srf";
  settings.sig_extension = ".sig";
  settings.create_attached = false;
  settings.create_base_64_encoded = true;
  settings.pack_to_zip = true;
  settings.pack_separate_zips = false;

  // valid destination
  settings.dest_dir_path = TEST_DIR;
  REQUIRE(tree.SignTree(settings));

  std::cout << boost::json::serialize(tree.LastSignResultJson()) << "\n";
  const auto res = tree.LastSignResult();
  REQUIRE(res);
  REQUIRE(res->result_files.size() == 1);
  REQUIRE(res->warnings.size() == 0);
  std::ignore = std::filesystem::remove_all(res->final_dir);
}

TEST_CASE("pack_to_separate_zips") {
  mrpa::TreeContext tree;
  // add a simple txt file
  REQUIRE(tree.AddFile(detached_valid1_src, false, false));
  // REQUIRE(tree.AddFile(mrpa_valid2, false, false));
  // REQUIRE(tree.AddFile(mrpa_valid2_sig, false, false));
  REQUIRE(tree.AddFile(regular_file1));
  REQUIRE(tree.AddFile(mrpa_in_zip));

  // create params
  mrpa::BatchSignatureSettings settings{};

  settings.cades_type = "CADES_T";
  settings.cert_serial = USER_CERT_SERIAL;
  settings.cert_subject = USER_CERT_SUBJECT;
  settings.tsp_link = "http://pki.tax.gov.ru/tsp/tsp.srf";
  settings.sig_extension = ".sig";
  settings.create_attached = false;
  settings.create_base_64_encoded = true;
  settings.pack_to_zip = true;
  settings.pack_separate_zips = true;

  // valid destination
  settings.dest_dir_path = TEST_DIR;
  REQUIRE(tree.SignTree(settings));

  std::cout << boost::json::serialize(tree.LastSignResultJson()) << "\n";
  const auto res = tree.LastSignResult();
  REQUIRE(res);
  REQUIRE(res->result_files.size() == 2);
  REQUIRE(res->warnings.size() == 0);
  std::ignore = std::filesystem::remove_all(res->final_dir);
}

TEST_CASE("invalid_settings") {
  mrpa::TreeContext tree;
  // add a simple txt file
  REQUIRE(tree.AddFile(detached_valid1_src, false, false));
  // REQUIRE(tree.AddFile(mrpa_valid2, false, false));
  // REQUIRE(tree.AddFile(mrpa_valid2_sig, false, false));
  REQUIRE(tree.AddFile(regular_file1));
  REQUIRE(tree.AddFile(mrpa_in_zip));

  // create params
  mrpa::BatchSignatureSettings settings{};

  settings.cades_type = "CADES_T";
  settings.cert_serial = USER_CERT_SERIAL;
  settings.cert_subject = "";
  settings.tsp_link = "http://pki.tax.gov.ru/tsp/tsp.srf";
  settings.sig_extension = ".sig";
  settings.create_attached = false;
  settings.create_base_64_encoded = true;
  settings.pack_to_zip = true;
  settings.pack_separate_zips = true;

  // valid destination
  settings.dest_dir_path = TEST_DIR;
  REQUIRE_FALSE(tree.SignTree(settings));

  std::cout << boost::json::serialize(tree.LastSignResultJson()) << "\n";
  const auto res = tree.LastSignResult();
  REQUIRE(res);
  REQUIRE(res->warnings.size() == 1);
  REQUIRE(res->warnings.at(0) == "INVALID_PARAMETERS");
  std::ignore = std::filesystem::remove_all(res->final_dir);
}

TEST_CASE("invalid_cert") {
  mrpa::TreeContext tree;
  // add a simple txt file
  REQUIRE(tree.AddFile(detached_valid1_src, false, false));
  // REQUIRE(tree.AddFile(mrpa_valid2, false, false));
  // REQUIRE(tree.AddFile(mrpa_valid2_sig, false, false));
  REQUIRE(tree.AddFile(regular_file1));
  REQUIRE(tree.AddFile(mrpa_in_zip));

  // create params
  mrpa::BatchSignatureSettings settings{};

  settings.cades_type = "CADES_T";
  settings.cert_serial = "0000sss";
  settings.cert_subject = "name";
  settings.tsp_link = "http://pki.tax.gov.ru/tsp/tsp.srf";
  settings.sig_extension = ".sig";
  settings.create_attached = false;
  settings.create_base_64_encoded = true;
  settings.pack_to_zip = true;
  settings.pack_separate_zips = true;

  // valid destination
  settings.dest_dir_path = TEST_DIR;
  REQUIRE_FALSE(tree.SignTree(settings));

  std::cout << boost::json::serialize(tree.LastSignResultJson()) << "\n";
  const auto res = tree.LastSignResult();
  REQUIRE(res);
  REQUIRE(res->warnings.size() == 1);
  REQUIRE(res->warnings.at(0) == "SIGN_ALL_FILES_FAILED");
  std::ignore = std::filesystem::remove_all(res->final_dir);
}

TEST_CASE("LastSignResult_busy_context") {
  mrpa::TreeContext tree;
  // add a simple txt file
  REQUIRE(tree.AddFile(detached_valid1_src, false, false));
  // REQUIRE(tree.AddFile(mrpa_valid2, false, false));
  // REQUIRE(tree.AddFile(mrpa_valid2_sig, false, false));
  REQUIRE(tree.AddFile(regular_file1));
  REQUIRE(tree.AddFile(mrpa_in_zip));

  // create params
  mrpa::BatchSignatureSettings settings{};

  settings.cades_type = "CADES_T";
  settings.cert_serial = USER_CERT_SERIAL;
  settings.cert_subject = USER_CERT_SUBJECT;
  settings.tsp_link = "http://pki.tax.gov.ru/tsp/tsp.srf";
  settings.sig_extension = ".sig";
  settings.create_attached = false;
  settings.create_base_64_encoded = true;
  settings.pack_to_zip = true;
  settings.pack_separate_zips = true;

  // valid destination
  settings.dest_dir_path = TEST_DIR;
  REQUIRE(tree.SignTree(settings));

  std::cout << boost::json::serialize(tree.LastSignResultJson()) << "\n";
  const auto res = tree.LastSignResult();
  REQUIRE(res);
  REQUIRE(res->result_files.size() == 2);
  REQUIRE(res->warnings.size() == 0);
  std::ignore = std::filesystem::remove_all(res->final_dir);

  mrpa::TestTreePrivate::Lock(tree);
  REQUIRE(!tree.LastSignResult().has_value());
  REQUIRE(tree.LastSignResultJson().empty());
  mrpa::TestTreePrivate::Unlock(tree);
  REQUIRE(tree.LastSignResult().has_value());
  REQUIRE_FALSE(tree.LastSignResultJson().empty());

  // empty tree
  mrpa::TreeContext tree2;
  REQUIRE(tree2.LastSignResultJson().empty());
}

#endif

TEST_CASE("ChangeFilePrefix") {
  const std::string conflicting_1 = std::string(TEST_DIR) + "file.txt";
  const std::string conflicting_2 = std::string(TEST_DIR) + "1_file.txt";
  std::filesystem::copy_file(regular_file1, conflicting_1);
  std::filesystem::copy_file(regular_file1, conflicting_2);

  std::string fname = std::string(TEST_DIR) + "file.txt";
  uint64_t old_prefix = 0;
  while (std::filesystem::exists(fname)) {
    uint64_t prefix_new = old_prefix + 1;
    mrpa::ChangeFilePrefix(fname, old_prefix, prefix_new);
    old_prefix = prefix_new;
  }
  REQUIRE(fname == std::string(TEST_DIR) + "2_file.txt");
}