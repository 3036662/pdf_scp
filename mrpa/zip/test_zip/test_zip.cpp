#include <zipconf.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <string>
#include <tuple>

#include "common_utils.hpp"
#define CATCH_CONFIG_MAIN
#include <libzip/zip.h>

#include <catch2/catch.hpp>
#include <filesystem>
#include <string_view>

#include "file_handler.hpp"
#include "zip_cpp.hpp"

const std::string test_dir = std::string(TEST_FILES_DIR) + "mrpa/zip/";
const std::string real_archive =
  std::string(TEST_FILES_DIR) +
  "mrpa/sensitive/Счет_на_оплату_№_1513_от_30_июня_2025_г_pdf.zip";
const std::string real_archive2 =
  std::string(TEST_FILES_DIR) + "mrpa/sensitive/bugzilla_54258_CP866.zip";
const std::string real_archive3 =
  std::string(TEST_FILES_DIR) + "mrpa/sensitive/bugzilla_542258_nested.zip";
const std::string zip1 = test_dir + "simple.zip";
const std::string zip_empty = test_dir + "empty.zip";
const std::string zip_nonzip = test_dir + "non_zip.zip";
const std::string zip_encrypted = test_dir + "encrypted.zip";
const std::string random_text = test_dir + "Архив.zip";
const std::string random_text_src = test_dir + "рандом.txt";
const std::string win1 = test_dir + "winrar.zip";
const std::string win2 = test_dir + "winzip.zip";
const std::string win3 = test_dir + "winrarspec.zip";
const std::string win4 = test_dir + "winzipspec.zip";

TEST_CASE("OpenZip") {
  REQUIRE(true);
  REQUIRE(std::filesystem::exists(zip1));
  int error_code = 0;
  zip_t* zfile = nullptr;
  SECTION("Normal") {
    zfile = zip_open(zip1.c_str(), ZIP_RDONLY, &error_code);
    REQUIRE(error_code == 0);
    REQUIRE(zfile != nullptr);
    zip_int64_t entries_count = zip_get_num_entries(zfile, ZIP_FL_UNCHANGED);
    REQUIRE(entries_count == 2);
    REQUIRE(zip_close(zfile) == 0);
  }
  SECTION("Empty") {
    zfile = zip_open(zip_empty.c_str(), ZIP_RDONLY, &error_code);
    REQUIRE(error_code == 0);
    REQUIRE(zfile != nullptr);
    zip_int64_t entries_count = zip_get_num_entries(zfile, ZIP_FL_UNCHANGED);
    REQUIRE(entries_count == 1);
    REQUIRE(zip_close(zfile) == 0);
  }
  SECTION("Broken") {
    zfile = zip_open(zip_nonzip.c_str(), ZIP_RDONLY, &error_code);
    REQUIRE(zfile == nullptr);
    zip_error_t error;
    zip_error_init_with_code(&error, error_code);
    REQUIRE(error_code == ZIP_ER_NOZIP);
    const char* err_c_str = zip_error_strerror(&error);
    REQUIRE(err_c_str != nullptr);
    const std::string err_str(err_c_str);
    REQUIRE_FALSE(err_str.empty());
    std::cout << "Error string:" << err_str << "\n";
    zip_error_fini(&error);
  }
}

TEST_CASE("ListFiles") {
  SECTION("Basic") {
    REQUIRE(std::filesystem::exists(zip1));
    int error_code = 0;
    zip_t* zfile = nullptr;
    zfile = zip_open(zip1.c_str(), ZIP_RDONLY, &error_code);
    REQUIRE(error_code == 0);
    REQUIRE(zfile != nullptr);
    zip_int64_t entries_count = zip_get_num_entries(zfile, ZIP_FL_UNCHANGED);
    REQUIRE(entries_count == 2);
    for (int i = 0; i < entries_count; ++i) {
      const char* cstr_filename =
        zip_get_name(zfile, i, ZIP_FL_ENC_RAW | ZIP_FL_ENC_GUESS);
      REQUIRE(cstr_filename != nullptr);
      const std::string filename(cstr_filename);
      std::cout << "File " << i << ":" << filename << "\n";
    }
    REQUIRE(zip_close(zfile) == 0);
  }
  SECTION("Empty") {
    REQUIRE(std::filesystem::exists(zip_empty));
    int error_code = 0;
    zip_t* zfile = nullptr;
    zfile = zip_open(zip_empty.c_str(), ZIP_RDONLY, &error_code);
    REQUIRE(error_code == 0);
    REQUIRE(zfile != nullptr);
    zip_int64_t entries_count = zip_get_num_entries(zfile, ZIP_FL_UNCHANGED);
    REQUIRE(entries_count > 0);
    for (int i = 0; i < entries_count; ++i) {
      const char* cstr_filename =
        zip_get_name(zfile, i, ZIP_FL_ENC_RAW | ZIP_FL_ENC_GUESS);
      REQUIRE(cstr_filename != nullptr);
      const std::string filename(cstr_filename);
      std::cout << "File " << i << ":" << filename << "\n";
    }
    REQUIRE(zip_close(zfile) == 0);
  }
  SECTION("Encrypted") {
    REQUIRE(std::filesystem::exists(zip_encrypted));
    int error_code = 0;
    zip_t* zfile = nullptr;
    zfile = zip_open(zip_encrypted.c_str(), ZIP_RDONLY, &error_code);
    REQUIRE(error_code == 0);
    REQUIRE(zfile != nullptr);
    REQUIRE(error_code == 0);
    zip_int64_t entries_count = zip_get_num_entries(zfile, ZIP_FL_UNCHANGED);
    REQUIRE(entries_count >= 1);
    for (int i = 0; i < entries_count; ++i) {
      const char* cstr_filename =
        zip_get_name(zfile, i, ZIP_FL_ENC_RAW | ZIP_FL_ENC_GUESS);
      REQUIRE(cstr_filename != nullptr);
      const std::string filename(cstr_filename);
      std::cout << "File " << i << ":" << filename << "\n";
    }
    REQUIRE(zip_close(zfile) == 0);
  }
}

TEST_CASE("TestInternals") {
  REQUIRE(zip_cpp::TestEmptyHandler());
  REQUIRE(zip_cpp::TestNormalHandler(zip1));
  REQUIRE(zip_cpp::TestMoveConstructorHandler(zip1));
  REQUIRE(zip_cpp::TestMoveAssignmentHandler(zip1));
  REQUIRE(zip_cpp::TestBoolOperatorHandler(zip1));
}

TEST_CASE("Check_if_zip") {
  SECTION("Normal") { REQUIRE(zip_cpp::IsZipArchive(zip1)); }
  SECTION("Empty") { REQUIRE(zip_cpp::IsZipArchive(zip_empty)); }
  SECTION("Encrypted") { REQUIRE(zip_cpp::IsZipArchive(zip_encrypted)); }
  SECTION("Non_zip") { REQUIRE_FALSE(zip_cpp::IsZipArchive(zip_nonzip)); }
  SECTION("Empty string") { REQUIRE_FALSE(zip_cpp::IsZipArchive("")); }
}

TEST_CASE("Zip_container") {
  REQUIRE(std::filesystem::exists(zip1));
  SECTION("empty") {
    zip_cpp::Zip zip_empty;
    REQUIRE(zip_empty.empty());
  }
  SECTION("basic") {
    zip_cpp::Zip zip_reader(zip1);
    REQUIRE(zip_reader.size() > 0);
    std::cout << "Basic ranged-based for:\n";
    for (const auto& zip_file : zip_reader) {
      std::cout << zip_file.stat().toString() << "\n";
    }
    REQUIRE(zip_reader.at(1)->stat().index.value() == 1);
    REQUIRE_THROWS(zip_reader.at(100)->stat());
  }
  SECTION("enctypted") {
    zip_cpp::Zip zip_reader(zip_encrypted);
    REQUIRE(zip_reader.size() > 0);
    std::cout << "Std::for_each:\n";
    std::for_each(zip_reader.cbegin(), zip_reader.cend(),
                  [](const zip_cpp::FileEntry& file) {
                    std::cout << file.stat().toString() << "\n";
                  });
  }

  SECTION("non-existing") { REQUIRE_THROWS(zip_cpp::Zip("blabla")); }

  SECTION("IteratorOperator") {
    zip_cpp::Zip zip_reader(zip1);
    REQUIRE(zip_reader.size() > 0);
    auto tmp_iter = zip_reader.cbegin();
    REQUIRE(tmp_iter->stat().name.value() == "1.txt");
    ++tmp_iter;
    REQUIRE(tmp_iter->stat().name.value() == "2.txt");
    --tmp_iter;
    REQUIRE(tmp_iter->stat().name.value() == "1.txt");
    tmp_iter++;
    REQUIRE(tmp_iter->stat().name.value() == "2.txt");
    tmp_iter--;
    REQUIRE(tmp_iter->stat().name.value() == "1.txt");
    tmp_iter += 2;
    REQUIRE(tmp_iter == zip_reader.cend());
    tmp_iter -= 2;
    REQUIRE(tmp_iter == zip_reader.cbegin());
    REQUIRE((tmp_iter + 1)->stat().name.value() == "2.txt");
    REQUIRE(tmp_iter + 2 == zip_reader.cend());
    ++tmp_iter;
    REQUIRE(tmp_iter - 1 == zip_reader.cbegin());
    REQUIRE(zip_reader.cend() - zip_reader.cbegin() == 2);
    REQUIRE(zip_reader.cbegin() < zip_reader.cend());
    REQUIRE(zip_reader.cbegin() + 1 > zip_reader.cbegin());
    REQUIRE(zip_reader.cend() > zip_reader.cbegin());
    REQUIRE(zip_reader.cbegin() + 2 <= zip_reader.cend());
    REQUIRE(zip_reader.cbegin() + 2 >= zip_reader.cend());
    REQUIRE(2 + zip_reader.cbegin() == zip_reader.cend());
  }
}

TEST_CASE("Real_sens") {
  SECTION("ListFiles") {
    if (std::filesystem::exists(real_archive)) {
      zip_cpp::Zip zip(real_archive);
      REQUIRE(zip.at(0)->stat().name);
      REQUIRE(zip.at(0)->stat().name.value() ==
              "Счет на оплату № 1513 от 30 июня 2025 "
              "г.pdf/"
              "DP_IZVPOL_2AED2CA234F-6AB5-4F81-9D1B-1E0861C82B9A_2BM-"
              "7714350892-771401001-201603240358214.xml");
    }
  }

  SECTION("ListFiles2") {
    if (std::filesystem::exists(real_archive2)) {
      zip_cpp::Zip zip(real_archive2);
      REQUIRE(zip.size() > 0);
      REQUIRE(zip.at(0)->stat().name);
      REQUIRE(zip.at(0)->stat().name.value() ==
              "CP866/Документы по закупке №0373100115225000027 12.05.2025 "
              "13.01.55 (1).zip");
    }
  }

  SECTION("ListFiles3") {
    if (std::filesystem::exists(real_archive3)) {
      zip_cpp::Zip zip(real_archive3);
      REQUIRE(zip.size() > 0);
      REQUIRE(zip.at(0)->stat().name);
      REQUIRE(zip.at(0)->stat().name.value() ==
              "Заявки/005 Заявка №1 ООО КОМПАС-АВТО ИНН 5010054580/Заявка №1 "
              "ИНН 5010054580.rtf");
    }
  }
}

TEST_CASE("Real") {
  SECTION("win1") {
    std::cout << "\n win1" << "\n";
    zip_cpp::Zip zip(win1);
    REQUIRE(zip.at(0)->stat().name);
    REQUIRE(zip.at(0)->stat().name.value() == "Порядок колонок — копия.txt");
    std::cout << zip.at(0)->stat().toString() << "\n";
  }
  SECTION("win2") {
    std::cout << "\n win2" << "\n";
    zip_cpp::Zip zip(win2);
    REQUIRE(zip.at(0)->stat().name);
    REQUIRE(zip.at(0)->stat().name.value() == "Порядок колонок.txt");
    std::cout << zip.at(0)->stat().toString() << "\n";
  }
  SECTION("win3") {
    std::cout << "\n win3" << "\n";
    zip_cpp::Zip zip(win3);
    REQUIRE(zip.at(0)->stat().name);
    REQUIRE(zip.at(0)->stat().name.value() == "!№;%()_+ТрасплонтацияЁЮЪъ.txt");
    std::cout << zip.at(0)->stat().toString() << "\n";
  }
  SECTION("win4") {
    std::cout << "\n win4" << "\n";
    zip_cpp::Zip zip(win4);
    REQUIRE(zip.at(0)->stat().name);
    REQUIRE(zip.at(0)->stat().name.value() == "!№;%()_+ТрасплонтацияЁЮЪъ.txt");
    std::cout << zip.at(0)->stat().toString() << "\n";
  }
}

TEST_CASE("TempFolder") {
  const std::string tmp_dir = std::filesystem::temp_directory_path().string();
  REQUIRE_FALSE(tmp_dir.empty());
  std::cout << "Temporary dir: " << tmp_dir << "\n";
}

TEST_CASE("ReadEntryToBuffer") {
  SECTION("Normal_file") {
    zip_cpp::Zip zip(random_text);
    for (const auto& entry : zip) {
      std::cout << entry.stat().toString() << "\n";
    }
    REQUIRE(zip.size() > 1);
    auto start = std::chrono::steady_clock::now();
    auto buf = zip.at(1)->readToBuffer();
    auto end = std::chrono::steady_clock::now();
    std::cout << std::chrono::duration_cast<std::chrono::milliseconds>(end -
                                                                       start)
                   .count()
              << " ms";
    REQUIRE(buf.has_value());
    REQUIRE(buf->size() == zip.at(1)->stat().size.value());
    std::cout << "Extracted file size:" << buf->size() << "\n";
    auto expected_buf = pdfcsp::utils::FileToVector(random_text_src);
    REQUIRE(expected_buf.has_value());
    REQUIRE(buf.value() == expected_buf.value());
  }

  SECTION("Encrypted") {
    zip_cpp::Zip zip(zip_encrypted);
    for (const auto& entry : zip) {
      std::cout << entry.stat().toString() << "\n";
    }
    REQUIRE_FALSE(zip.empty());

    auto buf = zip.at(0)->readToBuffer();

    REQUIRE_FALSE(buf.has_value());
  }
}

TEST_CASE("Create_zip") {
  SECTION("Simple") {
    const std::string dest = std::string(TEST_DIR) + "testzip1.zip";
    zip_cpp::ZipCreator zip(dest);
    REQUIRE(zip.empty());
    REQUIRE(zip.push_file(u8"Олег", "тестовый_файл.txt"));
    REQUIRE(zip.commit());
    REQUIRE(zip.size() == 1);
    REQUIRE(zip.at(0)->stat().size.has_value());
    REQUIRE(zip.at(0)->stat().size.value() == 8);
    REQUIRE(zip.at(0)->stat().name.has_value());
    REQUIRE(zip.at(0)->stat().name.value() == "тестовый_файл.txt");
    const std::string unzip_dest = TEST_DIR + zip.at(0)->stat().name.value();
    REQUIRE(zip.at(0)->readToFile(unzip_dest));
    REQUIRE(std::filesystem::exists(unzip_dest));
    auto result = pdfcsp::utils::FileToVector(unzip_dest);
    REQUIRE(result.has_value());
    REQUIRE(std::string(result.value().cbegin(), result.value().cend()) ==
            u8"Олег");
    REQUIRE(std::filesystem::remove(dest));
    REQUIRE(std::filesystem::remove(unzip_dest));
  }

  SECTION("folder") {
    const std::string dest = std::string(TEST_DIR) + "testzip6.zip";
    zip_cpp::ZipCreator zip(dest);
    REQUIRE(zip.empty());
    REQUIRE(zip.push_folder("папка2"));
    REQUIRE(zip.push_file(u8"Олег", "папка2/тестовый_файл.txt"));
    REQUIRE(zip.commit());
    REQUIRE(zip.size() == 2);
    REQUIRE(zip.at(0)->isFolder());
    const std::string unzip_dest = TEST_DIR + zip.at(0)->stat().name.value();
    REQUIRE(zip.at(0)->readToFile(unzip_dest));
    REQUIRE_FALSE(zip.at(0)->readToBuffer().has_value());
    const std::string unzip_dest2 = TEST_DIR + zip.at(1)->stat().name.value();
    std::cout << "unzip_dest2:" << unzip_dest2 << "\n";
    REQUIRE(zip.at(1)->stat().size.has_value());
    REQUIRE(zip.at(1)->stat().size.value() == 8);
    REQUIRE(zip.at(1)->stat().name.has_value());
    REQUIRE(zip.at(1)->stat().name.value() == "папка2/тестовый_файл.txt");
    REQUIRE(zip.commit());
    REQUIRE(zip.at(1)->readToFile(unzip_dest2));
    REQUIRE(std::filesystem::exists(unzip_dest2));
    auto tmp_path1 = zip.at(1)->readToTmp();
    REQUIRE(tmp_path1.has_value());
    std::cout << "Extracted to the temporary folder:" << tmp_path1.value()
              << "\n";
    for (const auto& tmp_dir : zip.getTmpDirsCreated()) {
      std::cout << "Temoprary dir created:" << tmp_dir << "\n";
    }
    REQUIRE(std::filesystem::remove(dest));
    REQUIRE(std::filesystem::remove(unzip_dest2));
    REQUIRE(std::filesystem::remove(unzip_dest));
    REQUIRE(std::filesystem::remove(tmp_path1.value()));
    REQUIRE(zip.removeTempDirs());
  }

  SECTION("folder") {
    const std::string dest = std::string(TEST_DIR) + "testzip5.zip";
    zip_cpp::ZipCreator zip(dest);
    REQUIRE(zip.empty());
    REQUIRE(zip.push_file(u8"Олег", "папка/тестовый_файл.txt"));
    REQUIRE(zip.commit());
    REQUIRE(zip.size() == 1);
    REQUIRE(zip.at(0)->stat().size.has_value());
    REQUIRE(zip.at(0)->stat().size.value() == 8);
    REQUIRE(zip.at(0)->stat().name.has_value());
    REQUIRE(zip.at(0)->stat().name.value() == "папка/тестовый_файл.txt");
    std::ignore = zip.push_folder("папка");
    REQUIRE(zip.commit());
    REQUIRE(std::filesystem::remove(dest));
  }

  SECTION("reset") {
    const std::string dest = std::string(TEST_DIR) + "testzip4.zip";
    zip_cpp::ZipCreator zip(dest);
    REQUIRE(zip.empty());
    REQUIRE(zip.push_file(u8"Олег", "папка/тестовый_файл.txt"));
    zip.reset();
    REQUIRE(zip.commit());
    REQUIRE(zip.size() == 0);
    REQUIRE_FALSE(std::filesystem::exists(dest));
  }
}

TEST_CASE("FileHandler") {
  SECTION("AssignToSelf") {
    zip_cpp::FileHandler handl1(zip1);
    const auto* expected = handl1.get();
    zip_cpp::FileHandler* handl2 = &handl1;
    handl1 = std::move(*handl2);
    REQUIRE(handl1.get() == expected);
  }
  SECTION("CloseEmpty") {
    zip_cpp::FileHandler handl1(zip1);
    REQUIRE(handl1.close());
    REQUIRE(handl1.close());
  }

  SECTION("CreateExisting") { REQUIRE_THROWS(zip_cpp::ZipCreator(zip1)); }

  SECTION("UnwritableDest") {
    std::string unwritable_folder = std::string(TEST_DIR) + "unwritable";
    REQUIRE_NOTHROW(std::filesystem::create_directory(unwritable_folder));
    REQUIRE_NOTHROW(std::filesystem::permissions(
      unwritable_folder, std::filesystem::perms::owner_write |
                           std::filesystem::perms::owner_read));
    std::string unwritable_dest = unwritable_folder + "/test.zip";
    REQUIRE_THROWS(zip_cpp::ZipCreator(unwritable_dest));
    REQUIRE(std::filesystem::remove(unwritable_folder));
  }
}

TEST_CASE("Unreadable_zip") {
  std::string dest = std::string(TEST_DIR) + "unreadable.zip";
  {
    zip_cpp::ZipCreator zip1(dest);
    REQUIRE(zip1.push_file("data", "data.txt"));
    REQUIRE(zip1.commit());
  }
  REQUIRE(std::filesystem::exists(dest));
  REQUIRE_NOTHROW(
    std::filesystem::permissions(dest, std::filesystem::perms::owner_write));
  {
    REQUIRE_THROWS(zip_cpp::Zip(dest));
  }
  REQUIRE(std::filesystem::remove(dest));
}

TEST_CASE("Unzip_to_invalid_location") {
  std::string dest = std::string(TEST_DIR) + "testzip.zip";
  {
    zip_cpp::ZipCreator zip1(dest);
    REQUIRE(zip1.push_file("data", "data.txt"));
    REQUIRE(zip1.commit());
  }
  {
    REQUIRE(std::filesystem::exists(dest));
    zip_cpp::Zip reader(dest);
    REQUIRE_FALSE(reader.at(0)->readToFile("/home/tmp.tmp"));
  }
  {
    REQUIRE(std::filesystem::exists(dest));
    zip_cpp::Zip reader(dest);
    REQUIRE_FALSE(reader.at(0)->readToDir("/home"));
  }
  REQUIRE(std::filesystem::remove(dest));
  {
    zip_cpp::ZipCreator zip1(dest);
    REQUIRE(zip1.push_folder("folder"));
    REQUIRE(zip1.commit());
  }
  {
    REQUIRE(std::filesystem::exists(dest));
    zip_cpp::Zip reader(dest);
    REQUIRE_FALSE(reader.at(0)->readToFile("/home/tmp.tmp"));
  }
  {
    REQUIRE(std::filesystem::exists(dest));
    zip_cpp::Zip reader(dest);
    REQUIRE_FALSE(reader.at(0)->readToDir("/home"));
  }
  REQUIRE(std::filesystem::remove(dest));
}

TEST_CASE("IsValidUtf") {
  SECTION("Valid") {
    REQUIRE(zip_cpp::IsValidUtf(u8"Правильный UTF-8😂😂😂あああ"));
  }
  SECTION("Invalid") {
    REQUIRE_FALSE(zip_cpp::IsValidUtf(
      {static_cast<char>(0xE4), static_cast<char>(0x88), 0x00}));
  }
}

TEST_CASE("PushEmptyNameData") {
  std::string dest = std::string(TEST_DIR) + "testzip8.zip";
  zip_cpp::ZipCreator creator(dest);
  REQUIRE_FALSE(creator.push_file(std::string(), "name"));
  REQUIRE_FALSE(creator.push_file(zip_cpp::BytesVector(), "name"));
  REQUIRE_FALSE(creator.push_file("data", ""));
  REQUIRE_FALSE(creator.push_folder(""));
}
