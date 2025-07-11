#pragma once

#include <cstddef>
#include <cstdint>
#include <ctime>
#include <memory>
#include <optional>
#include <string>
#include <vector>

/**
 * @brief Simple wrapper for libzip
 */

namespace zip_cpp {

struct FileStat {
  std::optional<std::string> name;
  std::optional<uint64_t> index;
  std::optional<uint64_t> size;
  std::optional<uint64_t> size_compressed;
  std::optional<time_t> time_mod;
  std::optional<uint32_t> crc;
  std::optional<uint16_t> comp_method;
  std::optional<uint16_t> encryption_method;
  bool encrypted = false;

  [[nodiscard]] std::string toSting() const noexcept;
};

class FileHandler;

class FileEntry {
 public:
  [[nodiscard]] const FileStat& stat() const noexcept { return stat_; }
  FileEntry() = default;
  FileEntry(FileStat stat, std::string filename)
    : stat_{std::move(stat)}, filename_{std::move(filename)} {}

 private:
  FileStat stat_;
  std::string filename_;
};

class Zip {
 public:
  //   class ConstIterator {
  //    public:
  //     using iterator_category = std::random_access_iterator_tag;
  //     using value_type = const FileEntry;
  //     using difference_type = ptrdiff_t;
  //     using pointer = const FileEntry*;
  //     using reference = const FileEntry&;
  //   };

  Zip() = default;

  explicit Zip(const std::string& path, bool read_only = true) noexcept;

  [[nodiscard]] bool empty() const noexcept { return vec_.empty(); }
  [[nodiscard]] size_t size() const noexcept { return vec_.size(); }

 private:
  std::shared_ptr<FileHandler> zfile_;
  std::vector<FileEntry> vec_;
};

[[nodiscard]] bool IsZipArchive(const std::string& path) noexcept;

// Test hidden functions
#ifdef TEST_BUILD
bool TestEmptyHandler();
bool TestNormalHandler(const std::string& path);
bool TestMoveConstructorHandler(const std::string& path);
bool TestMoveAssignmentHandler(const std::string& path);
bool TestBoolOperatorHandler(const std::string& path);
#endif

}  // namespace zip_cpp