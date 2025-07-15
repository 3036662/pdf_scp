#pragma once

#include <cstddef>
#include <cstdint>
#include <ctime>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

/**
 * @brief Simple wrapper for libzip
 */

namespace zip_cpp {

using BytesVector = std::vector<unsigned char>;
using OptBytesVector = std::optional<BytesVector>;

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
  FileEntry() = default;
  FileEntry(FileStat stat, std::string filename, uint64_t index,
            const std::shared_ptr<FileHandler>& zfile)
    : stat_{std::move(stat)},
      filename_{std::move(filename)},
      index_(index),
      zip_file_handler_(zfile) {}

  /// @brief read to memory
  [[nodiscard]] OptBytesVector readToBuffer() const noexcept;

  // TODO(Oleg) implement
  /// @brief read to file
  [[nodiscard]] std::optional<std::string> readToTmp() const noexcept;

  // TODO(Oleg) implement
  /// @brief read to file
  [[nodiscard]] bool readToFile() const noexcept;

  [[nodiscard]] const FileStat& stat() const noexcept { return stat_; }
  void SetFileName(const std::string& fname) noexcept {
    stat_.name = fname;
    filename_ = fname;
  }

 private:
  FileStat stat_;
  std::string filename_;
  uint64_t index_ = 0;                           // default invalid index
  std::weak_ptr<FileHandler> zip_file_handler_;  // not owning pointer
};

class Zip {
 public:
  class ConstIterator {
   public:
    using iterator_category = std::random_access_iterator_tag;
    using value_type = const FileEntry;
    using difference_type = ptrdiff_t;
    using pointer = const FileEntry*;
    using reference = const FileEntry&;

    ConstIterator() = default;
    explicit ConstIterator(const FileEntry* ptr) : ptr_(ptr) {}
    reference operator*() const { return *ptr_; }
    pointer operator->() const { return ptr_; }
    reference operator[](difference_type n) { return ptr_[n]; }

    ConstIterator& operator++() {
      ++ptr_;
      return *this;
    }
    ConstIterator operator++(int) {
      ConstIterator tmp = *this;
      ++ptr_;
      return tmp;
    }
    ConstIterator& operator--() {
      --ptr_;
      return *this;
    }
    ConstIterator operator--(int) {
      ConstIterator tmp = *this;
      --ptr_;
      return tmp;
    }
    ConstIterator& operator+=(difference_type n) {
      ptr_ += n;
      return *this;
    }
    ConstIterator& operator-=(difference_type n) {
      ptr_ -= n;
      return *this;
    }
    ConstIterator operator+(difference_type n) const {
      return ConstIterator(ptr_ + n);
    }
    ConstIterator operator-(difference_type n) const {
      return ConstIterator(ptr_ - n);
    }
    difference_type operator-(const ConstIterator& other) const {
      return ptr_ - other.ptr_;
    }
    bool operator==(const ConstIterator& other) const {
      return ptr_ == other.ptr_;
    }
    bool operator!=(const ConstIterator& other) const {
      return ptr_ != other.ptr_;
    }
    bool operator<(const ConstIterator& other) const {
      return ptr_ < other.ptr_;
    }
    bool operator>(const ConstIterator& other) const {
      return ptr_ > other.ptr_;
    }
    bool operator<=(const ConstIterator& other) const {
      return ptr_ <= other.ptr_;
    }
    bool operator>=(const ConstIterator& other) const {
      return ptr_ >= other.ptr_;
    }

   private:
    const FileEntry* ptr_ = nullptr;
  };

  Zip() = default;

  explicit Zip(const std::string& path, bool read_only = true) noexcept;

  [[nodiscard]] bool empty() const noexcept { return vec_.empty(); }
  [[nodiscard]] size_t size() const noexcept { return vec_.size(); }

  [[nodiscard]] ConstIterator cbegin() const {
    return ConstIterator(vec_.data());
  };
  [[nodiscard]] ConstIterator cend() const {
    return ConstIterator(vec_.data() + vec_.size());
  }
  [[nodiscard]] ConstIterator begin() const { return cbegin(); }
  [[nodiscard]] ConstIterator end() const { return cend(); }

  [[nodiscard]] ConstIterator at(size_t index) const {
    if (index > vec_.size()) {
      throw std::out_of_range("Zip file entry index is out of range");
    }
    return ConstIterator(vec_.data() + index);
  };

 private:
  std::shared_ptr<FileHandler> zfile_;
  std::vector<FileEntry> vec_;
};

inline Zip::ConstIterator operator+(Zip::ConstIterator::difference_type n,
                                    const Zip::ConstIterator& iter) {
  return iter + n;
}

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