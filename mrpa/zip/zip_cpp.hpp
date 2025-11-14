#pragma once

/* File: zip_cpp.hpp
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

#include <cstddef>
#include <cstdint>
#include <ctime>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "file_stat.hpp"

/**
 * @brief Simple wrapper for libzip
 */

namespace zip_cpp {

using BytesVector = std::vector<unsigned char>;
using OptBytesVector = std::optional<BytesVector>;

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

  /// @brief unzip entry to destination directory
  [[nodiscard]] std::optional<std::string> readToDir(
    std::string dir) const noexcept;

  /// @brief read to file
  /// @param dest full name of the destination file
  [[nodiscard]] bool readToFile(const std::string& dest) const noexcept;

  [[nodiscard]] const FileStat& stat() const noexcept { return stat_; }
  void SetFileName(const std::string& fname) noexcept {
    stat_.name = fname;
    filename_ = fname;
  }

  [[nodiscard]] bool isFolder() const noexcept;

 private:
  FileStat stat_;
  std::string filename_;
  uint64_t index_ = 0;                           // default invalid index
  std::weak_ptr<FileHandler> zip_file_handler_;  // not owning pointer
};

/**
 * @brief Container for a zip file
 * @throws runtime_error if construct from path failed
 */
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

  /// @brief open ReadOnly
  /// @throws runtime_error on fail
  explicit Zip(const std::string& path);

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

  [[nodiscard]] ConstIterator at(size_t index) const;

  /// all temporary directories created with FileEntry::readToTmp
  [[nodiscard]] std::vector<std::string> getTmpDirsCreated() const noexcept;

  /// @details removes all temporary directories created with
  /// FileEntry::readToTmp
  [[nodiscard]] bool removeTempDirs() noexcept;

 private:
  void fillEntries() noexcept;

  std::shared_ptr<FileHandler> zfile_;
  std::vector<FileEntry> vec_;
  friend class ZipCreator;
};

class ZipCreator : public Zip {
 public:
  /**
   * @brief Construct a new Zip archive
   * @param path
   * @throws runtime_error on fail
   * @details empty archive is always deleted on close
   */
  explicit ZipCreator(std::string path);

  ZipCreator() = delete;
  ZipCreator(const ZipCreator&) = delete;
  ZipCreator(ZipCreator&&) = delete;
  ZipCreator& operator=(const ZipCreator&) = delete;
  ZipCreator& operator=(ZipCreator&&) = delete;

  /// @details all uncommitted changes will be reset
  ~ZipCreator();

  /// @brief reset all uncommitted changes
  void reset() noexcept;

  /// @brief commit the changes
  [[nodiscard]] bool commit() noexcept;

  /**
   * @brief Push file to zip
   *
   * @param data raw data file (size>0)
   * @param name target filename (length>0)
   * @return true success
   * @return false fail
   * @details the data will be stored in memory until the commit() call
   */
  [[nodiscard]] bool push_file(BytesVector data,
                               const std::string& name) noexcept;
  [[nodiscard]] bool push_file(const std::string& data,
                               const std::string& name) noexcept;
  [[nodiscard]] bool push_file(const std::string& path) noexcept;

  /// @brief  adds a directory to a zip archive
  [[nodiscard]] bool push_folder(const std::string& folder) noexcept;

 private:
  std::string target_path_;
  std::vector<BytesVector> buffers_;
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
bool IsValidUtf(const std::string& str);
#endif

}  // namespace zip_cpp