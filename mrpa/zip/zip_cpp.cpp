/* File: zip_cpp.cpp
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

#include "zip_cpp.hpp"

#include <libzip/zip.h>
#include <zipconf.h>

#include <algorithm>
#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/locale.hpp>
#include <exception>
#include <filesystem>
#include <fstream>
#include <ios>
#include <iostream>
#include <iterator>
#include <memory>
#include <numeric>
#include <optional>
#include <stdexcept>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include "common_utils.hpp"
#include "file_handler.hpp"
#include "file_stat.hpp"
#include "utils_zip.hpp"

// google guess unused
// #include "compact_enc_det/compact_enc_det.h"

namespace zip_cpp {

namespace {

FileStat CreateFileStat(const zip_stat_t& raw_stat) noexcept {
  FileStat res;
  const uint64_t memb_flags = raw_stat.valid;
  if (checkFlag(memb_flags, ZIP_STAT_NAME) && raw_stat.name != nullptr) {
    res.name.emplace(raw_stat.name);
  }
  if (checkFlag(memb_flags, ZIP_STAT_INDEX)) {
    res.index = raw_stat.index;
  }
  if (checkFlag(memb_flags, ZIP_STAT_SIZE)) {
    res.size = raw_stat.size;
  }
  if (checkFlag(memb_flags, ZIP_STAT_COMP_SIZE)) {
    res.size_compressed = raw_stat.comp_size;
  }
  if (checkFlag(memb_flags, ZIP_STAT_MTIME)) {
    res.time_mod = raw_stat.mtime;
  }
  if (checkFlag(memb_flags, ZIP_STAT_CRC)) {
    res.crc = raw_stat.crc;
  }
  if (checkFlag(memb_flags, ZIP_STAT_COMP_METHOD)) {
    res.comp_method = raw_stat.comp_method;
  }
  if (checkFlag(memb_flags, ZIP_STAT_ENCRYPTION_METHOD)) {
    res.encryption_method = raw_stat.encryption_method;
    res.encrypted = res.encryption_method != 0;
  }
  return res;
}

void ZipEntryCloser(zip_file_t* ptr) {
  if (ptr == nullptr) {
    return;
  }
  zip_fclose(ptr);
}

std::string cp866_to_utf8(const std::string& cp866_str) {
  return boost::locale::conv::to_utf<char>(cp866_str, "cp866");
}

bool is_valid_cp866(const std::string& str) {
  if (str.empty()) {
    return false;
  }
  for (const unsigned char symbol : str) {
    if (symbol < 0x80) {
      continue;
    }
    // Check valid CP866 ranges
    if (symbol > 0xAF &&  // Cyrillic uppercase
        symbol < 0xE0) {  // Cyrillic lowercase + symbols
      std::cout << "invalid cp866 symbol:" << std::to_string(symbol) << "\n";
      return false;
    }
  }
  return true;
}

bool is_valid_utf8(const std::string& str) {
  int follow_bytes = 0;
  for (const unsigned char symbol : str) {
    if (follow_bytes > 0) {
      // Continuation byte must start with 10xxxxxx
      if ((symbol & 0xC0) != 0x80) {
        return false;
      }
      follow_bytes--;
    } else {
      if (symbol <= 0x7F) {
        continue;  // ASCII
      }
      if ((symbol & 0b11100000) == 0b11000000) {
        follow_bytes = 1;  // 110xxxxx 2-byte sequence
      } else if ((symbol & 0b11110000) == 0b11100000) {
        follow_bytes = 2;  // 1110xxxx 3-byte
      } else if ((symbol & 0b11111000) == 0b11110000) {
        follow_bytes = 3;  // 11110xxx 4-byte
      } else {
        return false;  // Invalid UTF-8 start byte
      }
    }
  }
  return follow_bytes == 0;
}

}  // namespace

///@brief unique ptr to zip_file_t
using UniquePtrZipFileEntry =
  std::unique_ptr<zip_file_t, void (*)(zip_file_t*)>;

bool FileEntry::isFolder() const noexcept {
  return boost::ends_with(filename_, "/");
}

Zip::ConstIterator Zip::at(size_t index) const {
  if (index > vec_.size()) {
    throw std::out_of_range("Zip file entry index is out of range");
  }
  return ConstIterator(vec_.data() + index);
};

[[nodiscard]] bool IsZipArchive(const std::string& path) noexcept {
  const FileHandler file{path};
  return file.is_open();
}

Zip::Zip(const std::string& path)
  : zfile_{std::make_shared<FileHandler>(path, ZIP_RDONLY)} {
  if (!zfile_->is_open()) {
    zfile_->updateErrorString();
    throw std::runtime_error("[Zip] " + zfile_->getLastErr());
  }
  fillEntries();
};

void Zip::fillEntries() noexcept {
  try {
    const zip_int64_t entries_count =
      zip_get_num_entries(zfile_->get(), ZIP_FL_UNCHANGED);
    if (entries_count <= 0) {
      return;
    }
    vec_.reserve(entries_count);
    for (int i = 0; i < entries_count; ++i) {
      // filename
      const char* cstr_filename =
        zip_get_name(zfile_->get(), i, ZIP_FL_ENC_RAW);
      std::string filename;
      if (cstr_filename != nullptr) {
        filename = cstr_filename;
      }
      //   stat
      FileStat file_stat;
      zip_stat_t stat_raw{};
      const int stat_res = zip_stat_index(
        zfile_->get(), i, ZIP_FL_UNCHANGED | ZIP_FL_ENC_RAW, &stat_raw);
      if (stat_res != 0) {
        zfile_->updateErrorString();
        std::cerr << "[Zip] Error reading file info:" << zfile_->getLastErr()
                  << "\n";
      } else {
        file_stat = CreateFileStat(stat_raw);
      }
      vec_.emplace_back(std::move(file_stat), std::move(filename), i, zfile_);
    }

    // accumulate filenames to one string to guess the encoding
    const size_t accum_size =
      std::accumulate(vec_.cbegin(), vec_.cend(), static_cast<size_t>(0),
                      [](size_t init, const FileEntry& entry) {
                        if (!entry.stat().name) {
                          return init;
                        }
                        return init + entry.stat().name->size();
                      });
    std::string accum;
    accum.reserve(accum_size);
    std::for_each(vec_.cbegin(), vec_.cend(), [&accum](const FileEntry& entry) {
      if (!entry.stat().name) {
        return;
      }
      const std::string& stat_name = entry.stat().name.value();
      std::copy(stat_name.cbegin(), stat_name.cend(),
                std::back_inserter(accum));
    });
    // guess the encoding
    const bool need_to_convert =
      accum.size() > 4 && is_valid_cp866(accum) && !is_valid_utf8(accum);
    if (need_to_convert) {
      std::cout << "Filenames will be converted from cp866\n";
      std::for_each(vec_.begin(), vec_.end(), [](FileEntry& entry) {
        if (!entry.stat().name.has_value()) {
          return;
        }
        entry.SetFileName(cp866_to_utf8(entry.stat().name.value()));
      });
    }
  } catch (const std::exception& ex) {
    std::cerr << "[Zip::fillEntries][error]" << ex.what() << "\n";
  }
}

[[nodiscard]] OptBytesVector FileEntry::readToBuffer() const noexcept {
  constexpr const char* func_name = "[FileEntry::readToBuffer]";
  if (zip_file_handler_.expired() || isFolder()) {
    return std::nullopt;
  }

  auto pzip = zip_file_handler_.lock();
  if (!pzip) {
    return std::nullopt;
  }
  if (stat_.encrypted) {
    std::cerr << func_name << "[error] the file is encrypted\n";
    return std::nullopt;
  }
  BytesVector result;
  const UniquePtrZipFileEntry zfile(zip_fopen_index(pzip->get(), index_, 0),
                                    ZipEntryCloser);
  if (!zfile) {
    pzip->updateErrorString();
    std::cerr << pzip->getLastErr() << "\n";
    return std::nullopt;
  }
  // try to reserve buffer
  try {
    if (stat_.size && stat_.size.value() > 0) {
      result.resize(stat_.size.value() + 10, 0x00);
    } else {
      result.resize(1024, 0x00);
    }
  } catch (const std::exception& ex) {
    std::cerr << func_name << "[error]" << ex.what() << "\n";
    return std::nullopt;
  }
  // read the file
  zip_int64_t bytes_read = 1;
  zip_int64_t bytes_read_total = 0;
  while (bytes_read > 0) {
    const zip_int64_t buff_free_size =
      static_cast<zip_int64_t>(result.size()) - bytes_read_total;
    bytes_read =
      zip_fread(zfile.get(), result.data() + bytes_read_total, buff_free_size);
    if (bytes_read == -1) {
      pzip->updateErrorString();
      std::cerr << func_name << "[error] error reading the file entry\n";
      return std::nullopt;
    }
    bytes_read_total += bytes_read;
    if (buff_free_size == 0 && bytes_read != 0) {
      try {
        result.resize(result.size() + 1024);
      } catch (const std::exception& ex) {
        std::cerr << func_name << "[error] not enough memory\n";
        return std::nullopt;
      }
    }
  };
  result.resize(bytes_read_total);
  return result;
}

bool FileEntry::readToFile(const std::string& dest) const noexcept {
  constexpr const char* func_name = "[FileEntry::readToFile]";
  if (zip_file_handler_.expired()) {
    return false;
  }
  auto pzip = zip_file_handler_.lock();
  if (!pzip) {
    return false;
  }
  // just create the folder
  if (isFolder()) {
    try {
      return std::filesystem::create_directories(dest);
    } catch (const std::exception& ex) {
      std::cerr << "[FileEntry::readToFile] create folder error: " << ex.what()
                << "\n";
      return false;
    }
  }
  // create the parent path
  try {
    const std::filesystem::path dest_path(dest);
    std::filesystem::create_directories(dest_path.parent_path());
  } catch (const std::exception& ex) {
    std::cerr << func_name << "[error] Filesystem error: " << ex.what() << "\n";
    return false;
  }
  // create the file
  std::ofstream file(dest, std::ios_base::binary | std::ios_base::out);
  if (!file.is_open()) {
    std::cerr << func_name << "[error] can not create the file:" << dest
              << "\n";
    return false;
  }
  if (stat_.encrypted) {
    std::cerr << func_name << "[error] the file is encrypted\n";
    return false;
  }

  const UniquePtrZipFileEntry zfile(zip_fopen_index(pzip->get(), index_, 0),
                                    ZipEntryCloser);
  if (!zfile) {
    pzip->updateErrorString();
    std::cerr << pzip->getLastErr() << "\n";
    return false;
  }
  BytesVector buf;
  buf.resize(1024, 0x00);
  zip_int64_t bytes_read = 1;
  while (bytes_read > 0) {
    bytes_read = zip_fread(zfile.get(), buf.data(), buf.size());
    if (bytes_read == -1) {
      pzip->updateErrorString();
      std::cerr << func_name << "[error] error reading the file entry\n";
      return false;
    }
    // NOLINTNEXTLINE
    file.write(reinterpret_cast<const char*>(buf.data()), bytes_read);
  }
  return true;
}

std::optional<std::string> FileEntry::readToDir(
  std::string dir) const noexcept {
  if (dir.empty() || !stat_.name.has_value()) {
    return std::nullopt;
  }
  if (!boost::algorithm::ends_with(dir, "/")) {
    dir.push_back('/');
  }
  dir += stat_.name.value();
  if (readToFile(dir)) {
    return dir;
  }
  return std::nullopt;
}

std::optional<std::string> FileEntry::readToTmp() const noexcept {
  if (zip_file_handler_.expired()) {
    return std::nullopt;
  }
  auto pzip = zip_file_handler_.lock();
  if (!pzip) {
    return std::nullopt;
  }
  // full path of this zip file (/foo/bar/archive.zip)
  auto full_zip_path = pzip->getFullPath();
  if (!full_zip_path) {
    return std::nullopt;
  }
  try {
    // tmp_folder + filename = /tmp/archive
    const std::string dest =
      std::filesystem::temp_directory_path().string() + "/csppdf/" +
      std::filesystem::path(full_zip_path.value()).filename().stem().string();
    pzip->registerTmpFolder(dest);
    return readToDir(dest);
  } catch (const std::exception& ex) {
    std::cerr << "[FileEntry::readToTmp] Filesystem error: " << ex.what()
              << "\n";
    return std::nullopt;
  }
}

ZipCreator::ZipCreator(std::string path) : target_path_(std::move(path)) {
  const std::string func_name = "[Zip::create] ";
  if (std::filesystem::exists(target_path_)) {
    throw std::runtime_error(func_name +
                             "file already exists: " + target_path_);
  }
  zfile_ = std::make_shared<FileHandler>(target_path_, ZIP_CREATE | ZIP_EXCL);
  if (!zfile_->is_open()) {
    throw std::runtime_error(func_name +
                             "create file failed:" + zfile_->getLastErr());
  }
}

void ZipCreator::reset() noexcept {
  if (!zfile_) {
    return;
  }
  const int res = zip_unchange_all(zfile_->get());
  if (res == -1) {
    zfile_->updateErrorString();
    std::cerr << "[ZipCreator::reset][error]" << zfile_->getLastErr();
  }
  buffers_.clear();
  vec_.clear();
}

ZipCreator::~ZipCreator() { reset(); }

bool ZipCreator::commit() noexcept {
  const bool res = zfile_->close();
  vec_.clear();
  std::vector<std::string> tmp_dirs = zfile_->getTmpDirsCreated();
  zfile_ = std::make_shared<FileHandler>(target_path_, ZIP_CREATE);
  zfile_->setTmpDirsCreated(std::move(tmp_dirs));
  fillEntries();
  return res;
}

bool ZipCreator::push_file(BytesVector data, const std::string& name) noexcept {
  if (!zfile_ || name.empty() || data.empty()) {
    return false;
  }
  buffers_.emplace_back(std::move(data));
  zip_source_t* zbuffer = zip_source_buffer(
    zfile_->get(), buffers_.back().data(), buffers_.back().size(), 0);
  zip_int64_t index = -1;
  if (zbuffer != nullptr) {
    index =
      zip_file_add(zfile_->get(), name.c_str(), zbuffer, ZIP_FL_ENC_UTF_8);
  }
  int set_comp_result = -1;
  if (index != -1) {
    set_comp_result =
      zip_set_file_compression(zfile_->get(), index, ZIP_CM_DEFAULT, 0);
  }
  if (zbuffer == nullptr || index == -1 || set_comp_result == -1) {
    zfile_->updateErrorString();
    std::cerr << "[ZipCreator::push_file][error]" << zfile_->getLastErr()
              << "\n";
  }
  const char* cstr_filename =
    zip_get_name(zfile_->get(), index, ZIP_FL_ENC_RAW);
  std::string filename;
  if (cstr_filename != nullptr) {
    filename = cstr_filename;
  }
  //   stat
  FileStat file_stat;
  zip_stat_t stat_raw{};
  const int stat_res =
    zip_stat_index(zfile_->get(), index, ZIP_FL_ENC_RAW, &stat_raw);
  if (stat_res != 0) {
    zfile_->updateErrorString();
    std::cerr << "[Zip] Error reading file info:" << zfile_->getLastErr()
              << "\n";
  } else {
    file_stat = CreateFileStat(stat_raw);
  }
  vec_.emplace_back(std::move(file_stat), std::move(filename), index, zfile_);
  return true;
}

bool ZipCreator::push_file(const std::string& data,
                           const std::string& name) noexcept {
  BytesVector buf(data.data(), data.data() + data.size());
  return push_file(std::move(buf), name);
}

bool ZipCreator::push_file(const std::string& path) noexcept {
  try {
    const auto fs_path = std::filesystem::path(path);
    if (path.empty() || !std::filesystem::exists(fs_path) ||
        !std::filesystem::is_regular_file(fs_path)) {
      return false;
    }
    auto file_data = pdfcsp::utils::FileToVector(path);
    if (!file_data) {
      return false;
    }
    return push_file(file_data.value(), fs_path.filename().string());
  } catch (const std::exception&) {
    return false;
  }
}

[[nodiscard]] bool ZipCreator::push_folder(const std::string& folder) noexcept {
  if (folder.empty()) {
    return false;
  }
  const zip_int64_t index =
    zip_dir_add(zfile_->get(), folder.c_str(), ZIP_FL_ENC_UTF_8);
  if (index == -1) {
    zfile_->updateErrorString();
    std::cerr << "[ZipCreator::push_folder][error] add folder failed"
              << zfile_->getLastErr() << "\n";
    return false;
  }
  FileStat file_stat;
  zip_stat_t stat_raw{};
  const int stat_res =
    zip_stat_index(zfile_->get(), index, ZIP_FL_ENC_RAW, &stat_raw);
  if (stat_res != 0) {
    zfile_->updateErrorString();
    std::cerr << "[Zip] Error reading file info:" << zfile_->getLastErr()
              << "\n";
  } else {
    file_stat = CreateFileStat(stat_raw);
  }
  vec_.emplace_back(std::move(file_stat), folder, index, zfile_);
  return true;
}

std::vector<std::string> Zip::getTmpDirsCreated() const noexcept {
  if (!zfile_) {
    return {};
  }
  return zfile_->getTmpDirsCreated();
}

bool Zip::removeTempDirs() noexcept {
  if (!zfile_) {
    return true;
  }
  try {
    const auto& dirs = zfile_->getTmpDirsCreated();
    std::for_each(dirs.cbegin(), dirs.cend(), [](const std::string& dir) {
      std::ignore = std::filesystem::remove_all(dir);
    });
    zfile_->clearTmpDirsCreated();
  } catch (const std::exception& ex) {
    std::cerr << "[Zip::removeTempDirs][error] " << ex.what() << "\n";
    return false;
  }
  return true;
}

#ifdef TEST_BUILD
bool TestEmptyHandler() {
  const FileHandler handler;
  return !handler.is_open();
}

bool TestNormalHandler(const std::string& path) {
  const FileHandler handler(path);
  return handler.is_open();
}

bool TestMoveConstructorHandler(const std::string& path) {
  FileHandler handl1(path);
  const FileHandler handl2(std::move(handl1));
  return !handl1.is_open() && handl2.is_open();  // NOLINT
}
bool TestMoveAssignmentHandler(const std::string& path) {
  FileHandler handl1(path);
  FileHandler handl2;
  handl2 = std::move(handl1);
  return !handl1.is_open() && handl2.is_open();  // NOLINT
}

bool TestBoolOperatorHandler(const std::string& path) {
  const FileHandler handl1(path);
  const FileHandler handl2;
  return static_cast<bool>(handl1) && !static_cast<bool>(handl2);
}
bool IsValidUtf(const std::string& str) { return is_valid_utf8(str); }

#endif

// google guess unused
// bool detectCP1251(const std::string& text) {
//   int bytes_consumed = 0;
//   bool is_reliable = false;
//   Encoding encoding = CompactEncDet::DetectEncoding(
//     text.data(), text.length(), nullptr, nullptr, nullptr, UNKNOWN_ENCODING,
//     UNKNOWN_LANGUAGE, CompactEncDet::WEB_CORPUS, false, &bytes_consumed,
//     &is_reliable);
//   if (encoding == 42) {
//     std::cout << "RUSSIAN_CP866\n";
//   } else if (encoding == 22) {
//     std::cout << "UTF-8\n";
//   } else {
//     std::cout << encoding << "\n";
//   }
//   std::cout << "Reliable:" << is_reliable << "\n";
//   return (encoding == RUSSIAN_CP1251);
// }

}  // namespace zip_cpp