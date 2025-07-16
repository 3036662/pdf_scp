#include "zip_cpp.hpp"

#include <libzip/zip.h>
#include <zipconf.h>

#include <algorithm>
#include <boost/locale.hpp>
#include <cstdint>
#include <exception>
#include <filesystem>
#include <iostream>
#include <iterator>
#include <memory>
#include <numeric>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

// google guess unused
// #include "compact_enc_det/compact_enc_det.h"

namespace zip_cpp {

namespace {

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

std::string ErrCodeToString(int err_code) {
  zip_error_t error;
  zip_error_init_with_code(&error, err_code);
  const char* err_c_str = zip_error_strerror(&error);
  if (err_c_str == nullptr) {
    return {};
  }
  std::string res(err_c_str);
  zip_error_fini(&error);
  return res;
}

inline bool checkFlag(uint64_t val, uint64_t flag) { return (val & flag) != 0; }

FileStat CreateFileStat(const struct zip_stat& raw_stat) {
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
  for (unsigned char symbol : str) {
    if (symbol < 0x80) {
      continue;
    }
    // Check valid CP866 ranges
    if ((symbol < 0x80 || symbol > 0xAF) &&  // Cyrillic uppercase
        (symbol < 0xE0 || symbol > 0xFF)) {  // Cyrillic lowercase + symbols
      std::cout << "invalid cp866 symbol:" << std::to_string(symbol) << "\n";
      return false;
    }
  }
  return !str.empty();
}

bool is_valid_utf8(const std::string& str) {
  int follow_bytes = 0;
  for (unsigned char symbol : str) {
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

class FileHandler {
 public:
  FileHandler() = default;

  FileHandler(const FileHandler& other) = delete;

  FileHandler& operator=(const FileHandler& other) = delete;

  FileHandler(FileHandler&& other) noexcept
    : zip{other.zip},
      err_code{other.err_code},
      err_string{std::move(other.err_string)},
      file_path{std::move(other.file_path)} {
    other.zip = nullptr;
    other.err_code = 0;
  }

  FileHandler& operator=(FileHandler&& other) noexcept {
    if (this == &other) {
      return *this;
    }
    zip = other.zip;
    other.zip = nullptr;
    err_code = other.err_code;
    other.err_code = 0;
    err_string = std::move(other.err_string);
    file_path = std::move(other.file_path);
    return *this;
  }

  explicit FileHandler(const std::string& filepath,
                       int flags = ZIP_RDONLY) noexcept {
    if ((filepath.empty() || !std::filesystem::exists(filepath)) &&
        !checkFlag(flags, ZIP_CREATE)) {
      err_string = "File not found";
    }
    zip = zip_open(filepath.c_str(), flags, &err_code);
    if (err_code != 0) {
      updateErrorString();
    }
  }

  bool close() {
    if (zip == nullptr) {
      return true;
    }
    if (zip_close(zip) != 0) {
      std::cerr << "Error closing file" << "\n";
      return false;
    }
    zip = nullptr;
    return true;
  }

  ~FileHandler() {
    if (zip == nullptr) {
      return;
    }
    if (zip_close(zip) != 0) {
      std::cerr << "Error closing file" << "\n";
    };
  }

  [[nodiscard]] zip_t* get() const noexcept { return zip; }

  explicit operator bool() const noexcept {
    return zip != nullptr && err_code == 0 && !err_string;
  }

  [[nodiscard]] bool is_open() const noexcept {
    return zip != nullptr && err_code == 0 && !err_string;
  }

  void updateErrorString() { err_string = ErrCodeToString(err_code); };

  std::string getLastErr() { return err_string.value_or(""); }

 private:
  zip_t* zip = nullptr;
  int err_code = 0;
  std::optional<std::string> err_string;
  std::optional<std::string> file_path;
};

Zip::ConstIterator Zip::at(size_t index) const {
  if (index > vec_.size()) {
    throw std::out_of_range("Zip file entry index is out of range");
  }
  return ConstIterator(vec_.data() + index);
};

[[nodiscard]] bool IsZipArchive(const std::string& path) noexcept {
  FileHandler file{path};
  return file.is_open();
}

std::string FileStat::toSting() const noexcept {
  std::ostringstream builder;
  if (name) {
    builder << "name:" << name.value() << "; ";
  }
  if (index) {
    builder << "index:" << index.value() << "; ";
  }
  if (size) {
    builder << "size:" << size.value() << "; ";
  }
  if (size_compressed) {
    builder << "size_compressed:" << size_compressed.value() << "; ";
  }
  if (time_mod) {
    builder << "modification time:" << time_mod.value() << "; ";
  }
  if (crc) {
    builder << "crc:" << crc.value() << "; ";
  }
  if (comp_method) {
    builder << "comp_method:" << comp_method.value() << "; ";
  }
  if (encryption_method) {
    builder << "encryption_method:" << encryption_method.value() << "; ";
  }
  builder << "Encrypted:" << encrypted << ";";
  return builder.str();
}

Zip::Zip(const std::string& path) noexcept
  : zfile_{std::make_shared<FileHandler>(path, ZIP_RDONLY)} {
  if (!zfile_->is_open()) {
    return;
  }
  fillEntries();
};

void Zip::fillEntries() noexcept {
  zip_int64_t entries_count =
    zip_get_num_entries(zfile_->get(), ZIP_FL_UNCHANGED);
  if (entries_count <= 0) {
    return;
  }
  vec_.reserve(entries_count);
  for (int i = 0; i < entries_count; ++i) {
    // filename
    const char* cstr_filename = zip_get_name(zfile_->get(), i, ZIP_FL_ENC_RAW);
    std::string filename;
    if (cstr_filename != nullptr) {
      filename = cstr_filename;
    }
    //   stat
    FileStat file_stat;
    zip_stat_t stat_raw{};
    int stat_res = zip_stat_index(zfile_->get(), i,
                                  ZIP_FL_UNCHANGED | ZIP_FL_ENC_RAW, &stat_raw);
    if (stat_res != 0) {
      zfile_->updateErrorString();
      std::cerr << "[Zip] Error reading file info:" << zfile_->getLastErr()
                << "\n";
    } else {
      file_stat = CreateFileStat(stat_raw);
    }
    vec_.emplace_back(std::move(file_stat), std::move(filename), i, zfile_);
  }

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
    std::copy(stat_name.cbegin(), stat_name.cend(), std::back_inserter(accum));
  });
  bool need_to_convert =
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
}

[[nodiscard]] OptBytesVector FileEntry::readToBuffer() const noexcept {
  constexpr const char* func_name = "[FileEntry::readToBuffer]";
  if (zip_file_handler_.expired()) {
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
  UniquePtrZipFileEntry zfile(zip_fopen_index(pzip->get(), index_, 0),
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
    zip_int64_t buff_free_size =
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

ZipCreator::ZipCreator(std::string path) : target_path_(std::move(path)) {
  const std::string func_name = "[Zip::create] ";
  if (std::filesystem::exists(target_path_)) {
    throw std::runtime_error(func_name + "file already exists");
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
  int res = zip_unchange_all(zfile_->get());
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
  zfile_ = std::make_shared<FileHandler>(target_path_, ZIP_CREATE);
  fillEntries();
  return res;
}

bool ZipCreator::push_file(BytesVector data, const std::string& name) noexcept {
  if (!zfile_ && name.empty() && data.empty()) {
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
  int stat_res =
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
  buf.push_back(0x00);
  return push_file(std::move(buf), name);
}

#ifdef TEST_BUILD
bool TestEmptyHandler() {
  FileHandler handler;
  return !handler.is_open();
}

bool TestNormalHandler(const std::string& path) {
  FileHandler handler(path);
  return handler.is_open();
}

bool TestMoveConstructorHandler(const std::string& path) {
  FileHandler handl1(path);
  FileHandler handl2(std::move(handl1));
  return !handl1.is_open() && handl2.is_open();
}
bool TestMoveAssignmentHandler(const std::string& path) {
  FileHandler handl1(path);
  FileHandler handl2;
  handl2 = std::move(handl1);
  return !handl1.is_open() && handl2.is_open();
}

bool TestBoolOperatorHandler(const std::string& path) {
  FileHandler handl1(path);
  FileHandler handl2;
  return static_cast<bool>(handl1) && !static_cast<bool>(handl2);
}
#endif

}  // namespace zip_cpp