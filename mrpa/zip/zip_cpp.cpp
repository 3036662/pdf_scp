#include "zip_cpp.hpp"

#include <libzip/zip.h>

#include <cstdint>
#include <filesystem>
#include <iostream>
#include <memory>
#include <optional>
#include <sstream>
#include <utility>

namespace zip_cpp {

namespace {

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
  std::cout << "[Debug] raw_flags" << memb_flags << "\n";
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

}  // namespace

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
    if (filepath.empty() || !std::filesystem::exists(filepath)) {
      err_string = "File not found";
    }
    zip = zip_open(filepath.c_str(), flags, &err_code);
    if (err_code != 0) {
      updateErrorString();
    }
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

Zip::Zip(const std::string& path, bool read_only) noexcept
  : zfile_{std::make_shared<FileHandler>(path, read_only)} {
  if (!zfile_->is_open()) {
    return;
  }
  zip_int64_t entries_count =
    zip_get_num_entries(zfile_->get(), ZIP_FL_UNCHANGED);
  if (entries_count <= 0) {
    return;
  }
  vec_.reserve(entries_count);
  for (int i = 0; i < entries_count; ++i) {
    // filename
    const char* cstr_filename =
      zip_get_name(zfile_->get(), i, ZIP_FL_ENC_RAW | ZIP_FL_ENC_GUESS);
    std::string filename;
    if (cstr_filename != nullptr) {
      filename = cstr_filename;
    }
    // stat
    FileStat file_stat;
    zip_stat_t stat_raw{};
    int stat_res = zip_stat_index(
      zfile_->get(), i, ZIP_FL_UNCHANGED | ZIP_FL_ENC_GUESS, &stat_raw);
    if (stat_res != 0) {
      zfile_->updateErrorString();
      std::cerr << "[Zip] Error reading file info:" << zfile_->getLastErr()
                << "\n";
    } else {
      file_stat = CreateFileStat(stat_raw);
    }
    std::cout << "[Debug]" << file_stat.toSting() << "\n";
    vec_.emplace_back(std::move(file_stat), std::move(filename));
  }
};

}  // namespace zip_cpp