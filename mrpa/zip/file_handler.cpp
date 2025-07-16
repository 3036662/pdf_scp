#include "file_handler.hpp"

#include <filesystem>
#include <iostream>

#include "utils_common.hpp"

namespace zip_cpp {

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

FileHandler::FileHandler(FileHandler&& other) noexcept
  : zip{other.zip},
    err_code{other.err_code},
    err_string{std::move(other.err_string)},
    file_path{std::move(other.file_path)} {
  other.zip = nullptr;
  other.err_code = 0;
}

FileHandler& FileHandler::operator=(FileHandler&& other) noexcept {
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

FileHandler::FileHandler(const std::string& filepath, int flags) noexcept {
  if ((filepath.empty() || !std::filesystem::exists(filepath)) &&
      !checkFlag(flags, ZIP_CREATE)) {
    err_string = "File not found";
  }
  zip = zip_open(filepath.c_str(), flags, &err_code);
  if (err_code != 0) {
    updateErrorString();
  }
}

bool FileHandler::close() noexcept {
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

FileHandler::~FileHandler() {
  if (zip == nullptr) {
    return;
  }
  if (zip_close(zip) != 0) {
    std::cerr << "Error closing file" << "\n";
  };
}

FileHandler::operator bool() const noexcept {
  return zip != nullptr && err_code == 0 && !err_string;
}

bool FileHandler::is_open() const noexcept {
  return zip != nullptr && err_code == 0 && !err_string;
}

}  // namespace zip_cpp