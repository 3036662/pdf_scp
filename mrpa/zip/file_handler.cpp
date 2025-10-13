#include "file_handler.hpp"

#include <filesystem>
#include <iostream>

#include "utils_zip.hpp"

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
  : zip_{other.zip_},
    err_code_{other.err_code_},
    err_string_{std::move(other.err_string_)},
    file_path_{std::move(other.file_path_)} {
  other.zip_ = nullptr;
  other.err_code_ = 0;
}

FileHandler& FileHandler::operator=(FileHandler&& other) noexcept {
  if (this == &other) {
    return *this;
  }
  zip_ = other.zip_;
  other.zip_ = nullptr;
  err_code_ = other.err_code_;
  other.err_code_ = 0;
  err_string_ = std::move(other.err_string_);
  file_path_ = std::move(other.file_path_);
  return *this;
}

FileHandler::FileHandler(std::string filepath, int flags) noexcept
  : file_path_{std::move(filepath)} {
  if ((file_path_->empty() || !std::filesystem::exists(file_path_.value())) &&
      !checkFlag(flags, ZIP_CREATE)) {
    err_string_ = "File not found";
  }
  zip_ = zip_open(file_path_->c_str(), flags, &err_code_);
  if (err_code_ != 0) {
    updateErrorString();
  }
}
void FileHandler::registerTmpFolder(std::string tmp_folder_created) noexcept {
  tmp_folders_created_.emplace_back(std::move(tmp_folder_created));
}

bool FileHandler::close() noexcept {
  if (zip_ == nullptr) {
    return true;
  }
  if (zip_close(zip_) != 0) {
    std::cerr << "Error closing file" << "\n";
    return false;
  }
  zip_ = nullptr;
  return true;
}

FileHandler::~FileHandler() {
  if (zip_ == nullptr) {
    return;
  }
  if (zip_close(zip_) != 0) {
    std::cerr << "Error closing file" << "\n";
  };
}

FileHandler::operator bool() const noexcept {
  return zip_ != nullptr && err_code_ == 0 && !err_string_;
}

bool FileHandler::is_open() const noexcept {
  return zip_ != nullptr && err_code_ == 0 && !err_string_;
}

}  // namespace zip_cpp