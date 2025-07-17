#pragma once
#include <libzip/zip.h>
#include <zipconf.h>

#include <optional>
#include <string>
#include <vector>

namespace zip_cpp {

std::string ErrCodeToString(int err_code);

class FileHandler {
 public:
  FileHandler() = default;

  FileHandler(const FileHandler& other) = delete;
  FileHandler& operator=(const FileHandler& other) = delete;

  FileHandler(FileHandler&& other) noexcept;

  FileHandler& operator=(FileHandler&& other) noexcept;

  explicit FileHandler(std::string filepath, int flags = ZIP_RDONLY) noexcept;

  bool close() noexcept;

  ~FileHandler();

  [[nodiscard]] zip_t* get() const noexcept { return zip_; }

  explicit operator bool() const noexcept;

  [[nodiscard]] bool is_open() const noexcept;

  void updateErrorString() { err_string_ = ErrCodeToString(err_code_); };

  [[nodiscard]] std::string getLastErr() { return err_string_.value_or(""); }

  [[nodiscard]] const std::optional<std::string>& getFullPath() const noexcept {
    return file_path_;
  }

  void registerTmpFolder(std::string tmp_folder_created) noexcept;

  [[nodiscard]] const std::vector<std::string>& getTmpDirsCreated()
    const noexcept {
    return tmp_folders_created_;
  }
  void clearTmpDirsCreated() noexcept { tmp_folders_created_.clear(); }
  void setTmpDirsCreated(std::vector<std::string> dirs) noexcept {
    tmp_folders_created_ = std::move(dirs);
  }

 private:
  zip_t* zip_ = nullptr;
  int err_code_ = 0;
  std::optional<std::string> err_string_;
  std::optional<std::string> file_path_;
  std::vector<std::string> tmp_folders_created_;
};

}  // namespace zip_cpp