#pragma once
#include <libzip/zip.h>
#include <zipconf.h>

#include <optional>
#include <string>

namespace zip_cpp {

std::string ErrCodeToString(int err_code);

class FileHandler {
 public:
  FileHandler() = default;

  FileHandler(const FileHandler& other) = delete;
  FileHandler& operator=(const FileHandler& other) = delete;

  FileHandler(FileHandler&& other) noexcept;

  FileHandler& operator=(FileHandler&& other) noexcept;

  explicit FileHandler(const std::string& filepath,
                       int flags = ZIP_RDONLY) noexcept;

  bool close() noexcept;

  ~FileHandler();

  [[nodiscard]] zip_t* get() const noexcept { return zip; }

  explicit operator bool() const noexcept;

  [[nodiscard]] bool is_open() const noexcept;

  void updateErrorString() { err_string = ErrCodeToString(err_code); };

  std::string getLastErr() { return err_string.value_or(""); }

 private:
  zip_t* zip = nullptr;
  int err_code = 0;
  std::optional<std::string> err_string;
  std::optional<std::string> file_path;
};

}  // namespace zip_cpp