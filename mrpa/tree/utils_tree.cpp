#include "utils_tree.hpp"

#include <chrono>
#include <exception>
#include <filesystem>

#include "file_stat.hpp"

namespace mrpa {

PtrNode createNodeFromFile(const std::string& path) noexcept {
  try {
    if (path.empty() || !std::filesystem::exists(path)) {
      return nullptr;
    }
    // regular file
    const std::filesystem::path fpath(path);
    if (std::filesystem::is_regular_file(fpath)) {
      zip_cpp::FileStat fstat;
      fstat.name = fpath.filename();
      fstat.size = std::filesystem::file_size(fpath);
      const auto sctp =
        std::chrono::time_point_cast<std::chrono::system_clock::duration>(
          std::filesystem::last_write_time(fpath) -
          std::filesystem::file_time_type::clock::now() +
          std::chrono::system_clock::now());
      fstat.time_mod = std::chrono::system_clock::to_time_t(sctp);
      // determine the file type: File,Sig,Asig,Zip
    }
  } catch (const std::exception& ex) {
    return nullptr;
  }
  return nullptr;
}

}  // namespace mrpa