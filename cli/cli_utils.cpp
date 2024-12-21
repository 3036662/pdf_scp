#include "cli_utils.hpp"

#include <algorithm>
#include <boost/algorithm/string/predicate.hpp>
#include <exception>
#include <filesystem>
#include <fstream>
#include <ios>

#include "tr.hpp"

namespace pdfcsp::cli {

/**
 * @brief Check all files - readable,non-empty, PDF
 *
 * @param files filenames
 * @param log logger
 * @return true if all files are ok
 * @return false if at least one file is bad
 */
bool CheckInputFiles(const std::vector<std::string>& files,
                     const std::shared_ptr<spdlog::logger>& log) {
  return std::all_of(
    files.cbegin(), files.cend(), [&log](const std::string& file) {
      try {
        if (!std::filesystem::exists(file)) {
          log->error(trs("File not found") + " " + file);
          return false;
        }
        if (!std::filesystem::is_regular_file(file)) {
          log->error(trs("This file is not a regular file") + " " + file);
          return false;
        }
        if (std::filesystem::file_size(file) < 10) {
          log->error(trs("File is empty or too small") + " " + file);
          return false;
        }
        // read 10 bytes to string
        auto ifile = std::ifstream(file, std::ios_base::binary);
        if (!ifile.is_open()) {
          log->error(trs("Can not open file") + " " + file);
          return false;
        }
        std::string read_buff;
        read_buff.resize(20, 0x00);
        if (!ifile.read(read_buff.data(), 10)) {
          log->error(trs("Can not read the file") + " " + file);
          return false;
        }
        if (!boost::contains(read_buff, "PDF")) {
          log->error(trs("Not a pdf file") + " " + file);
          return false;
        }
        ifile.close();
      } catch (const std::exception& ex) {
        log->error(ex.what());
        return false;
      }
      return true;
    });
}

bool CheckOutputDir(const std::string& output_dir,
                    const std::shared_ptr<spdlog::logger>& log) {
  if (!std::filesystem::exists(output_dir) ||
      !std::filesystem::is_directory(output_dir)) {
    log->error(trs("Directory not found") + " " + output_dir);
    return false;
  }
  std::string tmp_filename = output_dir;
  if (tmp_filename.back() != '/') {
    tmp_filename.push_back('/');
  }
  tmp_filename += "test_temporary_file_for_pdfsign";
  std::ofstream ofile(tmp_filename);
  if (!ofile.is_open()) {
    log->error(trs("Can not create file in directory") + " " + output_dir);
    return false;
  }
  ofile.close();
  std::filesystem::remove(tmp_filename);
  return true;
}

}  // namespace pdfcsp::cli