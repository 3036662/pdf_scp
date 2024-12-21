#include "cli_utils.hpp"

#include <algorithm>
#include <boost/algorithm/string/predicate.hpp>
#include <ctime>
#include <exception>
#include <filesystem>
#include <fstream>
#include <ios>
#include <memory>

#include "altcsp.hpp"
#include "cert_common_info.hpp"
#include "pdf_pod_structs.hpp"
#include "tr.hpp"
#include "utils.hpp"

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

bool CheckCertSerial(const std::string& cert,
                     const std::shared_ptr<csp::Csp>& csp,
                     const std::shared_ptr<spdlog::logger>& log) {
  auto cert_list = csp->GetCertList();
  const auto now = std::chrono::system_clock::now();
  const std::time_t nowt = std::chrono::system_clock::to_time_t(now);
  return std::any_of(
    cert_list.cbegin(), cert_list.cend(),
    [&cert, nowt, &log](const csp::CertCommonInfo& info) {
      // info.PrintToStdOut();
      if (csp::VecBytesStringRepresentation(info.serial) != cert) {
        return false;
      }
      // if found check time validity
      if (nowt > info.not_after || nowt < info.not_before) {
        log->warn(tr("The certificate is outdated "));
        return false;
      };
      return true;
    });
}


pdfcsp::pdf::CSignParams CreateSignParams(
    const Options& options,
    const std::shared_ptr<spdlog::logger>& log){
    pdf::CSignParams res{};
    //res.page_index=
    return res;    
};

}  // namespace pdfcsp::cli