#include "cli_utils.hpp"

#include <algorithm>
#include <boost/algorithm/string/predicate.hpp>
#include <cstddef>
#include <ctime>
#include <exception>
#include <filesystem>
#include <fstream>
#include <ios>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>

#include "altcsp.hpp"
#include "cert_common_info.hpp"
#include "csppdf.hpp"
#include "image_obj.hpp"
#include "pdf_pod_structs.hpp"
#include "pdf_utils.hpp"
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

/**
 * @brief Check the output directory
 *
 * @param output_dir
 * @param log logger
 * @return true - existing,writable
 * @return false
 */
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

/**
 * @brief Check if the given certificate exists in CSP
 *
 * @param cert serial number
 * @return true if exists
 * @return false
 */
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

/**
 * @brief Get info for one certificate
 *
 * @param cert serial number (string)
 * @param csp
 * @param log
 * @return std::optional<csp::CertCommonInfo>
 */
std::optional<csp::CertCommonInfo> GetCertInfo(
  const std::string& cert, const std::shared_ptr<csp::Csp>& csp,
  const std::shared_ptr<spdlog::logger>& log) {
  auto cert_list = csp->GetCertList();
  auto it_cert = std::find_if(
    cert_list.cbegin(), cert_list.cend(),
    [&cert](const csp::CertCommonInfo& info) {
      return csp::VecBytesStringRepresentation(info.serial) == cert;
    });
  if (it_cert == cert_list.cend()) {
    log->error(trs("Certificate not found") + cert);
    return std::nullopt;
  }
  return *it_cert;
}

/**
 * @brief Perfom file sign
 *
 * @param src_file source file
 * @param options command options object
 * @param csp
 * @param log
 * @param p_cached_img  raw poiner to ImageObj to use ase cached image value
 * @return pdfcsp::pdf::CSignPrepareResult*
 * @details fill CSignParams for PrepareDocCli
 */
pdfcsp::pdf::CSignPrepareResult* PerformSign(
  const std::string& src_file, const Options& options,
  const std::shared_ptr<csp::Csp>& csp,
  const std::shared_ptr<spdlog::logger>& log, pdf::ImageObj* p_cached_img) {
  pdf::CSignParams params{};
  std::shared_ptr<pdfcsp::pdf::Pdf> pdf_obj;
  try {
    pdf_obj = std::make_shared<pdf::Pdf>(src_file);
  } catch (const std::exception& ex) {
    log->error(tr("Cannot sign damaged document"));
    throw;
  }
  if (!pdf_obj->Valid()) {
    log->error(tr("Cannot sign damaged document"));
    return nullptr;
  }
  // if we already have an image in cache
  params.perform_cache_image = true;
  params.cached_img = p_cached_img;
  // page index
  params.page_index = options.GetPageNumber() - 1;
  if (params.page_index < 0 ||
      static_cast<size_t>(params.page_index) >= pdf_obj->GetPagesCount()) {
    throw std::runtime_error(trs("Invalid page number") + " " +
                             std::to_string(options.GetPageNumber()));
  }
  // page sizes
  auto visible_page_size =
    pdf::VisiblePageSize(pdf_obj->GetPage(params.page_index));
  if (!visible_page_size) {
    throw std::runtime_error(tr("Can't determine the page sise for file ") +
                             src_file);
  }
  params.page_width =
    visible_page_size->right_top.x - visible_page_size->left_bottom.x;
  params.page_height =
    visible_page_size->right_top.y - visible_page_size->left_bottom.y;
  if (params.page_width <= 0 || params.page_height <= 0) {
    throw std::runtime_error(tr("Invalid page size for file ") + src_file);
  }
  log->debug(trs("Page sizes:") + tr(" w ") +
             std::to_string(params.page_width) + tr(" h ") +
             std::to_string(params.page_height));
  // stamp position
  {
    const auto stamp_xy_percents = options.GetStampXYPercent();
    params.stamp_x = params.page_width * stamp_xy_percents.first / 100;
    params.stamp_y = params.page_height * stamp_xy_percents.second / 100;
    log->debug(trs("Stamp position:") + tr(" w ") +
               std::to_string(params.stamp_x) + tr(" h ") +
               std::to_string(params.stamp_y));
  }
  // stamp size
  {
    const auto stamp_size_percents = options.GetStampSizePercent();
    params.stamp_width = params.page_width * stamp_size_percents.first / 100;
    params.stamp_height = params.page_height * stamp_size_percents.second / 100;
    log->debug(trs("Stamp size:") + tr(" w ") +
               std::to_string(params.stamp_width) + tr(" h ") +
               std::to_string(params.stamp_height));
  }
  // logo
  const std::string logo_path = options.GetLogoPath();
  if (!logo_path.empty()) {
    params.logo_path = logo_path.c_str();
  }
  log->debug(trs("Logo path") + " " + logo_path);
  // set config path same as parent path to logo
  const std::filesystem::path plogo(logo_path);
  const std::string config_path = plogo.parent_path().string();
  params.config_path = config_path.c_str();
  // certificate info
  const std::string cert = options.GetCertSerial();
  params.cert_serial = cert.c_str();
  const std::string cert_serial_prefix = tr("Certificate: ");
  params.cert_serial_prefix = cert_serial_prefix.c_str();
  auto cert_info = GetCertInfo(cert, csp, log);
  if (!cert_info) {
    log->error(tr("Error reading the certificate info"));
    return nullptr;
  }
  params.cert_subject = cert_info->subj_common_name.c_str();
  const std::string cert_subject_prefix = trs("Subject: ");
  params.cert_subject_prefix = cert_subject_prefix.c_str();
  // time validity
  std::string cert_time_validity = trs("Validity: ");
  cert_time_validity += csp::TimeTToString(cert_info->not_before);
  cert_time_validity += trs(" till ");
  cert_time_validity += csp::TimeTToString(cert_info->not_after);
  params.cert_time_validity = cert_time_validity.c_str();
  // stamp type
  const std::string stamp_type = "ГОСТ";
  params.stamp_type = stamp_type.c_str();
  // cades type
  const std::string cades_type = options.GetCadesType();
  params.cades_type = cades_type.c_str();
  // file path
  params.file_to_sign_path = src_file.c_str();
  // temp folder is same as output folder
  const std::string output_folder = options.GetOutputDir();
  params.temp_dir_path = output_folder.c_str();
  // tsp link
  const std::string tsp_url = options.GetTSPLink();
  params.tsp_link = tsp_url.c_str();
  const std::string stamp_title =
    trs("THE DOCUMENT IS SIGNED WITH AN ELECTRONIC SIGNATURE");
  params.stamp_title = stamp_title.c_str();
  pdf::CSignPrepareResult* result = PrepareDocCli(params, log);
  if (result == nullptr) {
    log->error(tr("Sign document failed"));
    return nullptr;
  }
  if (!result->status) {
    log->error(tr("Sign document failed"));
    log->error(result->err_string);
  } else {
    log->info(tr("Signed successfully"));
    // rename temporary file to destination
    RenameTempFileToDest(result, src_file, options, log);
  }
  return result;
};

/**
 * @brief Create a signed file
 *
 * @param params CSignParams prepared by PerformSign
 * @param logger
 * @return pdf::CSignPrepareResult*
 * @details If CSignParams::perform_cache_image is TRUE, the stamp image will be
 * cached and returned with CSignPrepareResult.
 */
pdf::CSignPrepareResult* PrepareDocCli(
  pdf::CSignParams params, const std::shared_ptr<spdlog::logger>& logger) {
  pdf::CSignPrepareResult* res = new pdf::CSignPrepareResult{};  // NOLINT
  res->storage = new pdf::CSignPrepareResult::SignResStorage{};  // NOLINT
  try {
    if (params.file_to_sign_path == nullptr) {
      throw std::runtime_error("file_to_sign == nullptr");
    }
    auto pdf = std::make_unique<pdf::Pdf>(params.file_to_sign_path);
    auto stage1_result = pdf->CreateObjectKit(params);
    pdf.reset();  // free the source file
    // cache the img object
    res->storage->cached_img = std::move(stage1_result.cached_img);
    // read file
    const std::string file_path = stage1_result.file_name;
    const pdf::RangesVector& byteranges = stage1_result.byteranges;
    auto data_for_hashing = pdf::FileToVector(file_path, byteranges);
    if (!data_for_hashing) {
      throw std::runtime_error("Error reading data from " + file_path);
    }
    const std::string cades_type_str = params.cades_type;
    csp::CadesType cades_type = csp::CadesType::kUnknown;
    if (cades_type_str == "CADES_BES") {
      cades_type = csp::CadesType::kCadesBes;
    } else if (cades_type_str == "CADES_T") {
      cades_type = csp::CadesType::kCadesT;
    } else if (cades_type_str == "CADES_XLT1") {
      cades_type = csp::CadesType::kCadesXLong1;
    }
    // tsp url
    std::wstring tsp_url;
    {
      const std::string tsp_url_temp = params.tsp_link;
      std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
      tsp_url = converter.from_bytes(tsp_url_temp);
    }
    // create result
    const csp::Csp csp;
    auto raw_signature =
      csp.SignData(params.cert_serial, params.cert_subject, cades_type,
                   data_for_hashing.value(), tsp_url);
    // patch the file
    if (!raw_signature.empty() &&
        raw_signature.size() < stage1_result.sig_max_size) {
      pdf::PatchDataToFile(stage1_result.file_name, stage1_result.sig_offset,
                           pdf::ByteVectorToHexString(raw_signature));
    }
    res->status = true;
    res->storage->file_path = stage1_result.file_name;
    res->tmp_file_path = res->storage->file_path.c_str();
  } catch (const std::exception& ex) {
    logger->error("[cli] error, {}", ex.what());
    res->status = false;
    res->storage->err_string = std::string("[PDFCSP::PrepareDoc] ") + ex.what();
    res->err_string = res->storage->err_string.c_str();
  }
  return res;
}

/**
 * @brief Rename temporary file to destination
 *
 * @param [in,out] result CSignPrepareResult - destination filename will be
 * placed here
 * @param [in] src_file
 * @param [in] options
 * @param [in] log
 * @return true on success
 * @return false on fail
 */
bool RenameTempFileToDest(pdf::CSignPrepareResult* result,
                          const std::string& src_file, const Options& options,
                          const std::shared_ptr<spdlog::logger>& log) {
  if (result == nullptr) {
    return false;
  }
  try {
    std::vector<std::string> extensions;
    const uint max_it = 10;
    uint it_counter = 0;
    std::string clear_path =
      options.GetOutputDir() +
      std::filesystem::path(src_file).filename().string();
    std::string next = std::filesystem::path(clear_path).extension();
    while (!next.empty() && it_counter < max_it) {
      ++it_counter;
      // shrink one extension
      clear_path.resize(clear_path.length() - next.length());
      extensions.emplace_back(std::move(next));
      next = std::filesystem::path(clear_path).extension();
    }
    // add postfix
    clear_path += options.GetNamePostifx();
    // append the rest of extensions
    std::for_each(extensions.cbegin(), extensions.cend(),
                  [&clear_path](const std::string& ext) { clear_path += ext; });
    while (std::filesystem::exists(clear_path)) {
      log->warn(trs("File already exists ") + clear_path);
      clear_path += ".next";
    }
    log->info(trs("Rename result file to ") + clear_path);
    std::filesystem::rename(result->tmp_file_path, clear_path);
    result->storage->file_path = clear_path;
    result->tmp_file_path = result->storage->file_path.c_str();
    return true;
  } catch (const std::exception& ex) {
    log->error(ex.what());
    result->status = false;
    result->storage->err_string =
      trs("Rename result file failed: ") + ex.what();
  }
  return false;
}

}  // namespace pdfcsp::cli
