#pragma once

#include <memory>

#include "altcsp.hpp"
#include "cert_common_info.hpp"
#include "image_obj.hpp"
#include "logger_utils.hpp"
#include "options.hpp"
#include "pdf_pod_structs.hpp"

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
                     const std::shared_ptr<spdlog::logger>& log);

/**
 * @brief Check the output directory
 *
 * @param output_dir
 * @param log logger
 * @return true - existing,writable
 * @return false
 */
bool CheckOutputDir(const std::string& output_dir,
                    const std::shared_ptr<spdlog::logger>& log);

/**
 * @brief Check if the given certificate exists in CSP
 *
 * @param cert serial number
 * @return true if exists
 * @return false
 */
bool CheckCertSerial(const std::string& cert,
                     const std::shared_ptr<csp::Csp>& csp,
                     const std::shared_ptr<spdlog::logger>& log);

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
  const std::shared_ptr<spdlog::logger>& log);

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
  const std::shared_ptr<spdlog::logger>& log,
  pdf::ImageObj* p_cached_img = nullptr);

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
  pdf::CSignParams params, const std::shared_ptr<spdlog::logger>& logger);

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
                          const std::shared_ptr<spdlog::logger>& log);

}  // namespace pdfcsp::cli