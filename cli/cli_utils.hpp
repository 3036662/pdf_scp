#pragma once
#include <spdlog/spdlog.h>

#include <memory>

#include "altcsp.hpp"
#include "cert_common_info.hpp"
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

pdfcsp::pdf::CSignPrepareResult* PerformSign(
  const std::string& src_file, const Options& options,
  const std::shared_ptr<csp::Csp>& csp,
  const std::shared_ptr<spdlog::logger>& log);

std::optional<csp::CertCommonInfo> GetCertInfo(
  const std::string& cert, const std::shared_ptr<csp::Csp>& csp,
  const std::shared_ptr<spdlog::logger>& log);

}  // namespace pdfcsp::cli