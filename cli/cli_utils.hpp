#pragma once
#include <spdlog/spdlog.h>

#include <memory>

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

bool CheckOutputDir(const std::string& output_dir,
                    const std::shared_ptr<spdlog::logger>& log);

}  // namespace pdfcsp::cli