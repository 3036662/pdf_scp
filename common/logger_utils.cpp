#include "logger_utils.hpp"
#include "spdlog/sinks/stdout_color_sinks.h"
#include "spdlog/sinks/syslog_sink.h"
#include "spdlog/spdlog.h"
#include <iostream>
#include <spdlog/common.h>
#include <syslog.h>

namespace pdfcsp::logger {

std::shared_ptr<spdlog::logger> InitLog() noexcept {

  try {
    spdlog::set_level(spdlog::level::debug);
    if constexpr (LOG_TO_JOURNAL) {
      auto logger = spdlog::get("syslog");
      if (logger) {
        return logger;
      };
      return spdlog::syslog_logger_mt("syslog", LOG_TAG);
    } else {
      auto logger = spdlog::get("stderr");
      if (logger) {
        return logger;
      };
      return spdlog::stderr_color_mt("stderr");
    }

  } catch (const std::exception &ex) {
    std::cerr << ex.what();
    openlog("altpdfcsp", LOG_PID, LOG_USER);
    syslog(LOG_ERR, "Can't create init log"); // NOLINT
    return nullptr;
  }
}

} // namespace pdfcsp::logger
