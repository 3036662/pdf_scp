/* File: logger_utils.cpp  
Copyright (C) Basealt LLC,  2024
Author: Oleg Proskurin, <proskurinov@basealt.ru>

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with this program; if not, write to the Free Software Foundation,
Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/


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
