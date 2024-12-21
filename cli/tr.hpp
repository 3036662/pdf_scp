#pragma once

#include <libintl.h>

#include <string>
namespace pdfcsp::cli {

constexpr const char *tr(const char *val) { return gettext(val); }

constexpr const char *tr(const std::string &val) {
  return gettext(val.c_str());
}

inline std::string trs(const char *val) { return gettext(val); }

inline std::string trs(const std::string &val) { return gettext(val.c_str()); }

}  // namespace pdfcsp::cli