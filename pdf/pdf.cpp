#include "pdf.hpp"
#include <filesystem>
#include <stdexcept>

#include "common_defs.hpp"

namespace pdfcsp::pdf {

void Pdf::Open(const std::string &path) {
  namespace fs = std::filesystem;
  if (path.empty()) {
    throw std::logic_error("empty path to file");
  }
  if (!fs::exists(path)) {
    throw std::logic_error("file doesn't exist");
  }
  if (fs::file_size(path) > kMaxPdfFileSize) {
    throw std::logic_error("file is too big");
  }

  // not existing
  // cant open for reading
  //  not enough memory to read
}

} // namespace pdfcsp::pdf