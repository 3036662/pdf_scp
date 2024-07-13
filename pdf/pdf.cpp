#include "pdf.hpp"
#include <filesystem>
#include <memory>
#include <qpdf/QPDF.hh>
#include <qpdf/QPDFObjectHandle.hh>
#include <stdexcept>
#include <string>

#include "common_defs.hpp"

namespace pdfcsp::pdf {

Pdf::Pdf() : qpdf_(std::make_unique<QPDF>()) {}

Pdf::Pdf(const std::string &path) : qpdf_(std::make_unique<QPDF>()) {
  Open(path);
}

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
  qpdf_->processFile(path.c_str());
}

bool Pdf::FindSignature() noexcept {
  ObjHandler obj_root = std::make_unique<QPDFObjectHandle>(qpdf_->getRoot());
  if (obj_root->isNull()) {
    return false;
  } else {
    root_ = std::move(obj_root);
  }
  std::string tag_acro(kTagAcroForm);
  if (!root_->hasKey(tag_acro)) {
    return false;
  } else {
    acroform_ = std::make_unique<QPDFObjectHandle>(root_->getKey(tag_acro));
    if (acroform_->isNull()) {
      return false;
    }
  }
  if (!acroform_->isDictionary()) {
    Log("No DICT in AcroForm\n");
    return false;
  }
  std::string tag_fields(kTagFields);
  if (!acroform_->hasKey(tag_fields)) {
    Log("No fields in the AcroForm\n");
    return false;
  }
  auto acro_fields = acroform_->getKey(tag_fields);
  if (!acro_fields.isArray()) {
    Log("Acro /Fields is not an array\n");
    return false;
  }
  return true;
}

// ---------------------------------------------------
// private

void Pdf::Log(const char *msg) const noexcept {
  if (std_err_flag_) {
    std::cerr << "[Pdf]" << msg << "\n";
  }
}

inline void Pdf::Log(const std::string &msg) const noexcept {
  Log(msg.c_str());
}

} // namespace pdfcsp::pdf