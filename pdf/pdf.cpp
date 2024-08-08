#include "pdf.hpp"
#include <cstdint>
#include <exception>
#include <filesystem>
#include <iterator>
#include <memory>
#include <qpdf/QPDF.hh>
#include <qpdf/QPDFObjectHandle.hh>
#include <stdexcept>
#include <string>
#include <vector>

#include "common_defs.hpp"
#include "utils.hpp"

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
  src_file_path_ = path;
  qpdf_->processFile(path.c_str());
}

bool Pdf::FindSignatures() noexcept {
  // find root
  PtrPdfObj obj_root = std::make_unique<QPDFObjectHandle>(qpdf_->getRoot());
  if (obj_root->isNull()) {
    Log("Not root found");
    return false;
  }
  root_ = std::move(obj_root);
  // check if pdf has any Acroforms
  const std::string tag_acro(kTagAcroForm);
  if (!root_->hasKey(tag_acro)) {
    Log(kErrNoAcro);
    return false;
  }

  acroform_ = std::make_unique<QPDFObjectHandle>(root_->getKey(tag_acro));
  if (acroform_->isNull()) {
    Log(kErrNoAcro);
    return false;
  }

  if (!acroform_->isDictionary()) {
    Log("No DICT in AcroForm\n");
    return false;
  }
  const std::string tag_fields(kTagFields);
  if (!acroform_->hasKey(tag_fields)) {
    Log("No fields in the AcroForm\n");
    return false;
  }
  auto acro_fields = acroform_->getKey(tag_fields);
  if (!acro_fields.isArray()) {
    Log("Acro /Fields is not an array\n");
    return false;
  }
  for (int i = 0; i < acro_fields.getArrayNItems(); ++i) {
    QPDFObjectHandle field = acro_fields.getArrayItem(i);
    auto signature_ = GetSignatureV(field);
    if (!signature_) {
      continue;
    }
    auto byterange = signature_->getKey(kTagByteRange);
    if (byterange.isNull() || !byterange.isArray()) {
      Log("No byterange is found");
      return false;
    }
    const int num_items = byterange.getArrayNItems();
    if (num_items % 2 != 0) {
      Log("Error number of items in array is not odd");
      return false;
    }
    int64_t start = 0;
    [[maybe_unused]] int64_t end = 0;
    RangesVector byteranges;
    for (int i2 = 0; i2 < num_items; ++i2) {
      auto item = byterange.getArrayItem(i2);
      auto val = item.getIntValue();
      if (i2 % 2 == 0) {
        start = val;
      } else {
        end = val;
        byteranges.emplace_back(start, end);
      }
    }
    signatures_.emplace_back(
        SigInstance{std::move(signature_), std::move(byteranges)});
    // break;
  }
  return !signatures_.empty();
}

BytesVector Pdf::getRawSignature(unsigned int sig_index) noexcept {
  std::vector<unsigned char> res;
  if (signatures_.size() < sig_index + 1) {
    Log("No sig with such index");
    return res;
  }
  PtrPdfObj &signature = signatures_[sig_index].signature;
  if (!signature || signature->isNull()) {
    return res;
  }
  const std::string sig_content = signature->getKey(kTagContents).unparse();
  if (sig_content.empty()) {
    Log("Empty signature content");
    return res;
  }

  std::string decoded_sign_content;

  try {
    decoded_sign_content = QUtil::hex_decode(sig_content);
  } catch (const std::exception &ex) {
    Log(ex.what());
    return res;
  }
  std::copy(decoded_sign_content.cbegin(), decoded_sign_content.cend(),
            std::back_inserter(res));
  return res;
};

// get a Raw data from pdf (except signature) specified in byrerange_
BytesVector Pdf::getRawData(unsigned int sig_index) const noexcept {
  BytesVector res;
  if (signatures_.size() < sig_index + 1) {
    Log("No signature with such index");
    return res;
  }
  const RangesVector &byteranges = signatures_[sig_index].bytes_ranges;
  if (src_file_path_.empty()) {
    return res;
  }
  auto data = FileToVector(src_file_path_, byteranges);
  if (!data.has_value()) {
    return res;
  }
  res = std::move(data.value());
  return res;
};

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

pdfcsp::pdf::PtrPdfObj
Pdf::GetSignatureV(QPDFObjectHandle &field) const noexcept {
  if (field.isDictionary() && field.hasKey("/FT") &&
      field.getKey("/FT").isName() && field.getKey("/FT").getName() == "/Sig") {
    if (!field.hasKey("/V")) {
      Log("No value of signature\n");
      return nullptr;
    }
    PtrPdfObj signature_v =
        std::make_unique<QPDFObjectHandle>(field.getKey("/V"));
    if (!signature_v->isDictionary() || !signature_v->hasKey(kTagType) ||
        !signature_v->getKey(kTagType).isName() ||
        signature_v->getKey(kTagType).getName() != "/Sig") {
      Log("Invalid Signature\n");
      return nullptr;
    }
    if (!signature_v->hasKey(kTagFilter) ||
        !signature_v->getKey(kTagFilter).isName()) {
      Log("Invalid /Filter field in signature");
      return nullptr;
    }
    if (!signature_v->hasKey(kTagContents)) {
      Log("No signature content was found");
      return nullptr;
    }
    // get the signature byte range
    if (!signature_v->hasKey(kTagByteRange)) {
      Log("No byte range found");
      return nullptr;
    }
    return signature_v;
  }
  return nullptr;
}

} // namespace pdfcsp::pdf