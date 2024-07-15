#pragma once

#include <memory>
#define POINTERHOLDER_TRANSITION 3
#include <qpdf/QPDF.hh>
#include <qpdf/QPDFAcroFormDocumentHelper.hh>
#include <qpdf/QPDFAnnotationObjectHelper.hh>
#include <qpdf/QPDFObjectHandle.hh>
#include <qpdf/QPDFPageObjectHelper.hh>
#include <qpdf/QUtil.hh>
#include <string>
#include <vector>

namespace pdfcsp::pdf {

using RangesVector = std::vector<std::pair<long long, long long>>;
using PtrPdfObj = std::unique_ptr<QPDFObjectHandle>;
using BytesVector = std::vector<unsigned char>;

class Pdf {
public:
  /**
   * @brief Construct a new Pdf object
   * @throws propagateed exceptions
   */
  Pdf();

  /**
   * @brief Construct a new Pdf object
   *
   * @param path to file
   * @throws if cant open file
   */
  Pdf(const std::string &path);

  Pdf(const Pdf &) = delete;
  Pdf(Pdf &&) = delete;
  Pdf &operator=(const Pdf &) = delete;
  Pdf &operator=(Pdf &&) = delete;

  /**
   * @brief Open a pdf file
   * @param path string path to file
   * @throws std::logical_error if file doesn't exist or can't open
   */
  void Open(const std::string &path);

  /**
   * @brief true if some Signatures found
   *
   * @return true
   * @return false
   */
  [[nodiscard]] bool FindSignature() noexcept;

  /**
   * @brief Get the Raw Signature data
   * @return std::vector<unsigned char>
   */
  BytesVector getRawSignature() noexcept;

  /**
   * @brief Get the Raw Data object excluding the signature value
   * @return std::vector<unsigned char>
   */
  BytesVector getRawData() noexcept;

  /**
   * @brief Turn off/on logging to a stderr
   * @param val true/false
   */
  void EnableLogToStdErr(bool val) noexcept { std_err_flag_ = val; }

private:
  static constexpr const char *const kTagAcroForm = "/AcroForm";
  static constexpr const char *const kTagFields = "/Fields";
  static constexpr const char *const kTagType = "/Type";
  static constexpr const char *const kTagFilter = "/Filter";
  static constexpr const char *const kTagContents = "/Contents";
  static constexpr const char *const kTagByteRange = "/ByteRange";
  static constexpr const char *const kErrNoAcro = "/ByteRange";

  void Log(const char *msg) const noexcept;
  inline void Log(const std::string &msg) const noexcept;

  std::unique_ptr<QPDF> qpdf_;

  // default on Construct
  std::string src_file_path_;
  PtrPdfObj root_;
  PtrPdfObj acroform_;
  PtrPdfObj signature_;
  RangesVector byteranges_;
  bool std_err_flag_ = true;
  std::string sig_raw_;
};

} // namespace  pdfcsp::pdf