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

class Pdf {
public:
  using ObjHandler = std::unique_ptr<QPDFObjectHandle>;

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
  std::vector<unsigned char> getRawSignature() noexcept;

  /**
   * @brief Get the Raw Data object excluding the signature value
   * @return std::vector<unsigned char>
   */
  std::vector<unsigned char> getRawData() noexcept;

  /**
   * @brief Turn off/on logging to a stderr
   * @param val true/false
   */
  void EnableLogToStdErr(bool val) noexcept { std_err_flag_ = val; }

private:
  static constexpr const char *const kTagAcroForm = "/Acroform";
  static constexpr const char *const kTagFields = "/Fields";

  void Log(const char *msg) const noexcept;
  inline void Log(const std::string &msg) const noexcept;

  std::unique_ptr<QPDF> qpdf_;

  // default on Construct
  std::unique_ptr<QPDFObjectHandle> root_;
  std::unique_ptr<QPDFObjectHandle> acroform_;
  std::unique_ptr<QPDFObjectHandle> signature_value_;
  bool std_err_flag_ = true;
};

} // namespace  pdfcsp::pdf