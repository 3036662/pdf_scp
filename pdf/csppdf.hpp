#pragma once
#include <cstdint>
#include <memory>
#define POINTERHOLDER_TRANSITION 3 // NOLINT (cppcoreguidelines-macro-usage)
#include "pdf_structs.hpp"
#include <qpdf/QPDF.hh>
#include <qpdf/QPDFAcroFormDocumentHelper.hh>
#include <qpdf/QPDFAnnotationObjectHelper.hh>
#include <qpdf/QPDFObjectHandle.hh>
#include <qpdf/QPDFPageObjectHelper.hh>
#include <qpdf/QUtil.hh>
#include <string>
#include <vector>

namespace pdfcsp::pdf {

using PtrPdfObj = std::unique_ptr<QPDFObjectHandle>;

struct SigInstance {
  PtrPdfObj signature;
  RangesVector bytes_ranges;
};

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
  explicit Pdf(const std::string &path);

  Pdf(const Pdf &) = delete;
  Pdf(Pdf &&) = delete;
  Pdf &operator=(const Pdf &) = delete;
  Pdf &operator=(Pdf &&) = delete;
  ~Pdf() = default;

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
  [[nodiscard]] bool FindSignatures() noexcept;

  /**
   * @brief Get the Raw Signature data
   * @return std::vector<unsigned char>
   */
  [[nodiscard]] BytesVector getRawSignature(unsigned int sig_index) noexcept;

  /**
   * @brief Get the byte ranges for the specified signature.
   * @param sig_index Signature index
   * @return RangesVector
   */
  [[nodiscard]] RangesVector
  getSigByteRanges(unsigned int sig_index) const noexcept;

  /**
   * @brief Get the Raw Data object excluding the signature value
   * @return std::vector<unsigned char>
   */
  [[nodiscard]] BytesVector getRawData(unsigned int sig_index) const noexcept;

  /**
   * @brief Turn off/on logging to a stderr
   * @param val true/false
   */
  void EnableLogToStdErr(bool val) noexcept { std_err_flag_ = val; }

  [[nodiscard]] uint GetSignaturesCount() const noexcept {
    return signatures_.size();
  };

  // for tests
  [[nodiscard]] const std::unique_ptr<QPDF> &getQPDF() const & noexcept {
    return qpdf_;
  }

  /**
   * @brief Get the Last Object ID
   * @return ObjRawId
   */
  [[nodiscard]] ObjRawId GetLastObjID() const noexcept;

private:
  /**
   * @brief Get the Signature Value object
   * @return PtrPdfObj
   */
  PtrPdfObj GetSignatureV(QPDFObjectHandle &field) const noexcept;

  void Log(const char *msg) const noexcept;
  inline void Log(const std::string &msg) const noexcept;

  std::unique_ptr<QPDF> qpdf_;

  // default on Construct
  std::string src_file_path_;
  PtrPdfObj root_;
  PtrPdfObj acroform_;
  // PtrPdfObj signature_;
  // RangesVector byteranges_;
  std::vector<SigInstance> signatures_;
  bool std_err_flag_ = true;
  std::string sig_raw_;
};

} // namespace  pdfcsp::pdf