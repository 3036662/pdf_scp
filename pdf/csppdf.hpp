#pragma once
#include <SignatureImageCWrapper/pod_structs.hpp>
#include <memory>

#include "pdf_pod_structs.hpp"
#include "pdf_structs.hpp"
#include "pdf_update_object_kit.hpp"

#include <string>
#include <vector>

namespace pdfcsp::pdf {

struct SigInstance {
  PtrPdfObj signature;
  RangesVector bytes_ranges;
};

// for debug
void DebugPrintDict(QPDFObjectHandle &obj);

class Pdf {
public:
  using SharedImgParams = std::shared_ptr<ImageParamWrapper>;

  /**
   * @brief Construct a new Pdf object
   * @throws propagated exceptions
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

  /**
   * @brief check is there /Acroform in document calalog
   * @return shared pointer to acroform
   */
  [[nodiscard]] PtrPdfObjShared GetAcroform() const noexcept;

  [[nodiscard]] PtrPdfObjShared GetPage(int page_index) const noexcept;

  [[nodiscard]] PtrPdfObjShared GetRoot() const noexcept;

  [[nodiscard]] PtrPdfObjShared GetTrailer() const noexcept;

  /**
   * @brief Create a kit of object for pdf incremental update
   * @return PrepareEmptySigResult
   * @throws std::runtime_error
   */
  PrepareEmptySigResult CreateObjectKit(const CSignParams &params);

  static StampResizeFactor CalcImgResizeFactor(const CSignParams &params);

private:
  /**
   * @brief Get the Signature Value object
   * @return PtrPdfObj
   */
  PtrPdfObj GetSignatureV(QPDFObjectHandle &field) const noexcept;

  void Log(const char *msg) const noexcept;
  inline void Log(const std::string &msg) const noexcept;

  void CreareImageObj(const CSignParams &params);
  void CreateFormXobj(const CSignParams &params);
  void CreateSignAnnot(const CSignParams &params);
  void CreateAcroForm(const CSignParams &params);
  void CreateUpdatedPage(const CSignParams &params);
  void CreateUpdateRoot(const CSignParams &params);
  void CreateEmptySigVal();
  void CreateXRef(const CSignParams &params);
  void WriteUpdatedFile(const CSignParams &params) const;

  /* This function are called from CreateXRef
   * We need to create simple table if previous table is simple,
   * create a cross-reference stream if previous table is cross-ref. stream
   */

  /**
   * @brief Create a simple trailer and xref table
   * @param[in,out] old_trailer_fields - previous trailer fields string->string
   * @param[in] prev_x_ref_offset - offset in bytes of previous x_ref (string)
   * @param[in,out] result_file_buf  - resulting signed file buffer
   */
  void CreateSimpleXref(std::map<std::string, std::string> &old_trailer_fields,
                        const std::string &prev_x_ref_offset,
                        std::vector<unsigned char> &result_file_buf);

  /**
   * @brief Create a Cross Ref Stream object
   * @details ISO3200 [7.5.8] Cross-Reference Streams
   * @param old_trailer_fields
   * @param prev_x_ref_offset
   * @param result_file_buf
   * @throws runtime_error
   */
  void
  CreateCrossRefStream(std::map<std::string, std::string> &old_trailer_fields,
                       const std::string &prev_x_ref_offset,
                       std::vector<unsigned char> &result_file_buf);

  static SharedImgParams CreateImgParams(const CSignParams &params);

  std::unique_ptr<QPDF> qpdf_;
  // default on Construct
  std::string src_file_path_;
  PtrPdfObj root_;
  PtrPdfObj acroform_;
  std::vector<SigInstance> signatures_;
  bool std_err_flag_ = true;
  std::string sig_raw_;
  std::shared_ptr<PdfUpdateObjectKit> update_kit_;
};

} // namespace  pdfcsp::pdf