/* File: csppdf.hpp
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

#pragma once
#include <spdlog/logger.h>

#include <SignatureImageCWrapper/c_wrapper.hpp>
#include <SignatureImageCWrapper/pod_structs.hpp>
#include <cstddef>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "pdf_annots_object_kit.hpp"
#include "pdf_pod_structs.hpp"
#include "pdf_structs.hpp"
#include "pdf_update_object_kit.hpp"

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
  using ImageGeneratorResult =
    std::unique_ptr<signiamge::c_wrapper::Result,
                    std::function<void(signiamge::c_wrapper::Result *)>>;

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
  [[nodiscard]] RangesVector getSigByteRanges(
    unsigned int sig_index) const noexcept;

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

  [[nodiscard]] size_t GetPagesCount() const noexcept {
    return qpdf_->getAllPages().size();
  };

  /**
   * @brief Create a kit of object for pdf incremental update
   * @return PrepareEmptySigResult
   * @throws std::runtime_error
   */
  PrepareEmptySigResult CreateObjectKit(const CSignParams &params);

  StampResizeFactor CalcImgResizeFactor(const CSignParams &params);

  CEmbedAnnotResult EmbedAnnots(const std::vector<CAnnotParams> &params,
                                const std::string &temp_dir_path);
  /**
   * @brief Set(Mock) the Image Generator functions
   * @param func default = signiamge::c_wrapper::getResult
   * @param free_func default = signiamge::c_wrapper::freeResult
   */
  void SetImageGenerator(
    std::function<signiamge::c_wrapper::Result *(signiamge::c_wrapper::Params)>
      func,
    std::function<void(signiamge::c_wrapper::Result *)> free_func) {
    image_generator_ = std::move(func);
    image_generator_free_ = std::move(free_func);
  }

  ImageGeneratorResult CallImageGenerator(
    const Pdf::SharedImgParams &img_params_wrapper,
    const std::shared_ptr<spdlog::logger> &logger);

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

  /**
   * @brief Create one annotation object and push it to the annots_kit_ field.
   * @param params @see CAnnotParams
   */
  void CreateOneAnnot(const CAnnotParams &params, AnnotationType annot_type);

  ///@brief update pages with annots references
  void UpdatePagesWithAnnots();

  std::unique_ptr<QPDF> qpdf_;
  // default on Construct
  std::string src_file_path_;
  PtrPdfObj root_;
  PtrPdfObj acroform_;
  std::vector<SigInstance> signatures_;
  bool std_err_flag_ = true;
  std::string sig_raw_;
  std::shared_ptr<PdfUpdateObjectKit> update_kit_;
  std::shared_ptr<PdfAnnotsObjectKit> annots_kit_;

  std::function<signiamge::c_wrapper::Result *(signiamge::c_wrapper::Params)>
    image_generator_ = signiamge::c_wrapper::getResult;
  std::function<void(signiamge::c_wrapper::Result *)> image_generator_free_ =
    signiamge::c_wrapper::FreeResult;
};

}  // namespace  pdfcsp::pdf