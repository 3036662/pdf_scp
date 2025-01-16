/* File: pdf.cpp
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

#include <SignatureImageCWrapper/c_wrapper.hpp>
#include <SignatureImageCWrapper/pod_structs.hpp>
#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <exception>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <limits>
#include <memory>
#include <optional>
#include <qpdf/QPDF.hh>
#include <qpdf/QPDFObjectHandle.hh>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "common_defs.hpp"
#include "cross_ref_stream.hpp"
#include "csppdf.hpp"
#include "image_obj.hpp"
#include "logger_utils.hpp"
#include "pdf_defs.hpp"
#include "pdf_pod_structs.hpp"
#include "pdf_structs.hpp"
#include "pdf_utils.hpp"
#include "sig_field.hpp"

namespace pdfcsp::pdf {

using BytesVector = std::vector<unsigned char>;

void DebugPrintDict(QPDFObjectHandle &obj) {
  for (auto &key : obj.getDictAsMap()) {
    std::cout << key.first << " " << key.second.unparse() << "\n";
  }
}

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
}

/**
 * @brief Get the byte ranges for the specified signature.
 * @param sig_index Signature index
 * @return RangesVector
 */
[[nodiscard]] RangesVector Pdf::getSigByteRanges(
  unsigned int sig_index) const noexcept {
  if (signatures_.size() < sig_index + 1) {
    Log("No sig with such index");
    return {};
  }
  return signatures_.at(sig_index).bytes_ranges;
}

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

pdfcsp::pdf::PtrPdfObj Pdf::GetSignatureV(
  QPDFObjectHandle &field) const noexcept {
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

/**
 * @brief Get the Last Object ID
 * @return ObjRawId
 */
ObjRawId Pdf::GetLastObjID() const noexcept {
  if (!qpdf_) {
    return {};
  }
  ObjRawId res{};
  auto objects = qpdf_->getAllObjects();
  auto it_max = std::max_element(
    objects.cbegin(), objects.cend(),
    [](const QPDFObjectHandle &left, const QPDFObjectHandle &right) {
      return left.getObjectID() < right.getObjectID();
    });
  if (it_max != objects.cend()) {
    res.id = it_max->getObjectID();
    res.gen = it_max->getGeneration();
  }
  const size_t obj_count = qpdf_->getObjectCount();
  if (obj_count > std::numeric_limits<int>::max()) {
    Log("[LastObjID] object count > max int");
    return res;
  }
  const int count = static_cast<int>(obj_count);
  if (res.id < count) {
    res.id = count;
    res.gen = 0;
  }
  return res;
}

PtrPdfObjShared Pdf::GetAcroform() const noexcept {
  if (!qpdf_) {
    Log("[HasAcroForm] empty document");
    return nullptr;
  }
  // find root
  const PtrPdfObjShared obj_root =
    std::make_unique<QPDFObjectHandle>(qpdf_->getRoot());
  if (obj_root->isNull()) {
    return nullptr;
  }
  // check if pdf has any Acroforms
  if (obj_root->hasKey(kTagAcroForm)) {
    auto res =
      std::make_shared<QPDFObjectHandle>(obj_root->getKey(kTagAcroForm));
    if (res->isNull()) {
      return nullptr;
    }
    return res;
  }
  return nullptr;
}

PtrPdfObjShared Pdf::GetPage(int page_index) const noexcept {
  if (!qpdf_) {
    Log("[GetPage] empty document");
    return nullptr;
  }
  auto all_pages = qpdf_->getAllPages();
  if (all_pages.empty() || page_index < 0 ||
      static_cast<size_t>(page_index) > all_pages.size() - 1) {
    return nullptr;
  }
  auto res = std::make_shared<QPDFObjectHandle>(all_pages[page_index]);
  if (res->isNull() || !res->isPageObject()) {
    return nullptr;
  }
  return res;
}

PtrPdfObjShared Pdf::GetRoot() const noexcept {
  if (!qpdf_) {
    Log("[GetPage] empty document");
    return nullptr;
  }
  // find root
  PtrPdfObjShared obj_root =
    std::make_unique<QPDFObjectHandle>(qpdf_->getRoot());
  if (obj_root->isNull()) {
    return nullptr;
  }
  return obj_root;
}

PtrPdfObjShared Pdf::GetTrailer() const noexcept {
  if (!qpdf_) {
    Log("[GetPage] empty document");
    return nullptr;
  }
  PtrPdfObjShared obj_trailer =
    std::make_unique<QPDFObjectHandle>(qpdf_->getTrailer());
  if (obj_trailer->isNull()) {
    return nullptr;
  }
  return obj_trailer;
}

/**
 * @brief Create a kit of object for pdf incremental update
 * @return PrepareEmptySigResult
 * @throws std::runtime_error
 */
PrepareEmptySigResult Pdf::CreateObjectKit(const CSignParams &params) {
  // check the mandatory params
  if (params.file_to_sign_path == nullptr || params.cert_serial == nullptr ||
      params.config_path == nullptr || params.cert_subject == nullptr ||
      params.cert_time_validity == nullptr || params.cades_type == nullptr ||
      params.temp_dir_path == nullptr) {
    throw std::runtime_error(
      "[ Pdf::CreateObjectKit] invalid parameters,null pointers");
  }
  update_kit_ = std::make_shared<PdfUpdateObjectKit>();
  // save last id of original doc
  update_kit_->original_last_id = GetLastObjID();
  update_kit_->last_assigned_id = update_kit_->original_last_id;
  // find the targe page
  update_kit_->p_page_original = GetPage(params.page_index);
  if (!update_kit_->p_page_original) {
    throw std::runtime_error("Target page not found");
  }
  // tmp dir
  update_kit_->users_tmp_dir = params.temp_dir_path;
  // image
  CreareImageObj(params);
  // cache the image if not alreaty cached
  if (params.perform_cache_image && params.cached_img == nullptr) {
    update_kit_->stage1_res.cached_img =
      std::make_shared<ImageObj>(update_kit_->image_obj);
  }
  // xobj
  CreateFormXobj(params);
  // empty signature
  CreateEmptySigVal();
  // sig annot
  CreateSignAnnot(params);
  // create an AcroForm (or copy existing)
  CreateAcroForm(params);
  // update page
  CreateUpdatedPage(params);
  // root
  CreateUpdateRoot(params);
  // xref and trailer
  CreateXRef(params);
  // write updated
  WriteUpdatedFile(params);
  return update_kit_->stage1_res;
}

void Pdf::CreateFormXobj(const CSignParams &params) {
  FormXObject &form_x_object = update_kit_->form_x_object;
  form_x_object.id = ++update_kit_->last_assigned_id;
  update_kit_->origial_page_rect =
    VisiblePageSize(update_kit_->p_page_original);
  std::optional<BBox> &page_rect = update_kit_->origial_page_rect;
  if (!page_rect.has_value()) {
    throw std::runtime_error(kErrPageSize);
  }
  //   calculate the size
  const double stamp_width = page_rect->right_top.x * params.stamp_width /
                             (params.page_width != 0 ? params.page_width : 1);
  // stamp_width *= update_kit_->image_obj.resize_factor_x;
  const double stamp_height =
    page_rect->right_top.y * params.stamp_height /
    (params.page_height != 0 ? params.page_height : 1);
  // stamp_height *= update_kit_->image_obj.resize_factor_y;
  form_x_object.bbox.right_top.x = stamp_width;
  form_x_object.bbox.right_top.y = stamp_height;
  form_x_object.resources_img_ref = update_kit_->image_obj.id;
}

Pdf::SharedImgParams Pdf::CreateImgParams(const CSignParams &params) {
  const std::string func_name = "[Pdf::CreateImgParams] ";
  auto res = std::make_shared<ImageParamWrapper>();
  namespace ig = signiamge::c_wrapper;
  ig::Params &img_params = res->img_params;
  constexpr auto white = ig::RGBAColor{0xFF, 0xFF, 0xFF};
  // constexpr auto black = ig::RGBAColor{0x00, 0x00, 0x00};
  constexpr auto blue = ig::RGBAColor{50, 62, 168};
  img_params.right_margin = 0.01;
  img_params.bg_color = white;
  img_params.text_color = blue;
  img_params.border_color = blue;
  img_params.border_radius = {50, 50};
  if (params.stamp_height != 0 && params.stamp_width != 0) {
    img_params.signature_size = {
      kStampImgDefaultWidth,
      kStampImgDefaultWidth * (params.stamp_height / params.stamp_width)};
  } else {
    img_params.signature_size = {kStampImgDefaultWidth, kStampImgDefaultHeight};
  }
  img_params.title_font_size = kStampTitleFontSize;
  img_params.font_size = kStampFontSize;
  res->font_family = "Garuda";
  img_params.font_family = res->font_family.c_str();
  img_params.border_width = kStampBorderWidth;
  // img_params.debug_enabled = true;
  res->title = params.stamp_title == nullptr ? kStampTitle : params.stamp_title;
  img_params.title = res->title.c_str();
  res->cert_prefix = params.cert_serial_prefix == nullptr
                       ? kStampCertText
                       : params.cert_serial_prefix;
  res->cert_text = res->cert_prefix + params.cert_serial;
  img_params.cert_serial = res->cert_text.c_str();
  res->subj_prefix = params.cert_serial_prefix == nullptr
                       ? kStampSubjText
                       : params.cert_subject_prefix;
  res->subj_text = res->subj_prefix + params.cert_subject;

  img_params.subject = res->subj_text.c_str();
  res->cert_time_validity = params.cert_time_validity;
  img_params.time_validity = res->cert_time_validity.c_str();
  // logo
  if (params.logo_path != nullptr) {
    std::filesystem::path logo_path(params.logo_path);  // path from profile
    std::string path_in_config = params.config_path;
    path_in_config += '/';
    path_in_config += logo_path.filename();
    if (path_in_config != logo_path.string()) {
      logo_path = std::filesystem::path(path_in_config);
    }
    res->img_raw = FileToVector(logo_path.string());
    std::optional<BytesVector> &img_raw = res->img_raw;
    if (!img_raw.has_value() || img_raw->empty()) {
      throw std::runtime_error(func_name + "Can not read logo file " +
                               logo_path.string());
    }
    img_params.ptr_logo_data = img_raw->data();
    img_params.ptr_logo_size = img_raw->size();

  } else {
    img_params.ptr_logo_data = nullptr;
    img_params.ptr_logo_size = 0;
  }
  const auto logo_x_goal = img_params.signature_size.height / 2;
  img_params.logo_size_goal = {logo_x_goal, logo_x_goal};
  img_params.logo_preserve_ratio = true;
  img_params.logo_position = {20, 20};
  img_params.title_position = {logo_x_goal + 30, logo_x_goal / 3};
  img_params.cert_serial_position = {30, logo_x_goal + 30};
  img_params.subject_position = {30, img_params.cert_serial_position.y + 40};
  img_params.time_validity_position = {30, img_params.subject_position.y + 40};
  img_params.title_alignment = ig::TextAlignment::CenterGravity;
  img_params.content_alignment = ig::TextAlignment::CenterGravity;
  return res;
}

StampResizeFactor Pdf::CalcImgResizeFactor(const CSignParams &params) {
  namespace ig = signiamge::c_wrapper;
  auto img_params_wrapper = CreateImgParams(params);
  const signiamge::c_wrapper::Params &img_params =
    img_params_wrapper->img_params;
  ig::Result *ig_res = ig::getResult(img_params);
  if (ig_res == nullptr || ig_res->stamp_img_data == nullptr ||
      ig_res->stamp_img_data_size == 0 || ig_res->resolution.height == 0 ||
      ig_res->resolution.width == 0) {
    throw std::runtime_error(
      "[Pdf::CalcImgResizeFactor] generate stamp img failed");
  }
  StampResizeFactor res{
    CalcResizeFactor(img_params.signature_size.width, ig_res->resolution.width),
    CalcResizeFactor(img_params.signature_size.height,
                     ig_res->resolution.height)};
  auto logger = logger::InitLog();
  if (logger) {
    logger->debug("estimate resize factor: ask {}x{} result {}x{}",
                  img_params.signature_size.width,
                  img_params.signature_size.height, ig_res->resolution.width,
                  ig_res->resolution.height);
  }
  ig::FreeResult(ig_res);
  return res;
}

void Pdf::CreareImageObj(const CSignParams &params) {
  const std::string func_name = "[CreareImageObj] ";
  if (!update_kit_) {
    throw std::runtime_error(func_name + "update_kit =nullptr");
  }
  namespace ig = signiamge::c_wrapper;
  auto logger = logger::InitLog();
  // no cached image - create new
  if (params.cached_img == nullptr) {
    auto img_params_wrapper = CreateImgParams(params);
    auto start = std::chrono::steady_clock::now();
    const signiamge::c_wrapper::Params &img_params =
      img_params_wrapper->img_params;
    const std::unique_ptr<ig::Result, void (*)(ig::Result *)> ig_res(
      ig::getResult(img_params), [](ig::Result *ptr) { ig::FreeResult(ptr); });
    auto end = std::chrono::steady_clock::now();
    auto duration =
      std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    if (ig_res == nullptr || ig_res->stamp_img_data == nullptr ||
        ig_res->stamp_img_data_size == 0 || ig_res->resolution.height == 0 ||
        ig_res->resolution.width == 0) {
      throw std::runtime_error(func_name + "generate stamp img failed");
    }
    if (logger) {
      logger->debug("duration:{} ms", duration.count());
      logger->debug("estimate resize factor: ask {}x{} result {}x{}",
                    img_params.signature_size.width,
                    img_params.signature_size.height, ig_res->resolution.width,
                    ig_res->resolution.height);
    }

    update_kit_->image_obj.width = ig_res->resolution.width;
    update_kit_->image_obj.height = ig_res->resolution.height;
    // maybe another size returned, calculate resize_factor
    update_kit_->image_obj.resize_factor_x = CalcResizeFactor(
      img_params.signature_size.width, ig_res->resolution.width);
    update_kit_->image_obj.resize_factor_y = CalcResizeFactor(
      img_params.signature_size.height, ig_res->resolution.height);
    update_kit_->image_obj.bits_per_component = 8;
    update_kit_->image_obj.data.reserve(ig_res->stamp_img_data_size);
    std::copy(ig_res->stamp_img_data,
              ig_res->stamp_img_data + ig_res->stamp_img_data_size,
              std::back_inserter(update_kit_->image_obj.data));
  }
  // copy from the cached image
  else {
    logger->debug("Using the cached image");
    // assign an ID
    update_kit_->image_obj = *params.cached_img;
  }
  // assign an ID
  update_kit_->image_obj.id = ++update_kit_->last_assigned_id;
}

void Pdf::CreateEmptySigVal() {
  SigVal &sig_val = update_kit_->sig_val;
  sig_val.id = ++update_kit_->last_assigned_id;
  sig_val.contents_raw.resize(64000, 0x00);
  sig_val.CalcOffsets();
}

void Pdf::CreateSignAnnot(const CSignParams &params) {
  SigField &sig_field = update_kit_->sig_field;
  sig_field.id = ++update_kit_->last_assigned_id;
  sig_field.parent = ObjRawId{update_kit_->p_page_original->getObjectID(),
                              update_kit_->p_page_original->getGeneration()};
  sig_field.name =
    /*  params.cert_subject +*/ "signature" +
    std::to_string(
      std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()));
  sig_field.appearance_ref = update_kit_->form_x_object.id;
  sig_field.value = update_kit_->sig_val.id;
  if (!update_kit_->origial_page_rect) {
    update_kit_->origial_page_rect =
      VisiblePageSize(update_kit_->p_page_original);
  }
  const auto &page_rect = update_kit_->origial_page_rect;
  if (!page_rect.has_value()) {
    throw std::runtime_error(kErrPageSize);
  }
  const double x_pos_relative =
    params.stamp_x / (params.page_width > 1 ? params.page_width : 1);
  const double page_width = page_rect->right_top.x;
  sig_field.rect.left_bottom.x = page_width * x_pos_relative;
  const double y_pos_relative =
    (params.stamp_y + params.stamp_height) /
    (params.page_height > 1 ? params.page_height : 1);
  const double page_height = page_rect->right_top.y;
  sig_field.rect.left_bottom.y =
    page_height * (1 - y_pos_relative);  // reverse y axis
  sig_field.rect.right_top.x =
    sig_field.rect.left_bottom.x + update_kit_->form_x_object.bbox.right_top.x;
  sig_field.rect.right_top.y =
    sig_field.rect.left_bottom.y + update_kit_->form_x_object.bbox.right_top.y;
  auto crop_box_offset = CropBoxOffsetsXY(update_kit_->p_page_original);
  if (crop_box_offset.has_value()) {
    sig_field.rect.left_bottom.x += crop_box_offset->x;
    sig_field.rect.right_top.x += crop_box_offset->x;
    sig_field.rect.left_bottom.y += crop_box_offset->y;
    sig_field.rect.right_top.y += crop_box_offset->y;
  }
}

void Pdf::CreateAcroForm(const CSignParams & /*params*/) {
  AcroForm &acroform = update_kit_->acroform;
  auto original_acro_form = GetAcroform();
  if (original_acro_form && acroform.id.id == 0) {
    // copy original
    acroform = AcroForm::ShallowCopy(original_acro_form);
  } else {
    // create a new acroform id
    acroform.id = ++update_kit_->last_assigned_id;
  }
  acroform.fields.push_back(update_kit_->sig_field.id);
}

void Pdf::CreateUpdatedPage(const CSignParams & /*params*/) {
  std::vector<ObjRawId> annot_ids;
  // if original page already contains /Annots
  if (update_kit_->p_page_original->hasKey(kTagAnnots) &&
      update_kit_->p_page_original->getKey(kTagAnnots).isArray()) {
    // copy ids to annot_ids
    auto vec_annots =
      update_kit_->p_page_original->getKey(kTagAnnots).getArrayAsVector();
    std::for_each(vec_annots.cbegin(), vec_annots.cend(),
                  [&annot_ids](const QPDFObjectHandle &val) {
                    annot_ids.emplace_back(ObjRawId::CopyIdFromExisting(val));
                  });
  }
  auto unparsed_map = DictToUnparsedMap(*update_kit_->p_page_original);
  // push signature annotation field
  annot_ids.emplace_back(update_kit_->sig_field.id);
  std::string annots_unparsed_val;
  {
    std::ostringstream builder;
    builder << "[ ";  //<< sig_field.id.ToStringRef() << " ]";
    for (const auto &ann : annot_ids) {
      builder << ann.ToStringRef() << " ";
    }
    builder << "]";
    annots_unparsed_val = builder.str();
  }
  unparsed_map.insert_or_assign(kTagAnnots, annots_unparsed_val);
  {
    std::ostringstream builder;
    builder
      << ObjRawId::CopyIdFromExisting(*update_kit_->p_page_original).ToString()
      << " \n"
      << kDictStart << "\n";
    builder << UnparsedMapToString(unparsed_map);
    builder << kDictEnd << "\n" << kObjEnd;
    update_kit_->updated_page = builder.str();
  }
}

void Pdf::CreateUpdateRoot(const CSignParams & /*params*/) {
  auto root = GetRoot();
  update_kit_->p_root_original = root;
  if (!root || !root->isDictionary()) {
    throw std::runtime_error("Can't find the pdf root");
  }
  {
    std::ostringstream builder;
    builder << ObjRawId::CopyIdFromExisting(*root).ToString() << "\n"
            << kDictStart << "\n";
    auto root_unparsed_map = DictToUnparsedMap(*root);
    root_unparsed_map.insert_or_assign(kTagAcroForm,
                                       update_kit_->acroform.id.ToStringRef());
    builder << UnparsedMapToString(root_unparsed_map);
    builder << kDictEnd << "\n" << kObjEnd;
    update_kit_->root_updated = builder.str();
  }
}

void Pdf::CreateXRef(const CSignParams &params) {
  auto file_buff = FileToVector(params.file_to_sign_path);
  if (!file_buff || file_buff->empty()) {
    throw std::runtime_error("Error reading source pdf file");
  }
  file_buff->push_back('\n');
  std::vector<XRefEntry> &ref_entries = update_kit_->ref_entries;
  // page
  ref_entries.emplace_back(
    XRefEntry{ObjRawId::CopyIdFromExisting(*update_kit_->p_page_original),
              file_buff->size(), 0});
  std::copy(update_kit_->updated_page.cbegin(),
            update_kit_->updated_page.cend(), std::back_inserter(*file_buff));
  // root
  ref_entries.emplace_back(
    XRefEntry{ObjRawId::CopyIdFromExisting(*update_kit_->p_root_original),
              file_buff->size(), 0});
  std::copy(update_kit_->root_updated.cbegin(),
            update_kit_->root_updated.cend(), std::back_inserter(*file_buff));
  // image
  ref_entries.emplace_back(
    XRefEntry{update_kit_->image_obj.id, file_buff->size(), 0});
  {
    auto raw_img_obj = update_kit_->image_obj.ToRawData();
    std::copy(raw_img_obj.cbegin(), raw_img_obj.cend(),
              std::back_inserter(*file_buff));
  }
  // xobject
  ref_entries.emplace_back(
    XRefEntry{update_kit_->form_x_object.id, file_buff->size(), 0});
  {
    auto raw_img_obj = update_kit_->form_x_object.ToString();
    std::copy(raw_img_obj.cbegin(), raw_img_obj.cend(),
              std::back_inserter(*file_buff));
  }
  // sig value
  ref_entries.emplace_back(
    XRefEntry{update_kit_->sig_val.id, file_buff->size(), 0});
  // update offsets
  update_kit_->sig_val.hex_str_offset += file_buff->size();
  update_kit_->sig_val.byteranges_str_offset += file_buff->size();
  // update sig value byterange
  {
    auto raw_sig_obj = update_kit_->sig_val.ToString();
    std::copy(raw_sig_obj.cbegin(), raw_sig_obj.cend(),
              std::back_inserter(*file_buff));
  }
  // sig field
  ref_entries.emplace_back(
    XRefEntry{update_kit_->sig_field.id, file_buff->size(), 0});
  {
    auto raw_sig_field = update_kit_->sig_field.ToString();
    std::copy(raw_sig_field.cbegin(), raw_sig_field.cend(),
              std::back_inserter(*file_buff));
  }
  // the acroform
  ref_entries.emplace_back(
    XRefEntry{update_kit_->acroform.id, file_buff->size(), 0});
  {
    auto raw_acroform = update_kit_->acroform.ToString();
    std::copy(raw_acroform.cbegin(), raw_acroform.cend(),
              std::back_inserter(*file_buff));
  }
  // create new trailer
  auto trailer_orig = GetTrailer();
  if (!trailer_orig || !trailer_orig->isDictionary()) {
    throw std::runtime_error("Can't find document trailer");
  }
  auto map_unparsed = DictToUnparsedMap(*trailer_orig);
  auto prev_x_ref = FindXrefOffset(*file_buff);
  if (!prev_x_ref) {
    throw std::runtime_error("Can't find pdf xref");
  }
  // Make a decision: what type of cross-reference should be used
  if (trailer_orig->hasKey(kTagType) &&
      trailer_orig->getKey(kTagType).getName() == kTagXref) {
    CreateCrossRefStream(map_unparsed, prev_x_ref.value(), file_buff.value());
  } else {
    CreateSimpleXref(map_unparsed, prev_x_ref.value(), file_buff.value());
  }
  // finally patch byteranges
  {
    // region where we can patch
    unsigned char *p_byte_range_space =
      file_buff->data() + update_kit_->sig_val.byteranges_str_offset;
    std::string patch = "0 ";  // file beginning
    const size_t befor_hex = update_kit_->sig_val.hex_str_offset;
    patch += std::to_string(befor_hex);
    patch += ' ';
    const size_t offset_hex_end = update_kit_->sig_val.hex_str_offset +
                                  update_kit_->sig_val.hex_str_length +
                                  2;  // 2 is <>
    const size_t after_hex = file_buff->size() - offset_hex_end;
    patch += std::to_string(offset_hex_end);
    patch += " ";
    patch += std::to_string(after_hex);
    patch += " ]";
    const size_t patch_end_offs =
      update_kit_->sig_val.byteranges_str_offset + patch.size();
    // permorm patch
    if (patch_end_offs < file_buff->size() &&
        patch.size() < kSizeOfSpacesReservedForByteRanges) {
      std::copy(patch.begin(), patch.end(), p_byte_range_space);
    }
    update_kit_->stage1_res.byteranges.emplace_back(0, befor_hex);
    update_kit_->stage1_res.byteranges.emplace_back(offset_hex_end, after_hex);
    update_kit_->stage1_res.sig_offset = befor_hex + 1;
    update_kit_->stage1_res.sig_max_size = update_kit_->sig_val.hex_str_length;
  }
  update_kit_->updated_file_data = std::move(*file_buff);
}

/**
 * @brief Create a simple trailer and xref table
 *
 * @param[in,out] old_trailer_fields - previous trailer fields string->string
 * @param[in] prev_x_ref_offset - offset in bytes of previous x_ref (string)
 * @param[in,out] result_file_buf  - resulting signed file buffer
 */
void Pdf::CreateSimpleXref(
  std::map<std::string, std::string> &old_trailer_fields,
  const std::string &prev_x_ref_offset,
  std::vector<unsigned char> &result_file_buf) {
  const std::vector<XRefEntry> &ref_entries = update_kit_->ref_entries;
  old_trailer_fields.insert_or_assign(kTagPrev, prev_x_ref_offset);
  old_trailer_fields.insert_or_assign(
    kTagSize, std::to_string(update_kit_->last_assigned_id.id + 1));
  // fields to copy from old trailer
  {
    const std::set<std::string> trailer_possible_fields{
      kTagSize, kTagPrev, kTagRoot, kTagEncrypt, kTagInfo, kTagID};
    std::map<std::string, std::string> tmp_trailer;
    std::copy_if(old_trailer_fields.cbegin(), old_trailer_fields.cend(),
                 std::inserter(tmp_trailer, tmp_trailer.end()),
                 [&trailer_possible_fields](
                   const std::pair<std::string, std::string> &pair_val) {
                   return trailer_possible_fields.count(pair_val.first) > 0;
                 });
    std::swap(old_trailer_fields, tmp_trailer);
  }
  std::string raw_trailer = "trailer\n<<";
  raw_trailer += UnparsedMapToString(old_trailer_fields);
  raw_trailer += ">>\n";
  // complete the file
  // push xref_table to file
  const size_t xref_table_offset = result_file_buf.size();
  const std::string raw_xref_table = BuildXrefRawTable(ref_entries);
  std::copy(raw_xref_table.cbegin(), raw_xref_table.cend(),
            std::back_inserter(result_file_buf));
  std::copy(raw_trailer.cbegin(), raw_trailer.cend(),
            std::back_inserter(result_file_buf));
  // final info
  {
    std::string final_info = kStartXref;
    final_info += "\n";
    final_info += std::to_string(xref_table_offset);
    final_info += "\n";
    final_info += kEof;
    final_info += "\n";
    std::copy(final_info.cbegin(), final_info.cend(),
              std::back_inserter(result_file_buf));
  }
}

/**
 * @brief Create a Cross Ref Stream object
 * @details ISO3200 [7.5.8] Cross-Reference Streams
 * @param old_trailer_fields
 * @param prev_x_ref_offset
 * @param result_file_buf
 */
void Pdf::CreateCrossRefStream(
  std::map<std::string, std::string> &old_trailer_fields,
  const std::string &prev_x_ref_offset,
  std::vector<unsigned char> &result_file_buf) {
  CrossRefStream crs{};
  // first create xref object id
  crs.id = ++update_kit_->last_assigned_id;
  crs.size_val = crs.id.id + 1;  // highest object number + 1
  crs.entries = update_kit_->ref_entries;
  // sort entries and build sections
  crs.index_vec = BuildXRefStreamSections(crs.entries);
  // offset to previous xref
  crs.prev_val = prev_x_ref_offset;
  // copy fields from the previous trailer
  // root
  if (old_trailer_fields.count(kTagRoot) > 0) {
    crs.root_id = old_trailer_fields.at(kTagRoot);
  }
  // info
  if (old_trailer_fields.count(kTagInfo) > 0) {
    crs.info_id = old_trailer_fields.at(kTagInfo);
  }
  // ID
  if (old_trailer_fields.count(kTagID) > 0) {
    crs.id_val = old_trailer_fields.at(kTagID);
  }
  if (old_trailer_fields.count(kTagEncrypt) > 0) {
    crs.enctypt = old_trailer_fields.at(kTagEncrypt);
  }
  // set stream length
  if (crs.entries.size() > std::numeric_limits<int>::max()) {
    throw std::runtime_error("[Pdf::CreateCrossRefStream] can not cast to int");
  }
  crs.length = (crs.w_field_0_size + crs.w_field_1_size + crs.w_field_2_size) *
               static_cast<int>(crs.entries.size());

  // complete the file
  const size_t xref_table_offset = result_file_buf.size();
  {
    auto buf = crs.ToRawData();
    std::copy(buf.cbegin(), buf.cend(), std::back_inserter(result_file_buf));
  }

  // final info
  {
    std::string final_info = kStartXref;
    final_info += "\n";
    final_info += std::to_string(xref_table_offset);
    final_info += "\n";
    final_info += kEof;
    final_info += "\n";
    std::copy(final_info.cbegin(), final_info.cend(),
              std::back_inserter(result_file_buf));
  }
}

void Pdf::WriteUpdatedFile(const CSignParams &params) const {
  std::string output_file = params.temp_dir_path;
  output_file += "/altcsp_";
  output_file +=
    std::filesystem::path(params.file_to_sign_path).filename().string();
  output_file += ".sig_prepared";
  if (std::filesystem::exists(output_file)) {
    std::filesystem::remove(output_file);
  }
  {
    std::ofstream ofile(output_file, std::ios_base::binary);
    ofile.close();
    std::filesystem::permissions(
      output_file,
      std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
      std::filesystem::perm_options::replace);
  }

  std::ofstream ofile(output_file, std::ios_base::binary);
  if (!ofile.is_open()) {
    throw std::runtime_error("Can't create a file");
  }
  for (const auto symbol : update_kit_->updated_file_data) {
    ofile << symbol;
  }
  ofile.close();
  update_kit_->stage1_res.file_name = std::move(output_file);
}

}  // namespace pdfcsp::pdf
