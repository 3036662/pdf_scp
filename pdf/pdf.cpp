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
#include <tuple>
#include <utility>
#include <vector>

#include "annotation.hpp"
#include "common_defs.hpp"
#include "cross_ref_stream.hpp"
#include "csppdf.hpp"
#include "image_obj.hpp"
#include "logger_utils.hpp"
#include "pdf_defs.hpp"
#include "pdf_pod_structs.hpp"
#include "pdf_structs.hpp"
#include "pdf_utils.hpp"

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
    // mask
    if (params.image_generator_with_masks) {
      std::cerr << "generator with mask\n";
      const auto &imj_mask = update_kit_->img_mask_obj;
      if (params.cached_img_mask == nullptr && imj_mask.has_value()) {
        update_kit_->stage1_res.cached_mask =
          std::make_shared<ImageObj>(imj_mask.value());
      }
    }
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
  update_kit_->stage1_res.file_name =
    WriteUpdatedFile(params.temp_dir_path, params.file_to_sign_path,
                     update_kit_->updated_file_data);
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

StampResizeFactor Pdf::CalcImgResizeFactor(const CSignParams &params) {
  auto img_params_wrapper = CreateImgParams(params);
  const signiamge::c_wrapper::Params &img_params =
    img_params_wrapper->img_params;
  signiamge::c_wrapper::Result *ig_res = image_generator_(img_params);
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
  image_generator_free_(ig_res);
  return res;
}

Pdf::ImageGeneratorResult Pdf::CallImageGenerator(
  const Pdf::SharedImgParams &img_params_wrapper,
  const std::shared_ptr<spdlog::logger> &logger) {
  const std::string func_name = "[Pdf::CallImageGenerator] ";
  auto start = std::chrono::steady_clock::now();
  const signiamge::c_wrapper::Params &img_params =
    img_params_wrapper->img_params;
  ImageGeneratorResult ig_res(image_generator_(img_params),
                              image_generator_free_);
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
  return ig_res;
}

void Pdf::CreareImageObj(const CSignParams &params) {
  const std::string func_name = "[CreareImageObj] ";
  if (!update_kit_) {
    throw std::runtime_error(func_name + "update_kit =nullptr");
  }
  auto logger = logger::InitLog();
  // no cached image - create new
  if (params.cached_img == nullptr) {
    auto img_params_wrapper = CreateImgParams(params);
    ImageGeneratorResult ig_res =
      CallImageGenerator(img_params_wrapper, logger);
    update_kit_->image_obj.width = ig_res->resolution.width;
    update_kit_->image_obj.height = ig_res->resolution.height;
    // maybe another size returned, calculate resize_factor
    update_kit_->image_obj.resize_factor_x =
      CalcResizeFactor(img_params_wrapper->img_params.signature_size.width,
                       ig_res->resolution.width);
    update_kit_->image_obj.resize_factor_y =
      CalcResizeFactor(img_params_wrapper->img_params.signature_size.height,
                       ig_res->resolution.height);
    update_kit_->image_obj.bits_per_component = 8;
    update_kit_->image_obj.data.reserve(ig_res->stamp_img_data_size);
    std::copy(ig_res->stamp_img_data,
              ig_res->stamp_img_data + ig_res->stamp_img_data_size,
              std::back_inserter(update_kit_->image_obj.data));
    // mask
    if (params.image_generator_with_masks &&
        ig_res->stamp_mask_data != nullptr &&
        ig_res->stamp_mask_data_size != 0) {
      // copy sizes from the original image
      auto mask_obj = CloneExceptData(update_kit_->image_obj);
      mask_obj.mask_id_ = std::nullopt;  // erase mask
      mask_obj.colorspace = kDeviceGray;
      std::copy(ig_res->stamp_mask_data,
                ig_res->stamp_mask_data + ig_res->stamp_mask_data_size,
                std::back_inserter(mask_obj.data));

      update_kit_->img_mask_obj.emplace(std::move(mask_obj));
    }

  }
  // copy from the cached image
  else {
    logger->debug("Using the cached image");
    // assign an ID
    update_kit_->image_obj = *params.cached_img;
    if (params.cached_img_mask != nullptr) {
      update_kit_->img_mask_obj = *params.cached_img_mask;
    }
  }
  // assign an ID
  auto &imj_mask_obj = update_kit_->img_mask_obj;
  if (imj_mask_obj.has_value()) {
    imj_mask_obj->id = ++update_kit_->last_assigned_id;
    update_kit_->image_obj.mask_id_ = imj_mask_obj->id;
  }
  update_kit_->image_obj.id = ++update_kit_->last_assigned_id;
}

void Pdf::CreateEmptySigVal() {
  SigVal &sig_val = update_kit_->sig_val;
  sig_val.id = ++update_kit_->last_assigned_id;
  sig_val.contents_raw.resize(64000, 0x00);
  sig_val.CalcOffsets();
}

void Pdf::CreateSignAnnot(const CSignParams &params) {
  Annotation &sig_field = update_kit_->sig_field;
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
  update_kit_->updated_page = CreatePageUpdateWithAnnots(
    update_kit_->p_page_original, {update_kit_->sig_field.id});
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
  // find the previous xref
  auto prev_x_ref = FindXrefOffset(*file_buff);
  if (!prev_x_ref) {
    throw std::runtime_error("Can't find pdf xref");
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
  // image_mask
  auto &mask_obj = update_kit_->img_mask_obj;
  if (mask_obj.has_value()) {
    ref_entries.emplace_back(XRefEntry{mask_obj->id, file_buff->size(), 0});
    auto raw_img_obj = mask_obj->ToRawData();
    std::copy(raw_img_obj.cbegin(), raw_img_obj.cend(),
              std::back_inserter(*file_buff));
  }
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
  // Make a decision: what type of cross-reference should be used

  if (trailer_orig->hasKey(kTagType) &&
      trailer_orig->getKey(kTagType).getName() == kTagXref) {
    CreateCrossRefStream(map_unparsed, prev_x_ref.value(), file_buff.value(),
                         update_kit_->last_assigned_id,
                         update_kit_->ref_entries);
  } else {
    CreateSimpleXref(map_unparsed, prev_x_ref.value(), file_buff.value(),
                     update_kit_->last_assigned_id, update_kit_->ref_entries);
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

CEmbedAnnotResult Pdf::EmbedAnnots(const std::vector<CAnnotParams> &params,
                                   const std::string &temp_dir_path) {
  CEmbedAnnotResult res;
  annots_kit_ = std::make_shared<PdfAnnotsObjectKit>();
  annots_kit_->original_last_id = GetLastObjID();
  annots_kit_->last_assigned_id = annots_kit_->original_last_id;
  std::for_each(params.cbegin(), params.cend(),
                [this](const CAnnotParams &params) {
                  CreateOneAnnot(params, AnnotationType::kStamp);
                  if (params.link != nullptr) {
                    CreateOneAnnot(params, AnnotationType::kLink);
                  }
                });
  // create a vector of updated pages (annots_kit_->pages_updated)
  UpdatePagesWithAnnots();
  // create new xref
  auto file_buff = FileToVector(src_file_path_);
  if (!file_buff || file_buff->empty()) {
    throw std::runtime_error("Error reading source pdf file");
  }
  // find the previous xref
  auto prev_x_ref = FindXrefOffset(*file_buff);
  if (!prev_x_ref) {
    throw std::runtime_error("Can't find pdf xref");
  }
  file_buff->push_back('\n');
  std::vector<XRefEntry> xref_entries;
  // push the updated pages to xref_entries
  std::for_each(
    annots_kit_->pages_updated.cbegin(), annots_kit_->pages_updated.cend(),
    [&xref_entries,
     &file_buff](const std::pair<ObjRawId, std::string> &page_pair) {
      // push page to XRefEntry vector
      xref_entries.emplace_back(
        XRefEntry{page_pair.first, file_buff->size(), 0});
      // copy the raw page data to the file_buffer
      file_buff->reserve(file_buff->size() + page_pair.second.size());
      std::copy(page_pair.second.cbegin(), page_pair.second.cend(),
                std::back_inserter(*file_buff));
    });
  // push the new annotations data to the file buffer
  std::for_each(annots_kit_->annots.cbegin(), annots_kit_->annots.cend(),
                [&xref_entries, &file_buff](const SingleAnnot &ann) {
                  PushOneAnnotationToXRefAndBuffer(ann, xref_entries,
                                                   file_buff.value());
                });
  // create new trailer
  auto trailer_orig = GetTrailer();
  if (!trailer_orig || !trailer_orig->isDictionary()) {
    throw std::runtime_error("Can't find document trailer");
  }
  auto map_unparsed = DictToUnparsedMap(*trailer_orig);
  // Make a decision: what type of cross-reference should be used
  if (trailer_orig->hasKey(kTagType) &&
      trailer_orig->getKey(kTagType).getName() == kTagXref) {
    CreateCrossRefStream(map_unparsed, prev_x_ref.value(), file_buff.value(),
                         annots_kit_->last_assigned_id, xref_entries);
  } else {
    CreateSimpleXref(map_unparsed, prev_x_ref.value(), file_buff.value(),
                     annots_kit_->last_assigned_id, xref_entries);
  }
  res.storage = new EmbedAnnotResultStorage;  // NOLINT
  res.storage->tmp_file_path =
    WriteUpdatedFile(temp_dir_path, src_file_path_, *file_buff);
  res.tmp_file_path = res.storage->tmp_file_path.c_str();
  res.status = true;
  return res;
}

///@brief update pages with annots references
void Pdf::UpdatePagesWithAnnots() {
  if (!annots_kit_ || annots_kit_->annots.empty()) {
    return;
  }
  const std::vector<SingleAnnot> &annots = annots_kit_->annots;
  // create the pages_for_update map
  // "page id" -> vector of ids to be added to /Annots
  std::for_each(annots.cbegin(), annots.cend(), [this](const SingleAnnot &val) {
    if (annots_kit_->pages_for_update.count(val.annot.parent) > 0) {
      annots_kit_->pages_for_update.at(val.annot.parent)
        .push_back(val.annot.id);
    } else {
      annots_kit_->pages_for_update[val.annot.parent] =
        std::vector<ObjRawId>{val.annot.id};
    }
  });
  // for each page, create a vector <page_id,unparsed raw page string>
  std::for_each(
    annots_kit_->pages_for_update.cbegin(),
    annots_kit_->pages_for_update.cend(),
    [this](
      const std::pair<ObjRawId, const std::vector<ObjRawId>> &page_for_update) {
      const ObjRawId &page_id = page_for_update.first;
      auto page = std::make_shared<QPDFObjectHandle>(
        qpdf_->getObjectByID(page_id.id, page_id.gen));
      if (!page->isPageObject()) {
        throw std::runtime_error(
          "[Pdf::UpdatePagesWithAnnots] find page object by id failed");
      }
      annots_kit_->pages_updated.emplace_back(
        page_id, CreatePageUpdateWithAnnots(page, page_for_update.second));
    });
}

/**
 * @brief Create one annotation object and push it to the annots_kit_ field.
 * @param params @see CAnnotParams
 */
void Pdf::CreateOneAnnot(const CAnnotParams &params,
                         AnnotationType annot_type) {
  SingleAnnot tmp;
  const PtrPdfObjShared p_page_original = GetPage(params.page_index);
  const auto origial_page_rect = VisiblePageSize(p_page_original);
  if (!p_page_original) {
    throw std::runtime_error("[ Pdf::CreateOneAnnot] page not found ");
  };
  if (params.stamp_width == 0 || params.stamp_height == 0 ||
      params.img == nullptr || params.img_size == 0 ||
      params.resolution_x == 0 || params.resolution_y == 0) {
    throw std::invalid_argument("[Pdf::CreateOneAnnot] invalid image params");
  }
  std::optional<ObjRawId> form_id;
  std::optional<BBox> form_bbox;
  XYReal right_top;
  right_top.x = origial_page_rect->right_top.x * params.stamp_width /
                (params.page_width != 0 ? params.page_width : 1);
  right_top.y = origial_page_rect->right_top.y * params.stamp_height /
                (params.page_height != 0 ? params.page_height : 1);
  if (annot_type == AnnotationType::kStamp) {
    // Image
    tmp.img.emplace();
    ImageObj &img = tmp.img.value();
    img.id = ++annots_kit_->last_assigned_id;
    img.width = params.resolution_x;
    img.height = params.resolution_y;
    std::copy(params.img, params.img + params.img_size,
              std::back_inserter(img.data));
    // mask
    if (params.img_mask != nullptr && params.img_mask_size != 0) {
      auto &mask = tmp.img_mask;
      mask = CloneExceptData(img);
      mask->mask_id_ = std::nullopt;  // erase mask
      mask->id = ++annots_kit_->last_assigned_id;
      mask->colorspace = kDeviceGray;
      std::copy(params.img_mask, params.img_mask + params.img_mask_size,
                std::back_inserter(mask->data));
      // connect with the image
      img.mask_id_ = mask->id;
    }
    // Form
    tmp.form.emplace();
    FormXObject &form = tmp.form.value();
    form.id = ++annots_kit_->last_assigned_id;
    form_id = form.id;
    if (!origial_page_rect.has_value()) {
      throw std::runtime_error(kErrPageSize);
    }
    //   calculate the size
    form.bbox.right_top.x = right_top.x;
    form.bbox.right_top.y = right_top.y;
    form_bbox = form.bbox;
    form.resources_img_ref = img.id;
  }
  // annotation
  Annotation &annot = tmp.annot;
  annot.id = ++annots_kit_->last_assigned_id;
  annot.subtype =
    (params.link == nullptr || annot_type != AnnotationType::kLink) ? kTagStamp
                                                                    : kTagLink;
  if (params.link != nullptr && annot_type == AnnotationType::kLink) {
    annot.link = params.link;
  }
  annot.border = "[0 0 0]";
  annot.parent =
    ObjRawId{p_page_original->getObjectID(), p_page_original->getGeneration()};
  annot.appearance_ref = form_id;
  const double x_pos_relative =
    params.stamp_x / (params.page_width > 1 ? params.page_width : 1);
  const double page_width = origial_page_rect->right_top.x;
  annot.rect.left_bottom.x = page_width * x_pos_relative;
  const double y_pos_relative =
    (params.stamp_y + params.stamp_height) /
    (params.page_height > 1 ? params.page_height : 1);
  const double page_height = origial_page_rect->right_top.y;
  annot.rect.left_bottom.y =
    page_height * (1 - y_pos_relative);  // reverse y axis
  annot.rect.right_top.x = annot.rect.left_bottom.x + right_top.x;
  annot.rect.right_top.y = annot.rect.left_bottom.y + right_top.y;
  if (annot_type == AnnotationType::kStamp) {
    annot.flags = 0b1011000100;
  }

  auto crop_box_offset = CropBoxOffsetsXY(p_page_original);
  if (crop_box_offset.has_value()) {
    annot.rect.left_bottom.x += crop_box_offset->x;
    annot.rect.right_top.x += crop_box_offset->x;
    annot.rect.left_bottom.y += crop_box_offset->y;
    annot.rect.right_top.y += crop_box_offset->y;
  }
  // move the current annotation to the kit
  annots_kit_->annots.emplace_back(std::move(tmp));
}

}  // namespace pdfcsp::pdf
