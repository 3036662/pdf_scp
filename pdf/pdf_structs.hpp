/* File: pdf_structs.hpp
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

#include <SignatureImageCWrapper/pod_structs.hpp>
#include <cstdint>
#include <optional>
#include <qpdf/QPDFObjectHandle.hh>
#include <utility>

#include "pdf_defs.hpp"

namespace pdfcsp::pdf {

struct ObjRawId {
  int id = 0;
  int gen = 0;

  [[nodiscard]] std::string ToString() const noexcept {
    std::ostringstream builder;
    builder << id << " " << gen << " obj";
    return builder.str();
  }

  [[nodiscard]] std::string ToStringRef() const noexcept {
    std::ostringstream builder;
    builder << id << " " << gen << " R";
    return builder.str();
  }

  ObjRawId &operator++() noexcept {
    ++id;
    return *this;
  }

  static ObjRawId CopyIdFromExisting(const QPDFObjectHandle &other) noexcept;
};

struct XYReal {
  double x = 0;
  double y = 0;

  [[nodiscard]] std::string ToString() const;
};

struct BBox {
  XYReal left_bottom;
  XYReal right_top;

  [[nodiscard]] std::string ToString() const;
};

/*
Transformation matrix in pdf
[a b 0]
[c d 0]
[e f 1]
*/

struct Matrix {
  double a = 1;
  double b = 0;
  double c = 0;
  double d = 1;
  double e = 0;
  double f = 0;

  [[nodiscard]] std::string toString() const;
};

struct XRefEntry {
  ObjRawId id;
  size_t offset = 0;
  uint32_t gen = 0;

  [[nodiscard]] std::string ToString() const;
};

struct ImageParamWrapper {
  std::string font_family;
  std::string title;
  std::string cert_prefix;
  std::string cert_text;
  std::string subj_prefix;
  std::string subj_text;
  std::string cert_time_validity;
  std::optional<BytesVector> img_raw;
  signiamge::c_wrapper::Params img_params = {};
};

}  // namespace pdfcsp::pdf