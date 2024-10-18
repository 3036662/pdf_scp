#pragma once

#include "pdf_defs.hpp"
#include <qpdf/QPDFObjectHandle.hh>

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

}; // namespace pdfcsp::pdf