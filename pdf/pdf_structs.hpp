#pragma once

#include "pdf_defs.hpp"
#include <SignatureImageCWrapper/pod_structs.hpp>
#include <cstdint>
#include <optional>
#include <qpdf/QPDFObjectHandle.hh>
#include <utility>

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

struct PrepareEmptySigResult {
  std::string file_name;   // temporary file with space reserved for a signature
  size_t sig_offset = 0;   // offset where the signature value should be pasted
  size_t sig_max_size = 0; // maximal size to paste
  std::vector<std::pair<uint64_t, uint64_t>> byteranges;
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

} // namespace pdfcsp::pdf