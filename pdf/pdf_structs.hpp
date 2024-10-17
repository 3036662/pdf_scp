#pragma once

#include "utils.hpp"
#include <cstdint>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

namespace pdfcsp::pdf {

using RangesVector = std::vector<std::pair<uint64_t, uint64_t>>;
using BytesVector = std::vector<unsigned char>;

constexpr const char *const kTagAcroForm = "/AcroForm";
constexpr const char *const kTagFields = "/Fields";
constexpr const char *const kTagType = "/Type";
constexpr const char *const kTagSubType = "/Subtype";
constexpr const char *const kTagFilter = "/Filter";
constexpr const char *const kTagContents = "/Contents";
constexpr const char *const kTagByteRange = "/ByteRange";
constexpr const char *const kTagXObject = "/XObject";
constexpr const char *const kTagForm = "/Form";
constexpr const char *const kTagFormType = "/FormType";
constexpr const char *const kTagBBox = "/BBox";
constexpr const char *const kTagImage = "/Image";
constexpr const char *const kTagWidth = "/Width";
constexpr const char *const kTagHeight = "/Height";
constexpr const char *const kTagColorSpace = "/ColorSpace";
constexpr const char *const kTagBitsPerComponent = "/BitsPerComponent";
constexpr const char *const kTagLength = "/Length";
constexpr const char *const kTagResources = "/Resources";

constexpr const char *const kDictStart = "<<";
constexpr const char *const kDictEnd = ">>";
constexpr const char *const kStreamStart = "stream\n";
constexpr const char *const kStreamEnd = "endstream\n";
constexpr const char *const kObjEnd = "endobj\n";

constexpr const char *const kDeviceRgb = "/DeviceRGB";
constexpr const char *const kErrNoAcro = "No acroform found";

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
};

struct XYReal {
  double x = 0;
  double y = 0;

  [[nodiscard]] std::string ToString() const {
    std::ostringstream builder;
    builder << DoubleToString10(x) << " " << DoubleToString10(y);
    return builder.str();
  }
};

struct BBox {
  XYReal left_bottom;
  XYReal right_top;

  [[nodiscard]] std::string ToString() const {
    std::ostringstream builder;
    builder << "[ " << left_bottom.ToString() << " " << right_top.ToString()
            << " ]";
    return builder.str();
  }
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

  [[nodiscard]] std::string toString() const {
    std::ostringstream builder;
    builder << DoubleToString10(a) << " " << DoubleToString10(b) << " "
            << DoubleToString10(c) << " " << DoubleToString10(d) << " "
            << DoubleToString10(e) << " " << DoubleToString10(f);
    return builder.str();
  }
};

}; // namespace pdfcsp::pdf