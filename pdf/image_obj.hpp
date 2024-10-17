#pragma once

#include "pdf_structs.hpp"
#include <cstdint>
#include <vector>

namespace pdfcsp::pdf {

struct ImageObj {
  ObjRawId id;
  std::string type = kTagXObject;
  std::string subtype = kTagImage;
  uint32_t width = 0;
  uint32_t height = 0;
  std::string colorspace = kDeviceRgb;
  int32_t bits_per_component = 0;
  std::vector<unsigned char> data;

  [[nodiscard]] BytesVector ToRawData() const;
  [[nodiscard]] std::string ToString() const;
};

} // namespace pdfcsp::pdf