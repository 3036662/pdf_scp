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
  int32_t bits_per_component = 8;
  std::vector<unsigned char> data;
  double resize_factor_x = 1.0;
  double resize_factor_y = 1.0;

  [[nodiscard]] BytesVector ToRawData() const;
  [[nodiscard]] std::string ToString() const;

  bool ReadFile(const std::string &path, uint32_t pix_width,
                uint32_t pix_height, int32_t bits_p_component) noexcept;
};

} // namespace pdfcsp::pdf