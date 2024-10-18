
#include "image_obj.hpp"
#include "pdf_structs.hpp"
#include "utils.hpp"
#include <filesystem>
#include <iterator>
#include <sstream>
#include <utility>

namespace pdfcsp::pdf {

std::string ImageObj::ToString() const {
  std::ostringstream builder;
  builder << id.ToString() << "\n"
          << kDictStart << "\n"
          << kTagType << " " << kTagXObject << "\n"
          << kTagSubType << " " << kTagImage << "\n"
          << kTagWidth << " " << width << "\n"
          << kTagHeight << " " << height << "\n"
          << kTagColorSpace << " " << kDeviceRgb << "\n"
          << kTagBitsPerComponent << " " << bits_per_component << "\n"
          << kTagLength << " " << data.size() << "\n"
          << kDictEnd << "\n";
  return builder.str();
}

BytesVector ImageObj::ToRawData() const {
  BytesVector res;
  std::string strdata = ToString();
  strdata += kStreamStart;
  res.reserve(data.size() + strdata.size());
  std::copy(strdata.cbegin(), strdata.cend(), std::back_inserter(res));
  std::copy(data.cbegin(), data.cend(), std::back_inserter(res));
  strdata = "\n";
  strdata += kStreamEnd;
  strdata += kObjEnd;
  std::copy(strdata.cbegin(), strdata.cend(), std::back_inserter(res));
  return res;
}

bool ImageObj::ReadFile(const std::string &path, uint32_t pix_width,
                        uint32_t pix_height,
                        int32_t bits_p_component) noexcept {
  if (path.empty() || !std::filesystem::exists(path) || pix_width == 0 ||
      pix_height == 0 || bits_p_component == 0) {
    return false;
  }
  // read file
  auto buf = FileToVector(std::string(path));
  if (!buf || buf->empty()) {
    return false;
  }
  data = std::move(buf.value());
  width = pix_width;
  height = pix_height;
  bits_per_component = bits_p_component;
  return true;
}

} // namespace pdfcsp::pdf