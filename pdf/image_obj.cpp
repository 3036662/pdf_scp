
#include "image_obj.hpp"
#include "pdf_structs.hpp"
#include <iterator>
#include <sstream>

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

} // namespace pdfcsp::pdf