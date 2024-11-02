#include "sig_val.hpp"
#include "pdf_defs.hpp"
#include "utils.hpp"
#include <algorithm>
#include <cstddef>
#include <string>

namespace pdfcsp::pdf {

std::string SigVal::ToString() const {
  std::ostringstream builder;
  builder << id.ToString() << "\n"
          << kDictStart << "\n"
          << kTagType << " " << type << "\n"
          << kTagFilter << " " << filter << "\n"
          << kTagSubFilter << " " << subfilter << "\n"
          << kTagContents << "\n"
          << '<' << ByteVectorToHexString(contents_raw) << ">\n"
          << kTagByteRange << " [ ";
  //   for (const auto &pair_val : byteranges) {
  //     builder << pair_val.first << " " << pair_val.second;
  //   }
  // just free space for byteranges
  for (size_t i = 0; i < kSizeOfSpacesReservedForByteRanges; ++i) {
    builder << ' ';
  }
  builder << " ]\n";
  if (date.has_value()) {
    builder << "/M (D:" << date.value() << ")\n";
  }
  if (app_fullname.has_value()) {
    builder << kTagPropBuild << " " << kDictStart << "\n"
            << kTagAppFullName << " (" << app_fullname.value() << ")\n"
            << kDictEnd << "\n";
  }
  builder << kDictEnd << "\n" << kObjEnd;
  return builder.str();
}

void SigVal::CalcOffsets() {
  const std::string src = ToString();
  // offset of hex string
  {
    std::string substr = kTagContents;
    substr += "\n<";
    const size_t pos = src.find(substr, 0);
    if (pos != std::string::npos && pos + substr.size() < src.size()) {
      hex_str_offset = pos + substr.size() - 1;
      hex_str_length = contents_raw.size() * 2;
    }
  }
  // offset of free space for byteranges
  const std::string substr2 = std::string(kTagByteRange) + " [ ";
  const size_t pos2 = src.find(substr2);
  if (pos2 != std::string::npos && pos2 + 3 < src.size()) {
    byteranges_str_offset = pos2 + substr2.size();
  }
}

} // namespace pdfcsp::pdf