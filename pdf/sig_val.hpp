#pragma once
#include "pdf_defs.hpp"
#include "pdf_structs.hpp"
#include <cstddef>
#include <optional>

namespace pdfcsp::pdf {

struct SigVal {
  ObjRawId id;
  std::string type = kTagSig;
  std::string filter = kAdobePPKLite;
  std::string subfilter = kETSICAdESdetached;
  BytesVector contents_raw;
  // std::vector<std::pair<uint64_t, uint64_t>> byteranges;
  std::optional<std::string> date; //(D:20241015123037Z) only for CADES_BES
  std::optional<std::string> app_fullname = kAltLinuxPdfSignTool;

  size_t hex_str_offset = 0;
  size_t hex_str_length = 0;
  size_t byteranges_str_offset = 0;

  ///@brief calculate offset for hex string
  void CalcOffsets();

  [[nodiscard]] std::string ToString() const;
};

} // namespace pdfcsp::pdf