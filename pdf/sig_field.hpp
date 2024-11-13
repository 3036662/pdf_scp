#pragma once
#include "pdf_structs.hpp"
#include <optional>

namespace pdfcsp::pdf {

// SigField signature annotation
struct SigField {
  ObjRawId id;
  std::string type = kTagAnnot;
  std::string subtype = kTagWidget;
  ObjRawId parent;
  ObjRawId appearance_ref;
  BBox rect; // the location of the annotation on the page in default user space
             // units.
  std::string ft = kTagSig;
  int flags = 0b100;
  std::optional<std::string> name;
  std::optional<ObjRawId> value;

  [[nodiscard]] std::string ToString() const;
};

} // namespace pdfcsp::pdf