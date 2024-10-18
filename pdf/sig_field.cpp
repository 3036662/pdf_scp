#include "sig_field.hpp"
#include "pdf_structs.hpp"
#include <sstream>

namespace pdfcsp::pdf {

std::string SigField::ToString() const {
  std::ostringstream builder;
  builder << id.ToString() << "\n"
          << kDictStart << "\n" // dict start
          << kTagFT << " " << ft << "\n"
          << kTagF << " " << flags << "\n";
  if (name.has_value()) {
    builder << kTagT << " (" << name.value() << ")\n";
  }
  builder << kTagType << " " << type << "\n"
          << kTagSubType << " " << subtype << "\n"
          << kTagP << " " << parent.ToStringRef() << "\n"
          << kTagRect << " " << rect.ToString() << "\n";
  // /AP dict start
  builder << kTagAP << " " << kDictStart << "\n"
          << kTagN << " " << appearance_ref.ToStringRef() << "\n"
          << kDictEnd << "\n";
  // /AP dict end
  // /Sig
  if (value.has_value()) {
    builder << kTagV << " " << value->ToStringRef() << "\n";
  }
  builder << kDictEnd << "\n" // dict end
          << kObjEnd;
  return builder.str();
}

} // namespace pdfcsp::pdf