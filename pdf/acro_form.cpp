
#include "acro_form.hpp"
#include "pdf_defs.hpp"
#include "pdf_structs.hpp"
#include "pdf_utils.hpp"
#include <stdexcept>
#include <string>

namespace pdfcsp::pdf {

std::string AcroForm::ToString() const {
  std::ostringstream builder;
  builder << id.ToString() << "\n"
          << kDictStart << "\n"
          << kTagFields << " " << "[ ";
  for (const auto &field : fields) {
    builder << field.ToStringRef() << " ";
  }
  builder << "]\n";
  builder << kTagSigFlags << " " << std::to_string(sig_flags) << "\n";
  for (const auto &field_pair : other_fields_copied) {
    builder << field_pair.first << " " << field_pair.second << "\n";
  }
  builder << kDictEnd << "\n" << kObjEnd;
  return builder.str();
}

AcroForm AcroForm::ShallowCopy(const PtrPdfObjShared &other) {
  if (!other || !other->isDictionary()) {
    throw std::runtime_error("[AcroForm::ShallowCopy] not a dictionary");
  }
  AcroForm res;
  // res.id
  res.id.id = other->getObjectID();
  res.id.gen = other->getGeneration();
  // fields vector
  if (other->hasKey(kTagFields) && other->getKey(kTagFields).isArray()) {
    for (auto &lnk : other->getKey(kTagFields).getArrayAsVector()) {
      if (lnk.isDictionary()) {
        res.fields.push_back({lnk.getObjectID(), lnk.getGeneration()});
      }
    }
  }
  // copy all the rest fields except SigFlags,Fields
  auto unparsed_map = DictToUnparsedMap(*other);
  for (const auto &field_pair : unparsed_map) {
    if (field_pair.first != kTagFields && field_pair.first != kTagSigFlags) {
      res.other_fields_copied.insert(field_pair);
    }
  }

  return res;
}

} // namespace pdfcsp::pdf