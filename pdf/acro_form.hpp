#pragma once

#include "pdf_structs.hpp"
namespace pdfcsp::pdf {

// iso table 218
struct AcroForm {
  ObjRawId id;
  std::vector<ObjRawId> fields; // SigField
  int sig_flags = 0b11;         // iso table 219

  std::map<std::string, std::string> other_fields_copied;

  /**
   * @brief Copies an Acroform and it's ID
   * @param other Acroform object
   * @return AcroForm
   * @throws runtime_error if invalid parameter
   */
  static AcroForm ShallowCopy(const PtrPdfObjShared &other);

  [[nodiscard]] std::string ToString() const;
};

} // namespace pdfcsp::pdf
