#include "pdf_structs.hpp"
#include "utils.hpp"
namespace pdfcsp::pdf {

std::string XYReal::ToString() const {
  std::ostringstream builder;
  builder << DoubleToString10(x) << " " << DoubleToString10(y);
  return builder.str();
}

std::string BBox::ToString() const {
  std::ostringstream builder;
  builder << "[ " << left_bottom.ToString() << " " << right_top.ToString()
          << " ]";
  return builder.str();
}

std::string Matrix::toString() const {
  std::ostringstream builder;
  builder << DoubleToString10(a) << " " << DoubleToString10(b) << " "
          << DoubleToString10(c) << " " << DoubleToString10(d) << " "
          << DoubleToString10(e) << " " << DoubleToString10(f);
  return builder.str();
}

ObjRawId ObjRawId::CopyIdFromExisting(const QPDFObjectHandle &other) noexcept {
  return {other.getObjectID(), other.getGeneration()};
}

} // namespace pdfcsp::pdf