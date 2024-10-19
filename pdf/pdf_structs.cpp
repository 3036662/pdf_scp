#include "pdf_structs.hpp"
#include "utils.hpp"
#include <iomanip>
#include <ios>
#include <sstream>
#include <string>
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

std::string XRefEntry::ToString() const {
  std::string res;
  const std::string offs = std::to_string(offset);
  if (offs.size() < 10) {
    res.append(std::string(10 - offs.size(), '0'));
  }
  res.append(offs);
  res += ' ';
  const std::string gens = std::to_string(gen);
  if (gens.size() < 10) {
    res.append(std::string(5 - gens.size(), '0'));
  }
  res.append(gens);
  res += " n \n";
  return res; // result size must be 20 bytes
}

} // namespace pdfcsp::pdf