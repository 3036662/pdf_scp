#include "utils.hpp"

namespace pdfcsp::csp {

std::vector<unsigned char> CreateBuffer(size_t size) {
  std::vector<unsigned char> res;
  res.reserve(size + 1);
  return res;
}

} // namespace pdfcsp::csp