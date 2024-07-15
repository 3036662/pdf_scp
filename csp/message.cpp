#include "message.hpp"
#include <stdexcept>

namespace pdfcsp::csp {

Message::Message(std::shared_ptr<ResolvedSymbols> dl,
                 BytesVector &&raw_signature, BytesVector &&data)
    : dl_(std::move(dl)) {
  if (!dl_) {
    throw std::runtime_error("Symbol resolver is null");
  }
  if (raw_signature.empty() || data.empty()) {
    throw std::logic_error("Empty data");
  }
  
}

} // namespace pdfcsp::csp