#pragma once

#include "resolve_symbols.hpp"
#include "typedefs.hpp"
#include <memory>
#include <stdexcept>

namespace pdfcsp::csp {

class Message {
public:
  explicit Message(std::shared_ptr<ResolvedSymbols> dl,
                   BytesVector &&raw_signature, BytesVector &&data);

private:
  std::shared_ptr<ResolvedSymbols> dl_;
};

} // namespace pdfcsp::csp