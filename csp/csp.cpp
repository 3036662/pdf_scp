#include "csp.hpp"
#include "message.hpp"
#include <exception>
#include <iostream>
#include <memory>

namespace pdfcsp::csp {

// get Message object
PtrMsg Csp::OpenDetached(const BytesVector &message,
                         const BytesVector &data) noexcept {
  try {
    return std::make_shared<Message>(dl_, message, data);
  } catch (const std::exception &ex) {
    Log(ex.what());
    return nullptr;
  }
}

// -------------------------- private -----------------------------------

void Csp::Log(const char *msg) const noexcept {
  if (std_err_flag_) {
    std::cerr << "[CSP]" << msg << "\n";
  }
}

inline void Csp::Log(const std::string &msg) const noexcept {
  Log(msg.c_str());
}

} // namespace pdfcsp::csp