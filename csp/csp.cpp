#include "csp.hpp"
#include "message.hpp"
#include <exception>
#include <iostream>
#include <memory>

namespace pdfcsp::csp {

PtrMsg Csp::OpenDetached(BytesVector message, BytesVector data) noexcept {
  try {
    return std::make_unique<Message>(dl_, std::move(message), std::move(data));
  } catch (std::exception ex) {
    Log(ex.what());
    return nullptr;
  }
}

void Csp::Log(const char *msg) const noexcept {
  if (std_err_flag_) {
    std::cerr << "[Pdf]" << msg << "\n";
  }
}

inline void Csp::Log(const std::string &msg) const noexcept {
  Log(msg.c_str());
}

} // namespace pdfcsp::csp