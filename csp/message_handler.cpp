#include "message_handler.hpp"

#include <stdexcept>

namespace pdfcsp::csp {

// move constructor
MsgHandler::MsgHandler(MsgHandler &&other)
    : symbols_(std::move(other.symbols_)), val_{other.val_} {
  other.val_ = nullptr;
  other.symbols_ = nullptr;
};

// move assignment
MsgHandler &MsgHandler::operator=(MsgHandler &&other) {
  if (this == &other) {
    return *this;
  }
  if (val_ != nullptr && symbols_ != nullptr) {
    symbols_->dl_CryptMsgClose(val_);
  }
  symbols_ = std::move(other.symbols_);
  val_ = other.val_;
  other.val_ = nullptr;
  other.symbols_ = nullptr;
  return *this;
}

// construct with handler and symbols
MsgHandler::MsgHandler(HCRYPTMSG val, PtrSymbolResolver symbols)
    : symbols_{std::move(symbols)}, val_{val} {
  if (!symbols_) {
    throw std::runtime_error("[MsgHandler] empty symbol resolver");
  }
  if (!val_) {
    throw std::runtime_error(
        "[MsgHandler] can't construct with nullptr handler ");
  }
}

MsgHandler::~MsgHandler() {
  if (val_ != nullptr && symbols_) {
    symbols_->dl_CryptMsgClose(val_);
  }
};

HCRYPTMSG MsgHandler::operator*() const {
  if (val_ == nullptr) {
    throw std::runtime_error("[MsgHandler] derefercing nullptr");
  }
  return val_;
}

} // namespace pdfcsp::csp