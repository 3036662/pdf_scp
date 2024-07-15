#pragma once

#include "resolve_symbols.hpp"
#include <iostream>
#include <stdexcept>

namespace pdfcsp::csp {

class MsgHandler {
public:
  /**
   * @brief Construct an emptyMsg Handler object
   */
  MsgHandler() noexcept : symbols_(nullptr), val_(nullptr) {};

  // no copy
  MsgHandler(const MsgHandler &other) = delete;
  MsgHandler &operator=(const MsgHandler &other) = delete;
  // move
  MsgHandler(MsgHandler &&other);
  MsgHandler &operator=(MsgHandler &&other);

  /**
   * @brief Construct a new Msg Handler object
   *
   * @param val handler value from CryptMsgOpen
   * @param symbols symbol resover
   */
  MsgHandler(HCRYPTMSG val, PtrSymbolResolver symbols);

  /**
   * @brief get native CSP handler
   * @return HCRYPTMSG
   * @throws runtime_error if handler == nullptr
   */
  HCRYPTMSG operator*() const;

  ~MsgHandler();

private:
  PtrSymbolResolver symbols_;
  HCRYPTMSG val_;
};

} // namespace pdfcsp::csp