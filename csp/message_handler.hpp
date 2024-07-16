#pragma once

#include "resolve_symbols.hpp"
#include <iostream>
#include <stdexcept>

namespace pdfcsp::csp {

class MsgDescriptorWrapper {
public:
  /**
   * @brief Construct an emptyMsg Handler object
   */
  MsgDescriptorWrapper() noexcept : symbols_(nullptr), val_(nullptr) {};

  // no copy
  MsgDescriptorWrapper(const MsgDescriptorWrapper &other) = delete;
  MsgDescriptorWrapper &operator=(const MsgDescriptorWrapper &other) = delete;
  // move
  MsgDescriptorWrapper(MsgDescriptorWrapper &&other) noexcept;
  MsgDescriptorWrapper &operator=(MsgDescriptorWrapper &&other) noexcept;

  /**
   * @brief Construct a new Msg Handler object
   *
   * @param val handler value from CryptMsgOpen
   * @param symbols symbol resover
   */
  MsgDescriptorWrapper(HCRYPTMSG val, PtrSymbolResolver symbols);

  /**
   * @brief get native CSP handler
   * @return HCRYPTMSG
   * @throws runtime_error if handler == nullptr
   */
  HCRYPTMSG operator*() const;

  explicit operator bool() const { return val_ != nullptr; }

  ~MsgDescriptorWrapper();

private:
  PtrSymbolResolver symbols_;
  HCRYPTMSG val_;
};

} // namespace pdfcsp::csp