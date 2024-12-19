/* File: message_handler.hpp  
Copyright (C) Basealt LLC,  2024
Author: Oleg Proskurin, <proskurinov@basealt.ru>

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with this program; if not, write to the Free Software Foundation,
Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/


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