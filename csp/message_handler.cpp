/* File: message_handler.cpp
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

#include "message_handler.hpp"

#include <stdexcept>

namespace pdfcsp::csp {

// move constructor
MsgDescriptorWrapper::MsgDescriptorWrapper(
  MsgDescriptorWrapper &&other) noexcept
  : symbols_(std::move(other.symbols_)), val_{other.val_} {
  other.val_ = nullptr;
  other.symbols_ = nullptr;
}

// move assignment
MsgDescriptorWrapper &MsgDescriptorWrapper::operator=(
  MsgDescriptorWrapper &&other) noexcept {
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
MsgDescriptorWrapper::MsgDescriptorWrapper(HCRYPTMSG val,
                                           PtrSymbolResolver symbols)
  : symbols_{std::move(symbols)}, val_{val} {
  if (!symbols_) {
    throw std::runtime_error("[MsgHandler] empty symbol resolver");
  }
  if (val_ == nullptr) {
    throw std::runtime_error(
      "[MsgHandler] can't construct with nullptr handler ");
  }
}

MsgDescriptorWrapper::~MsgDescriptorWrapper() {
  if (val_ != nullptr && symbols_) {
    symbols_->dl_CryptMsgClose(val_);
  }
}

HCRYPTMSG MsgDescriptorWrapper::operator*() const {
  if (val_ == nullptr) {
    throw std::runtime_error("[MsgHandler] derefercing nullptr");
  }
  return val_;
}

}  // namespace pdfcsp::csp