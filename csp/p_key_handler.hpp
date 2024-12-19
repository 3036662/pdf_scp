/* File: p_key_handler.hpp  
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
#include "utils.hpp"
#include <iostream>
#include <stdexcept>
namespace pdfcsp::csp {

/**
 * @brief Owns a handler for user's private key
 * @throws invalid_argument,runtime_error on construct
 */
class PKeyHandler final {
public:
  PKeyHandler(PCCERT_CONTEXT cert_contex, PtrSymbolResolver symbols)
      : symbols_(std::move(symbols)) {
    if (!symbols_ || cert_contex == nullptr) {
      throw std::invalid_argument("[PKeyHandler] invalid args");
    }
    ResCheck(symbols_->dl_CryptAcquireCertificatePrivateKey(
                 cert_contex, 0, nullptr, &h_csp_, &key_additional_info_,
                 &caller_must_free_),
             "CryptAcquireCertificatePrivateKey", symbols_);
    if (h_csp_ == 0) {
      throw std::runtime_error(
          "[PKeyHandler] failed to get a private key for the certificate");
    }
  }

  PKeyHandler(const PKeyHandler &) = delete;
  PKeyHandler(PKeyHandler &&) = delete;
  PKeyHandler &operator=(const PKeyHandler &) = delete;
  PKeyHandler &operator=(PKeyHandler &&) = delete;

  ~PKeyHandler() {
    if (caller_must_free_ == TRUE) {
      symbols_->dl_CryptReleaseContext(h_csp_, 0);
    }
  }

private:
  PtrSymbolResolver symbols_;
  HCRYPTPROV_OR_NCRYPT_KEY_HANDLE h_csp_ = 0;
  DWORD key_additional_info_ = 0;
  BOOL caller_must_free_ = 0;
};

} // namespace pdfcsp::csp