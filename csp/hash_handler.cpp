/* File: hash_handler.cpp
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

#include "hash_handler.hpp"

#include <exception>
#include <stdexcept>

#include "CSP_WinCrypt.h"
#include "typedefs.hpp"
#include "utils.hpp"

namespace pdfcsp::csp {

HashHandler::HashHandler(const std::string &hashing_algo,
                         PtrSymbolResolver symbols)
  : symbols_(std::move(symbols)) {
  const uint64_t provider_type = GetProviderType(hashing_algo);
  ResCheck(
    symbols_->dl_CryptAcquireContextA(&csp_handler_, nullptr, nullptr,
                                      provider_type, CRYPT_VERIFYCONTEXT),
    "CryptAcquireContextA", symbols_);
  if (csp_handler_ == 0) {
    throw std::runtime_error("CSP handler == 0");
  }
  try {
    const unsigned int hash_calc_type = GetHashCalcType(hashing_algo);
    ResCheck(symbols_->dl_CryptCreateHash(csp_handler_, hash_calc_type, 0, 0,
                                          &hash_handler_),
             "CryptCreateHash", symbols_);
  } catch (const std::exception & /*&ex*/) {
    if (csp_handler_ != 0) {
      symbols_->dl_CryptReleaseContext(csp_handler_, 0);
    }
    throw;
  }
}

void HashHandler::SetData(const BytesVector &data) {
  ResCheck(
    symbols_->dl_CryptHashData(hash_handler_, data.data(), data.size(), 0),
    "CryptHashData", symbols_);
}

BytesVector HashHandler::GetValue() const {
  DWORD hash_size = 0;
  DWORD hash_size_size = sizeof(DWORD);
  // NOLINTBEGIN(cppcoreguidelines-pro-type-reinterpret-cast)
  ResCheck(symbols_->dl_CryptGetHashParam(hash_handler_, HP_HASHSIZE,
                                          reinterpret_cast<BYTE *>(&hash_size),
                                          &hash_size_size, 0),
           "Get Hash size", symbols_);
  // NOLINTEND(cppcoreguidelines-pro-type-reinterpret-cast)
  if (hash_size == 0) {
    throw std::runtime_error("hash size == 0");
  }
  BytesVector data_hash_calculated;
  data_hash_calculated.resize(hash_size, 0x00);
  ResCheck(
    symbols_->dl_CryptGetHashParam(hash_handler_, HP_HASHVAL,
                                   data_hash_calculated.data(), &hash_size, 0),
    "CryptGetHashParam hash value", symbols_);
  return data_hash_calculated;
}

HashHandler::~HashHandler() {
  if (hash_handler_ != 0) {
    symbols_->dl_CryptDestroyHash(hash_handler_);
  }
  if (csp_handler_ != 0) {
    symbols_->dl_CryptReleaseContext(csp_handler_, 0);
  }
}

HashHandler::HashHandler(HashHandler &&other) noexcept
  : csp_handler_(other.csp_handler_),
    hash_handler_(other.hash_handler_),
    symbols_(std::move(other.symbols_)) {
  other.csp_handler_ = 0;
  other.hash_handler_ = 0;
}

HashHandler &HashHandler::operator=(HashHandler &&other) noexcept {
  if (this == &other) {
    return *this;
  }
  if (hash_handler_ != 0) {
    symbols_->dl_CryptDestroyHash(hash_handler_);
  }
  if (csp_handler_ != 0) {
    symbols_->dl_CryptReleaseContext(csp_handler_, 0);
  }
  csp_handler_ = other.csp_handler_;
  other.csp_handler_ = 0;
  hash_handler_ = other.hash_handler_;
  other.hash_handler_ = 0;
  return *this;
}

}  // namespace pdfcsp::csp