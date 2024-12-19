/* File: hash_handler.hpp  
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
#include "typedefs.hpp"
#include <string>

namespace pdfcsp::csp {

///@throws runtime_exception on construct
///@details owns HCRYPTPROV and HCRYPTHASH
class HashHandler {
public:
  HashHandler() = delete;
  HashHandler(const HashHandler &) = delete;
  HashHandler &operator=(const HashHandler &) = delete;

  explicit HashHandler(const std::string &hashing_algo,
                       PtrSymbolResolver symbols);
  HashHandler(HashHandler &&other) noexcept;
  HashHandler &operator=(HashHandler &&other) noexcept;
  ~HashHandler();

  void SetData(const BytesVector &data);
  [[nodiscard]] BytesVector GetValue() const;

  [[nodiscard]] const HCRYPTPROV &get_csp_hanler() const noexcept {
    return csp_handler_;
  }

  [[nodiscard]] const HCRYPTHASH &get_hash_handler() const noexcept {
    return hash_handler_;
  }

private:
  HCRYPTPROV csp_handler_ = 0;
  HCRYPTHASH hash_handler_ = 0;
  PtrSymbolResolver symbols_;
};

} // namespace pdfcsp::csp