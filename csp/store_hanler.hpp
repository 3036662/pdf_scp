/* File: store_hanler.hpp  
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

#include "certificate.hpp"
#include "resolve_symbols.hpp"

namespace pdfcsp::csp {

class StoreHandler {
public:
  StoreHandler() = delete;
  StoreHandler(const StoreHandler &) = delete;
  StoreHandler(StoreHandler &&) = delete;
  StoreHandler &operator=(StoreHandler &&) = delete;
  StoreHandler &operator=(StoreHandler &) = delete;
  explicit StoreHandler(const char *store_provider, DWORD flags,
                        const void *params, PtrSymbolResolver symbols);
  ~StoreHandler();

  void AddCertificate(const Certificate &cert);

  [[nodiscard]] HCERTSTORE RawHandler() const noexcept { return h_store_; }

private:
  PtrSymbolResolver symbols_;
  HCERTSTORE h_store_ = nullptr;
};

} // namespace pdfcsp::csp