/* File: store_handler.cpp
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

#include <iostream>
#include <stdexcept>

#include "store_hanler.hpp"
#include "utils.hpp"

namespace pdfcsp::csp {

StoreHandler::StoreHandler(const char *store_provider, DWORD flags,
                           const void *params, PtrSymbolResolver symbols)
  : symbols_(std::move(symbols)) {
  if (!symbols_) {
    throw std::runtime_error("[StoreHandler] invalid symbol resolver");
  }
  h_store_ = symbols_->dl_CertOpenStore(store_provider, 0, 0, flags, params);
  if (h_store_ == nullptr) {
    symbols_->log->debug("[StoreHandler] constructor for store {} failed",
                         store_provider);
    throw std::runtime_error("[StoreHandler] CertOpenStore failed");
  }
}

StoreHandler::~StoreHandler() {
  if (h_store_ != nullptr) {
    symbols_->dl_CertCloseStore(h_store_, 0);
  }
}

void StoreHandler::AddCertificate(const Certificate &cert) {
  ResCheck(symbols_->dl_CertAddCertificateContextToStore(
             h_store_, cert.GetContext(), CERT_STORE_ADD_ALWAYS, nullptr),
           "CertAddCertificateContextToStore", symbols_);
}

}  // namespace pdfcsp::csp