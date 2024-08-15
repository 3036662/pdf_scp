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

private:
  PtrSymbolResolver symbols_;
  HCERTSTORE h_store_ = nullptr;
};

} // namespace pdfcsp::csp