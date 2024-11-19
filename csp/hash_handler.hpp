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