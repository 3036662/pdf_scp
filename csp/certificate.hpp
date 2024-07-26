#pragma once

#include "certificate_id.hpp"
#include "resolve_symbols.hpp"
#include "typedefs.hpp"

namespace pdfcsp::csp {

/**
 * @brief Certificate context wrapper
 * @throws runtime_error if construction fails
 */
class Certificate {
public:
  Certificate() = delete;
  Certificate(const Certificate &) = delete;
  Certificate &operator=(const Certificate &) = delete;

  explicit Certificate(const BytesVector &raw_certm, PtrSymbolResolver symbols);
  Certificate(Certificate &&other) noexcept;
  Certificate &operator=(Certificate &&other) noexcept;
  ~Certificate();

  [[nodiscard]] bool IsTimeValid() const noexcept;
  [[nodiscard]] bool IsRevocationStatusOK() const noexcept;

private:
  PCCERT_CONTEXT p_ctx_ = nullptr;
  PtrSymbolResolver symbols_;
};

} // namespace pdfcsp::csp