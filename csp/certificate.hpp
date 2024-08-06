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

  ///@brief construct from a raw certificate
  explicit Certificate(const BytesVector &raw_cert, PtrSymbolResolver symbols);
  Certificate(Certificate &&other) noexcept;
  Certificate &operator=(Certificate &&other) noexcept;
  ~Certificate();

  ///@brief check notBefore notAfter bounds
  [[nodiscard]] bool IsTimeValid() const noexcept;

  ///@brief check the certificate chain
  [[nodiscard]] bool IsChainOK() const noexcept;

  /**
   * @brief Ask the OSCP server about the certificate's status.
   * @throws runtime_error
   */
  [[nodiscard]] bool IsOcspStatusOK() const;

  ///@brief return a raw certificate context pointer
  [[nodiscard]] PCCERT_CONTEXT GetContext() const noexcept { return p_ctx_; }

private:
  PCCERT_CONTEXT p_ctx_ = nullptr;
  PtrSymbolResolver symbols_;
};

} // namespace pdfcsp::csp