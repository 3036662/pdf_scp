#pragma once

#include "resolve_symbols.hpp"
#include "typedefs.hpp"
#include <ctime>
#include <optional>

namespace pdfcsp::csp {

struct CertTimeBounds {
  time_t not_before = 0;
  time_t not_after = 0;
  std::optional<time_t> revocation;
};

/**
 * @brief Certificate context wrapper
 * @throws runtime_error if construction fails
 */
class Certificate {
public:
  Certificate() = default;
  Certificate(const Certificate &) = delete;
  Certificate &operator=(const Certificate &) = delete;

  ///@brief construct from a raw certificate
  explicit Certificate(const BytesVector &raw_cert, PtrSymbolResolver symbols);

  /**
   * @brief Wrap Certificate object without decoding
   * @param h_store A handle of a certificate store.
   * @param p_cert_ctx A pointer to the CERT_CONTEXT
   * @param symbols
   * @throws runtime_error
   */
  explicit Certificate(HCERTSTORE h_store, PCCERT_CONTEXT p_cert_ctx,
                       PtrSymbolResolver symbols);
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

  // @brief set bounds , notBefore, notAfter, (optional) revocation date
  [[nodiscard]] const CertTimeBounds &GetTimeBounds() const {
    return time_bounds_;
  }

private:
  // @brief set bounds , notBefore, notAfter
  [[nodiscard]] CertTimeBounds SetTimeBounds() const;

  PCCERT_CONTEXT p_ctx_ = nullptr;
  PtrSymbolResolver symbols_;
  CertTimeBounds time_bounds_;
  // in some cases we need a store handle to wrap a certificate
  HCERTSTORE h_store_ = nullptr;
};

} // namespace pdfcsp::csp