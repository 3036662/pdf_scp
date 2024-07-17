#pragma once

#include "cerificate.hpp"
#include "message_handler.hpp"
#include "resolve_symbols.hpp"
#include "typedefs.hpp"
#include <cstdint>
#include <memory>
#include <optional>
#include <sys/types.h>

namespace pdfcsp::csp {

enum class CadesType : uint8_t {
  kCadesBes,
  kCadesT,
  kCadesXLong1,
  kPkcs7,
  kUnknown
};

class Message {
public:
  /**
   * @brief Construct a new Message object
   * @param dl a Symbol Resolver
   * @param raw_signature raw signature data
   * @param data
   * @throws std::runtime exception on fail
   */
  explicit Message(std::shared_ptr<ResolvedSymbols> dlsymbols,
                   const BytesVector &raw_signature, const BytesVector &data);

  /**
   * @brief Get the Cades Type object
   *
   * @return CadesType ::kCadesBes,::kCadesT, etc...
   */
  [[nodiscard]] CadesType GetCadesType() const noexcept;

  [[nodiscard]] std::optional<uint> GetSignersCount() const noexcept;
  [[nodiscard]] std::optional<uint> GetRevokedCertsCount() const noexcept;

  /**
   * @brief Get the Signer Cert Id struct
   * @return std::optional<CertificateID>
   */
  [[nodiscard]] std::optional<CertificateID>
  GetSignerCertId(uint signer_index) const noexcept;
#ifndef TEST
private:
#endif

  /// @brief number of certificates
  [[nodiscard]] std::optional<uint> GetCertCount() const noexcept;
  /// @brief get a certificate by index
  [[nodiscard]] std::optional<BytesVector>
  GetRawCertificate(uint index) const noexcept;

#ifdef TEST
private:
#endif

  /**
   * @brief Decode raw message
   * @param sig a raw signature data
   * @param data a raw signed data
   * @throws std::runtime exception on fail
   */
  void DecodeDetachedMessage(const BytesVector &sig, const BytesVector &data);

  /**
   * @brief Throws a runtime_error if res=FALSE
   * @param res
   * @throws std::runtime_error
   */
  void ResCheck(BOOL res, const std::string &msg) const;

  std::shared_ptr<ResolvedSymbols> symbols_;
  MsgDescriptorWrapper msg_handler_;
};

} // namespace pdfcsp::csp