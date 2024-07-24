#pragma once

#include <vector>
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Winvalid-utf8"
#include "CSP_WinCrypt.h"
#pragma GCC diagnostic pop
#include "certificate_id.hpp"
#include "crypto_attribute.hpp"
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
   * @return CadesType ::kCadesBes,::kCadesT, etc...
   */
  [[nodiscard]] CadesType GetCadesType() const noexcept;

  /// @brief get number of signers
  [[nodiscard]] std::optional<uint> GetSignersCount() const noexcept;
  /// @brief get number of revoced certificates
  [[nodiscard]] std::optional<uint> GetRevokedCertsCount() const noexcept;

  /**
   * @brief Get the Signer Cert Id struct
   * @return std::optional<CertificateID>
   */
  [[nodiscard]] std::optional<CertificateID>
  GetSignerCertId(uint signer_index) const noexcept;

  [[nodiscard]] bool CheckDataHash(const BytesVector &data,
                                   uint signer_index) const noexcept;

// private in release
#ifndef TEST
private:
#endif

  /// @brief number of certificates
  [[nodiscard]] std::optional<uint> GetCertCount() const noexcept;
  /// @brief get a certificate by index
  [[nodiscard]] std::optional<BytesVector>
  GetRawCertificate(uint index) const noexcept;
  /// @brief CERT_NAME_BLOB to string

  [[nodiscard]] std::optional<CryptoAttributesBunch>
  GetSignedAttributes(uint signer_index) const noexcept;
  [[nodiscard]] std::optional<std::string>
  GetDataHashingAlgo(uint signer_index) const noexcept;
  [[nodiscard]] std::optional<BytesVector>
  GetSignedDataHash(uint signer_index) const noexcept;
  /**
   * @brief CalculateHash and Verify
   * @param hash_to_compare hash from signed attributes
   * @param hashing_algo
   * @param data data to hash
   * @return std::optional<BytesVector>
   */
  [[nodiscard]] bool VeriyHash(const BytesVector &hash_to_compare,
                               const std::string &hashing_algo,
                               const BytesVector &data,
                               uint signer_index) const noexcept;

  [[nodiscard]] std::optional<BytesVector>
  CalculateComputedHash(uint signer_index) const noexcept;

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
  BytesVector raw_signature_;
};

} // namespace pdfcsp::csp