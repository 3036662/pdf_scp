#pragma once

#include "hash_handler.hpp"
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

enum class AttributesType : uint8_t { kSigned, kUnsigned };

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
                   const BytesVector &raw_signature);

  /**
   * @brief Get the Cades Type object
   * @details uses csp cades func
   * @return CadesType ::kCadesBes,::kCadesT, etc...
   */
  [[nodiscard]] CadesType GetCadesType() const noexcept;

  [[nodiscard]] CadesType GetCadesTypeEx(uint signer_index) const noexcept;

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

  [[nodiscard]] bool Check(const BytesVector &data, uint signer_index,
                           bool ocsp_check) const noexcept;

// private in release
#ifndef TEST
private:
#endif

  /// @brief number of certificates
  [[nodiscard]] std::optional<uint>
  GetCertCount(uint64_t signer_index) const noexcept;
  /// @brief get a certificate by index
  [[nodiscard]] std::optional<BytesVector>
  GetRawCertificate(uint index) const noexcept;
  /// @brief CERT_NAME_BLOB to string

  /// @brief get a bunch of crypto-attributes
  [[nodiscard]] std::optional<CryptoAttributesBunch>
  GetAttributes(uint signer_index, AttributesType type) const noexcept;

  /**
   * @brief Extracts the ID of an algorithm that is used for data hashing
   * @param signer_index
   * @return std::optional<std::string>
   * @details extracts the id from two sources:
   * 1.signed attributes certificate info.
   * 2.CMSG_SIGNER_HASH_ALGORITHM_PARAM.
   * Compares these two values and returns first if they match.
   */
  [[nodiscard]] std::optional<std::string>
  GetDataHashingAlgo(uint signer_index) const noexcept;

  [[nodiscard]] std::optional<BytesVector>
  GetEncryptedDigest(uint signer_index) const noexcept;

  // -------------------- data hash ------------------
  /**
   * @brief Gets the data hash from signed attributes -
   * szOID_PKCS_9_MESSAGE_DIGEST
   * @param signer_index
   * @return std::optional<BytesVector>
   */
  [[nodiscard]] std::optional<BytesVector>
  GetSignedDataHash(uint signer_index) const noexcept;

  [[nodiscard]] std::optional<BytesVector>
  CalculateDataHash(const std::string &hashing_algo,
                    const BytesVector &data) const noexcept;

  /**
   * @brief Verify hash with CadesVerifyHash
   * @param hash
   * @param hashing_algo
   */
  [[nodiscard]] bool
  VeriyDataHashCades(const BytesVector &hash,
                     const std::string &hashing_algo) const noexcept;

  // -------------------- computed  hash ------------------
  /**
   * @brief Calculate a COMPUTED_HASH VALUE from raw data
   * @param signer_index
   * @return std::optional<BytesVector>
   */
  [[nodiscard]] std::optional<HashHandler>
  CalculateComputedHash(uint signer_index) const noexcept;

  /**
   * @brief extracts signer attributes from a raw signature
   * @param signer_index
   * @return BytesVector
   * @throws runtime_error
   */
  [[nodiscard]] BytesVector ExtractRawSignedAttributes(uint signer_index) const;

  [[nodiscard]] std::optional<BytesVector>
  GetComputedHash(uint signer_index) const noexcept;

  // -------------------- certificate hash ------------------

  /**
   * @brief Calculate a Certificate hash from raw certificate
   * @param signer_index
   * @return std::optional<BytesVector>
   */
  [[nodiscard]] std::optional<HashHandler>
  CalculateCertHash(uint signer_index) const noexcept;

  /**
   * @brief Calculate signer's cerificate hash and compare it with hash from
   * signed attributes
   * @param signer_index
   */
  [[nodiscard]] bool CheckCertificateHash(uint signer_index) const noexcept;

  // ----------------- CADES_T ------------------
  [[nodiscard]] bool CheckCadesT(uint signer_index) const;

#ifdef TEST
private:
#endif

  /**
   * @brief Decode raw message
   * @param sig a raw signature data
   * @param data a raw signed data
   * @throws std::runtime exception on fail
   */
  void DecodeDetachedMessage(const BytesVector &sig);

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