#pragma once

#include "asn1.hpp"
#include "certificate.hpp"
#include "certificate_id.hpp"
#include "check_result.hpp"
#include "crypto_attribute.hpp"
#include "hash_handler.hpp"
#include "message_handler.hpp"
#include "resolve_symbols.hpp"
#include "typedefs.hpp"
#include <cstdint>
#include <memory>
#include <optional>
#include <sys/types.h>

namespace pdfcsp::csp {

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
                   const BytesVector &raw_signature, MessageType msg_type);

  /**
   * @brief Get the Cades Type object
   * @details uses csp cades func
   * @return CadesType ::kCadesBes,::kCadesT, etc...
   */
  [[nodiscard]] CadesType GetCadesType() const noexcept;

  /**
   * @brief Replace function for GetCadesType
   * @details Does not use CadesMsgIsType
   * @param signer_index
   * @return CadesType
   */
  [[nodiscard]] CadesType GetCadesTypeEx(uint signer_index) const noexcept;

  /// @brief get number of signers
  [[nodiscard]] std::optional<uint> GetSignersCount() const noexcept;

  /// @brief get number of revoced certificates
  [[nodiscard]] std::optional<uint> GetRevokedCertsCount() const noexcept;

  /**
   * @brief Get the Signer Cert Id struct
   * @return std::optional<CertificateID>
   */
  [[nodiscard]] std::optional<asn::CertificateID>
  GetSignerCertId(uint signer_index) const noexcept;

  /**
   * @brief Returns the summary of the Comprehensive message check
   * @param data a raw data
   * @param signer_index
   * @param ocsp_check enable/disable an ocsp check
   * @throws runtime error
   */
  [[nodiscard]] bool Check(const BytesVector &data, uint signer_index,
                           bool ocsp_check) const noexcept;
  /**
   * @brief Comprehensive message check
   * @param data a raw data
   * @param signer_index
   * @param ocsp_check enable/disable an ocsp check
   * @returns a CheckResult structure
   */
  [[nodiscard]] checks::CheckResult
  ComprehensiveCheck(const BytesVector &data, uint signer_index,
                     bool ocsp_check) const noexcept;

  /**
   * @brief Check an attached message
   * @details Create a data hash, than performs chech with Check()
   * @param signer_index
   * @param ocsp_check enable/disable ocsp check
   * @throws runtime_error
   */
  [[nodiscard]] bool CheckAttached(uint signer_index, bool ocsp_check) const;

  /**
   * @brief Gets the data hash from signed attributes -
   * szOID_PKCS_9_MESSAGE_DIGEST
   * @param signer_index
   * @return std::optional<BytesVector>
   */
  [[nodiscard]] std::optional<BytesVector>
  GetSignedDataHash(uint signer_index) const noexcept;

  /**
   * @brief Calculate a hash value for data
   * @param hashing_algo
   * @param data
   * @return std::optional<BytesVector>
   */
  [[nodiscard]] std::optional<BytesVector>
  CalculateDataHash(const std::string &hashing_algo,
                    const BytesVector &data) const noexcept;

  /**
   * @brief Calculate a COMPUTED_HASH VALUE from raw data of signed attributes
   * @param signer_index
   * @return std::optional<HashHandler>
   */
  [[nodiscard]] std::optional<HashHandler>
  CalculateComputedHash(uint signer_index) const noexcept;

  /// @brief get a certificate by index
  [[nodiscard]] std::optional<BytesVector>
  GetRawCertificate(uint index) const noexcept;

  /// @brief returns CMSG_ENCRYPTED_DIGEST (signature)
  [[nodiscard]] std::optional<BytesVector>
  GetEncryptedDigest(uint signer_index) const noexcept;

  /// @brief Extracts the eContent of the message
  [[nodiscard]] BytesVector GetContentFromAttached() const;

  /**
   * @brief extracts unsigned attributes from a raw signature
   * @param signer_index
   * @return AsnObj containig unsigned attributes
   * @throws runtime_error
   */
  [[nodiscard]] asn::AsnObj ExtractUnsignedAttributes(uint signer_index) const;

  /**
   * @brief Get the Computed Hash value from CryptoApi
   * @param signer_index
   * @return std::optional<BytesVector>
   */
  [[nodiscard]] std::optional<BytesVector>
  GetComputedHash(uint signer_index) const noexcept;

  /**
   * @brief Calculate a Certificate hash from raw certificate
   * @param signer_index
   * @return std::optional<BytesVector>
   */
  [[nodiscard]] std::optional<HashHandler>
  CalculateCertHash(uint signer_index) const noexcept;

  /**
   * @brief Look for the signer's certificate in the x_long embedded
   * certificates and system store.
   * @param tsp_message
   * @param tsp_signer_index
   * @return std::optional<Certificate>
   */
  [[nodiscard]] std::optional<Certificate>
  FindTspCert(const Message &tsp_message, uint tsp_signer_index) const noexcept;

  /**
   * @brief Set the Explicit Certificate for signer with index
   * @param signer_index
   * @param raw_cert an encoded certificate
   */
  void SetExplicitCertForSigner(uint signer_index,
                                BytesVector raw_cert) noexcept;

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

  /// @brief true if this message is a timestamp
  [[nodiscard]] bool is_tsp_message() const noexcept { return is_tsp_message_; }

  /// @brief treat this message as a timestamp
  void SetIsTspMessage(bool flag) noexcept { is_tsp_message_ = flag; }

  /// @brief number of certificates
  [[nodiscard]] std::optional<uint>
  GetCertCount(uint64_t signer_index) const noexcept;

private:
  /**
   * @brief extracts signed attributes from a raw signature
   * @param signer_index
   * @return BytesVector
   * @throws runtime_error
   */
  [[nodiscard]] BytesVector ExtractRawSignedAttributes(uint signer_index) const;

  /**
   * @brief Decode raw message
   * @param sig a raw signature data
   * @param data a raw signed data
   * @throws std::runtime exception on fail
   */
  void DecodeMessage(const BytesVector &sig);

  /**
   * @brief Throws a runtime_error if res=FALSE
   * @param res
   * @throws std::runtime_error
   */
  void ResCheck(BOOL res, const std::string &msg) const;

  std::shared_ptr<ResolvedSymbols> symbols_;
  MsgDescriptorWrapper msg_handler_;
  BytesVector raw_signature_;
  MessageType msg_type_;
  // signer -> raw signers cert
  ExplicitlySetRawCers raw_certs_;
  bool is_tsp_message_ = false;
  bool is_primitive_pks_ = false;
};

} // namespace pdfcsp::csp