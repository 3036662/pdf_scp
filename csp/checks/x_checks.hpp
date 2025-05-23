/* File: x_checks.hpp
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

#pragma once

#include "t_checks.hpp"
#include "xl_certs.hpp"

namespace pdfcsp::csp::checks {

class XChecks : public TChecks {
 public:
  XChecks(const Message *pmsg, unsigned int signer_index, bool ocsp_online,
          PtrSymbolResolver symbols);

  /// @brief Performs all checks
  /// @param data - a raw pdf data (extacted with a byterange)
  [[nodiscard]] const CheckResult &All(
    const BytesVector &data) noexcept override;

 protected:
  /// @brief check certificate date,chain,ocsp status (optional)
  void CertificateStatus(bool ocsp_enable_check) noexcept override;

 private:
  void SetFatal() noexcept override { res().bres.x_fatal = true; }
  void ResetFatal() noexcept override { res().bres.x_fatal = false; }
  [[nodiscard]] bool Fatal() const noexcept override {
    return res().bres.x_fatal;
  }

  /// @brief Calls all the necessary X_LONG checks.
  void CadesXL1() noexcept;

  /// @brief Checks escTimeStam, the CADES_X timestamp over the CADES_C message.
  void EscTimeStamp(const CryptoAttributesBunch &unsigned_attrs) noexcept;

  /// @brief Extract data from CADES_X attributes.
  /// @details Extracts revocVals,revocRefs,certRefs,revocRefs
  void ExtractXlongData(const CryptoAttributesBunch &unsigned_attrs) noexcept;

  /// @brief Matches all extracted values and checks all OCSP responses and CRL
  /// lists.
  void XDataCheck() noexcept;

  /**
   * @brief Matches each OCSP referense to the corresponding OCSP value
   * @return std::vector<OcspReferenceValuePair>
   * @throws runtime_error
   */
  [[nodiscard]] std::vector<OcspReferenceValuePair>
  MatchOcspRevocRefsToValues();

  /**
   * @brief Matches each CRL referense to the corresponding CRL value
   * @return std::vector<CrlReferenceValuePair>
   * @throws runtime_error
   */
  [[nodiscard]] std::vector<CrlReferenceValuePair> MatchCrlRevocRefsToValues();

  /**
   * @brief Matches each certificate referense to the corresponding certificate
   * @return std::vector<CertReferenceValueIteratorPair>
   * @throws runtime_error
   */
  [[nodiscard]] std::vector<CertReferenceValueIteratorPair>
  MatchCertRefsToValueIterators();

  /**
   * @brief Finds a signer's certificate in XLCertsData
   * @return CertIterator  iterator to signer's certificate
   */
  [[nodiscard]] CertIterator FindSignersCert();

  /**
   * @brief For each OCSP response, find the corresponding certificate and check
   * its status.
   * @param revocation_data std::vector<OcspReferenceValuePair>
   * @param additional_store StoreHandler - the temporary store
   * @param signers_cert iterator to the signer's certificate.
   * @throws runtime_error
   */
  [[nodiscard]] bool CheckAllOcspValues(
    const std::vector<OcspReferenceValuePair> &revocation_data,
    const StoreHandler &additional_store, CertIterator signers_cert);

  /**
   * @brief Parse all revocation lists and look for certificates with matching
   * serial numbers.
   * @param crl_data
   * @param additional_store
   * @param signers_cert
   * @throws runtime_error
   */
  [[nodiscard]] bool CheckAllCrlValues(
    const std::vector<CrlReferenceValuePair> &crl_data,
    const StoreHandler &additional_store, CertIterator signers_cert);

  /**
   * @brief Find a certificate by it's public key SHA1 hash
   * @param sha1 BytesVector with sha1 hash to look for
   * @return CertIterator iterator to the corresponding certificate
   */
  CertIterator FindCertByPublicKeySHA1(const XLCertsData &xdata,
                                       const BytesVector &sha1);

  XLCertsData xdata_;
};

[[nodiscard]] bool CanSignCRL(CertIterator it_cert);

/**
 * @brief Find a certificate by it's public subject name
 * @param responder_name string name
 * @return CertIterator iterator to the corresponding certificate
 */
CertIterator FindCertByResponderName(const XLCertsData &xdata,
                                     const std::string &responder_name);

/**
 * @brief Find a certificate with OCSP signing key by it's public subject name
 * @param responder_name string name
 * @return CertIterator iterator to the corresponding certificate
 */
CertIterator FindOCSPCertByResponderName(const XLCertsData &xdata,
                                         const std::string &responder_name);

/**
 * @brief Find a certificate by it's subject name (simple string repr.)
 * @param simple_name string name
 * @return CertIterator iterator to the corresponding certificate
 */
CertIterator FindCertBySubjectSimpleName(const XLCertsData &xdata,
                                         const std::string &simple_name);

}  // namespace pdfcsp::csp::checks