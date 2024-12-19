/* File: x_checks.cpp  
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


#include "x_checks.hpp"
#include "CSP_WinBase.h"
#include "asn_tsp.hpp"
#include "certificate.hpp"
#include "check_result.hpp"
#include "check_utils.hpp"
#include "message.hpp"
#include "oids.hpp"
#include "store_hanler.hpp"
#include "t_checks.hpp"
#include "typedefs.hpp"
#include "utils.hpp"
#include "utils_cert.hpp"
#include "utils_msg.hpp"
#include "xl_certs.hpp"
#include <algorithm>
#include <boost/json/array.hpp>
#include <exception>
#include <memory>
#include <stdexcept>

namespace pdfcsp::csp::checks {

XChecks::XChecks(const Message *pmsg, unsigned int signer_index,
                 bool ocsp_online, PtrSymbolResolver symbols)
    : TChecks(pmsg, signer_index, ocsp_online, std::move(symbols)), xdata_{} {}

/// @brief Performs all checks
/// @param data - a raw pdf data (extacted with a byterange)
const CheckResult &XChecks::All(const BytesVector &data) noexcept {
  // BesChecks
  SignerIndex();
  CadesTypeFind();
  if (res().cades_type < CadesType::kCadesXLong1) {
    res().bres.cades_type_ok = false;
    SetFatal();
  }
  DecodeCertificate();
  SaveDigest();
  /*
   * Xlong Checks
   * Includes escTimeStamp,ExtractXlongData,XDataCheck
   * XDataCheck contains CheckAllOcspValues,IsChainOK,CheckAllCrlValues
   */
  CadesXL1();
  if (Fatal()) {
    symbols()->log->error("XLONG Checks failed");
    Free();
    return res();
  }
  // TChecks
  CheckAllCadesTStamps();

  DataHash(data);
  ComputedHash();
  CertificateHash();

  /* This method is overrided for time mocking
   * Includes CertificateHasKeyUsageBit,IsTimeValid,IsChainOK,
   * IsOcspStatusOK(online if ocsp_enable_check==true)
   */
  CertificateStatus(ocsp_online());
  Signature();
  FinalDecision();
  if (res().bres.bes_fatal) {
    symbols()->log->error(
        "XLONG Checks can not be performed,because BES checks failed");
    SetFatal();
    Free();
    return res();
  }
  res().bres.check_summary =
      res().bres.bes_all_ok && res().bres.t_all_ok && res().bres.x_all_ok;
  Free();
  xdata_.tmp_store_.reset();
  return res();
}

/// @brief Calls all the necessary X_LONG checks.
void XChecks::CadesXL1() noexcept {
  constexpr const char *const func_name = "[XChecks::CadesXL1] ";
  const auto unsigned_attributes =
      msg()->GetAttributes(signer_index(), AttributesType::kUnsigned);
  if (!unsigned_attributes || unsigned_attributes->get_bunch().empty()) {
    symbols()->log->error("{} Unsigned attributes not found", func_name);
    res().bres.x_esc_tsp_ok = false;
    SetFatal();
    return;
  }
  // check the escTimeStamp
  EscTimeStamp(unsigned_attributes.value());
  if (Fatal()) {
    symbols()->log->error("{} escTimeStamp check failed", func_name);
    res().bres.x_esc_tsp_ok = false;
    return;
  }
  // Extract the XLONG data
  ExtractXlongData(unsigned_attributes.value());
  if (Fatal()) {
    symbols()->log->error("{} Extract XLONG attributes failed", func_name);
    return;
  }
  // XLongCertsCheckResult
  XDataCheck();
  if (Fatal()) {
    symbols()->log->error("{} Check embedded certificates failed", func_name);
    return;
  }
  // summary
  res().bres.x_all_ok =
      res().bres.x_all_cert_refs_have_value &&
      res().bres.x_all_revoc_refs_have_value &&
      res().bres.x_signing_cert_found && res().bres.x_signing_cert_chain_ok &&
      (res().bres.x_singers_cert_has_ocsp_response ||
       res().bres.x_singers_cert_has_crl_response) &&
      res().bres.x_all_ocsp_responses_valid && res().bres.x_all_crls_valid;
  res().bres.x_fatal = !res().bres.x_all_ok;
}

//   The value of the messageImprint field within TimeStampToken shall be
//   a hash of the concatenated values (without the type or length
//   encoding for that value) of the following data objects:
//   - OCTETSTRING of the SignatureValue field within SignerInfo;
//   - signature-time-stamp, or a time-mark operated by a Time-Marking
//    Authority;
//   - complete-certificate-references attribute; and

/// @brief Checks escTimeStamp, the CADES_X timestamp over the CADES_C message.
void XChecks::EscTimeStamp(
    const CryptoAttributesBunch &unsigned_attrs) noexcept {
  constexpr const char *const func_name = "[XChecks::EscTimeStamp] ";
  // if this is tspMessage with xlong fields, but without a timestamp for
  // itself take a time from content
  if (utils::message::CountAttributesWithOid(
          unsigned_attrs, asn::kOid_id_aa_ets_escTimeStamp) == 0) {
    if (msg()->is_tsp_message()) {
      const BytesVector data = msg()->GetContentFromAttached();
      const asn::AsnObj obj(data.data(), data.size());
      const asn::TSTInfo tst(obj);
      auto parsed_time = GeneralizedTimeToTimeT(tst.genTime);
      xdata_.last_timestamp = parsed_time.time + parsed_time.gmt_offset;
      res().bres.x_esc_tsp_ok = true;
      ResetFatal();
      return;
    }
    symbols()->log->error("{} No escTimeStamp found", func_name);
    res().bres.x_esc_tsp_ok = false;
    SetFatal();
    return;
  }
  // calculate a value for hashing to compare with TSP imprint
  BytesVector val_for_hashing;
  {
    const asn::AsnObj attrs = msg()->ExtractUnsignedAttributes(signer_index());
    // 1. signature value
    auto digest = msg()->GetEncryptedDigest(signer_index());
    if (digest) {
      std::copy(digest.value().cbegin(), digest.value().cend(),
                std::back_inserter(val_for_hashing));
    }
    // 2. TimeStamp from CADES_C
    utils::message::CopyRawAttributeExceptAsnHeader(
        attrs, asn::kOID_id_aa_signatureTimeStampToken, val_for_hashing);
    // 3. Certificate references
    utils::message::CopyRawAttributeExceptAsnHeader(
        attrs, asn::kOID_id_aa_ets_certificateRefs, val_for_hashing);
    // 4. Revocation references
    utils::message::CopyRawAttributeExceptAsnHeader(
        attrs, asn::kOID_id_aa_ets_revocationRefs, val_for_hashing);
  }
  // for each escTimeStamp
  for (const auto &tsp_attr : unsigned_attrs.get_bunch()) {
    if (tsp_attr.get_id() != asn::kOid_id_aa_ets_escTimeStamp) {
      continue;
    }
    const CheckOneCadesTSPResult esc_tsp_check_res =
        CheckOneCadesTStmap(tsp_attr, val_for_hashing);
    if (!esc_tsp_check_res.result) {
      symbols()->log->error("{} escTimeStamp is not valid", func_name);
      SetFatal();
      res().bres.x_esc_tsp_ok = false;
      return;
    }
  }
  // find the time of last timestamp
  auto it_max_time =
      std::max_element(times_collection().cbegin(), times_collection().cend());
  if (it_max_time == times_collection().cend()) {
    symbols()->log->error("{} cant find last timestamp", func_name);
    SetFatal();
    res().bres.x_esc_tsp_ok = false;
    return;
  }
  xdata_.last_timestamp = *it_max_time;
  ResetFatal();
  res().bres.x_esc_tsp_ok = true;
  res().x_times_collection = times_collection();
  times_collection().clear();
}

/// @brief Extract data from CADES_X attributes.
/// @details Extracts revocVals,revocRefs,certRefs,revocRefs
void XChecks::ExtractXlongData(
    const CryptoAttributesBunch &unsigned_attrs) noexcept {
  constexpr const char *const func_name = "[XChecks::ExtractXlongData] ";
  try {
    // parse certificateRefs - all the certificates present in the certification
    // path used for verifying the signature.
    xdata_.cert_refs = utils::message::ExtractCertRefs(unsigned_attrs);
    symbols()->log->info("{} number of certificate references = {}", func_name,
                         xdata_.cert_refs.size());
    // parse revocationRefs - The complete-revocation-references
    // attribute contains references to the CRLs and/or OCSPs responses used
    // for verifying the signature.
    xdata_.revoc_refs = utils::message::ExtractRevocRefs(unsigned_attrs);
    symbols()->log->info("{} number of revoc references = {}", func_name,
                         xdata_.revoc_refs.size());
    // extract certificates - contains the whole
    // certificate path required for verifying the signature;
    xdata_.cert_vals =
        utils::message::ExtractCertVals(unsigned_attrs, symbols());
    symbols()->log->info("{} certifates extracted {}", func_name,
                         xdata_.cert_vals.size());
    // extract revocationValues -
    // contains the CRLs and/OCSP responses required for the validation of
    //  the signature.
    {
      auto revoc_vals_blob =
          unsigned_attrs.GetAttrBlobByID(asn::kOID_id_aa_ets_revocationValues);
      const asn::AsnObj revoc_vals_asn(revoc_vals_blob.data(),
                                       revoc_vals_blob.size());
      xdata_.revoc_vals = asn::RevocationValues(revoc_vals_asn);
    }
    {
      auto signers_cert_id = msg()->GetSignerCertId(signer_index());
      if (!signers_cert_id) {
        throw std::runtime_error("no signer's cert found");
      }
      xdata_.signers_cert = signers_cert_id.value();
    }

  } catch (const std::exception &ex) {
    symbols()->log->error("{} {}", func_name, ex.what());
    SetFatal();
    res().bres.x_data_ok = false;
    return;
  }
  res().bres.x_data_ok = true;
  ResetFatal();
}

/// @brief Matches all extracted values and checks all OCSP responses and CRL
/// lists.
void XChecks::XDataCheck() noexcept {
  try {
    // match OCSP references -> OCSP response values
    const std::vector<OcspReferenceValuePair> revocation_data =
        MatchOcspRevocRefsToValues();
    // match CRL references -> CRL values
    const std::vector<CrlReferenceValuePair> crl_data =
        MatchCrlRevocRefsToValues();
    // check if all referenced revocation values where found
    res().bres.x_all_revoc_refs_have_value =
        xdata_.revoc_refs.size() == revocation_data.size() + crl_data.size();
    // match all certificate values
    const std::vector<CertReferenceValueIteratorPair> certs_data =
        MatchCertRefsToValueIterators();
    res().bres.x_all_cert_refs_have_value =
        certs_data.size() == xdata_.cert_refs.size();
    // find the signer's certificate
    auto it_signers_cert = FindSignersCert();
    res().bres.x_signing_cert_found =
        it_signers_cert != xdata_.cert_vals.cend();
    res().bres.x_signers_cert_is_ca =
        utils::cert::CertificateIsCA(it_signers_cert->GetContext());
    if (!res().bres.x_all_revoc_refs_have_value ||
        !res().bres.x_all_cert_refs_have_value ||
        !res().bres.x_signing_cert_found) {
      throw std::runtime_error(
          "Not all values for the referenced data were found.");
    }
    // create a temporary storage for certs
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-cstyle-cast)
    xdata_.tmp_store_ = std::make_unique<StoreHandler>(CERT_STORE_PROV_MEMORY,
                                                       0, nullptr, symbols());
    // add all certificates to store
    if (res().bres.x_signing_cert_found) {
      xdata_.tmp_store_->AddCertificate(*it_signers_cert);
    }
    for (const auto &cert_pair : certs_data) {
      if (cert_pair.second != xdata_.cert_vals.cend()) {
        xdata_.tmp_store_->AddCertificate(*cert_pair.second);
      }
    }
    // check all responses
    res().bres.x_all_ocsp_responses_valid = CheckAllOcspValues(
        revocation_data, *xdata_.tmp_store_, it_signers_cert);
    symbols()->log->info(
        "Check all revoces ...{}",
        (res().bres.x_all_ocsp_responses_valid ? "OK" : "FAILED"));
    //  check a signer's certificate chain
    if (res().bres.x_signing_cert_found) {
      FILETIME time_to_check_chain = TimetToFileTime(xdata_.last_timestamp);
      // if the certificate is expired now, ignore revocation check errors
      const bool ignore_revoc_check_errors_for_expired =
          !it_signers_cert->IsTimeValid();
      res().bres.x_signing_cert_chain_ok = it_signers_cert->IsChainOK(
          &time_to_check_chain, xdata_.tmp_store_->RawHandler(),
          ignore_revoc_check_errors_for_expired);
    }
    if (res().bres.x_signing_cert_chain_ok) {
      symbols()->log->info("Signers certificate chain OK");
    }
    // check CRLS
    if (res().bres.x_signing_cert_found) {
      res().bres.x_all_crls_valid =
          CheckAllCrlValues(crl_data, *xdata_.tmp_store_, it_signers_cert);
    }

  } catch (const std::exception &ex) {
    symbols()->log->error("[XDataCheck] {}", ex.what());
    SetFatal();
    return;
  }
}

/**
 * @brief Matches each revocation reference to the coressponding OCSP response
 * @return std::vector<OcspReferenceValuePair>
 * @throws runtime_error
 */
std::vector<OcspReferenceValuePair> XChecks::MatchOcspRevocRefsToValues() {
  std::vector<OcspReferenceValuePair> res;
  for (const auto &ocsp_ref : xdata_.revoc_refs) {
    if (ocsp_ref.ocspids.has_value()) {
      for (const auto &ocsp_resp_id : ocsp_ref.ocspids.value()) {
        const auto &responder_hash =
            ocsp_resp_id.ocspIdentifier.ocspResponderID_hash;
        const auto &responder_name =
            ocsp_resp_id.ocspIdentifier.ocspResponderID_name;
        const auto &responder_time = ocsp_resp_id.ocspIdentifier.producedAt;
        auto opt_other_hash = ocsp_resp_id.ocspRepHash;
        if (!opt_other_hash) {
          throw std::runtime_error(
              "no hashing algo is defined for OcspResonseID");
        }
        const auto other_hash =
            std::get<asn::OtherHashAlgAndValue>(opt_other_hash.value());
        const std::string &hashing_algo = other_hash.hashAlgorithm.algorithm;
        const BytesVector &hash_val = other_hash.hashValue;
        const auto it_val = std::find_if(
            xdata_.revoc_vals.ocspVals.cbegin(),
            xdata_.revoc_vals.ocspVals.cend(),
            [&responder_hash, &responder_name,
             &responder_time](const asn::BasicOCSPResponse &resp) {
              return responder_hash == resp.tbsResponseData.responderID_hash &&
                     responder_name == resp.tbsResponseData.responderID_name &&
                     responder_time == resp.tbsResponseData.producedAt;
            });
        // found a match - compare a hash
        if (it_val != xdata_.revoc_vals.ocspVals.cend()) {
          HashHandler tmp_hash(hashing_algo, symbols());
          tmp_hash.SetData(it_val->der_encoded);
          if (hash_val != tmp_hash.GetValue()) {
            continue;
          }
          // the hash matched
          res.emplace_back(ocsp_resp_id, *it_val);
        }
      }
    }
  }
  return res;
}

/**
 * @brief Matches each CRL referense to the corresponding CRL value
 * @return std::vector<CrlReferenceValuePair>
 * @throws runtime_error
 */
std::vector<CrlReferenceValuePair> XChecks::MatchCrlRevocRefsToValues() {
  std::vector<CrlReferenceValuePair> res;
  constexpr const char *const expl_unsupported_hash_algo =
      "[MatchCrlRevocRefsToValues] unsupported hash type";
  for (const auto &crl_ref : xdata_.revoc_refs) {
    if (crl_ref.crlids.has_value()) {
      for (const auto &crl_id : crl_ref.crlids.value()) {
        if (!std::holds_alternative<asn::OtherHashAlgAndValue>(
                crl_id.crlHash)) {
          throw std::runtime_error(expl_unsupported_hash_algo);
        }
        const auto &crl_hash =
            std::get<asn::OtherHashAlgAndValue>(crl_id.crlHash);
        if (crl_hash.hashAlgorithm.algorithm.empty() ||
            crl_hash.hashValue.empty()) {
          throw std::runtime_error(
              "[MatchCrlRevocRefsToValues] empty hash algo or value");
        }
        const auto &hashing_algo = crl_hash.hashAlgorithm.algorithm;
        if (!IsHashAlgoSupported(hashing_algo)) {
          throw std::runtime_error(expl_unsupported_hash_algo);
        }
        const auto &hash_val = crl_hash.hashValue;
        auto it_crl_val =
            std::find_if(xdata_.revoc_vals.crlVals.cbegin(),
                         xdata_.revoc_vals.crlVals.cend(),
                         [&hashing_algo, &hash_val,
                          this](const asn::CertificateList &cert_list) {
                           HashHandler tmp_hash(hashing_algo, symbols());
                           tmp_hash.SetData(cert_list.der_encoded);
                           return tmp_hash.GetValue() == hash_val;
                         });
        if (it_crl_val != xdata_.revoc_vals.crlVals.cend()) {
          res.emplace_back(crl_id, *it_crl_val);
        }
      }
    }
  }
  return res;
}

/**
 * @brief Matches each certificate referense to the corresponding certificate
 * @return std::vector<CertReferenceValueIteratorPair>
 * @throws runtime_error
 */
std::vector<CertReferenceValueIteratorPair>
XChecks::MatchCertRefsToValueIterators() {
  std::vector<CertReferenceValueIteratorPair> res;
  for (const auto &cert_ref : xdata_.cert_refs) {
    if (std::holds_alternative<asn::OtherHashAlgAndValue>(
            cert_ref.otherCertHash)) {
      const auto &hash_and_val =
          std::get<asn::OtherHashAlgAndValue>(cert_ref.otherCertHash);
      const std::string &hash_algo = hash_and_val.hashAlgorithm.algorithm;
      const BytesVector &hash_val = hash_and_val.hashValue;
      // find a corresponding certificate in xdata
      auto it_cert_val = std::find_if(
          xdata_.cert_vals.cbegin(), xdata_.cert_vals.cend(),
          [&hash_algo, &hash_val, this](const Certificate &cert_val) {
            HashHandler tmp_hash(hash_algo, symbols());
            tmp_hash.SetData(cert_val.GetRawCopy());
            return hash_val == tmp_hash.GetValue();
          });
      if (it_cert_val != xdata_.cert_vals.cend()) {
        res.emplace_back(cert_ref, it_cert_val);
      }
    }
  }
  return res;
}

/**
 * @brief Finds a signer's certificate in XLCertsData
 * @return CertIterator  iterator to signer's certificate
 */
CertIterator XChecks::FindSignersCert() {
  return std::find_if(
      xdata_.cert_vals.cbegin(), xdata_.cert_vals.cend(),
      [this](const Certificate &cert) {
        if (xdata_.signers_cert.serial == cert.Serial()) {
          HashHandler tmp_hash(xdata_.signers_cert.hashing_algo_oid, symbols());
          tmp_hash.SetData(cert.GetRawCopy());
          return xdata_.signers_cert.hash_cert == tmp_hash.GetValue();
        }
        return false;
      });
}

/**
 * @brief For each OCSP response, find the corresponding certificate and check
 * its status.
 * @param revocation_data std::vector<OcspReferenceValuePair>
 * @param additional_store StoreHandler - the temporary store
 * @param signers_cert iterator to the signer's certificate.
 * @throws runtime_error
 */
bool XChecks::CheckAllOcspValues(
    const std::vector<OcspReferenceValuePair> &revocation_data,
    const StoreHandler &additional_store, CertIterator signers_cert) {
  symbols()->log->info("total ocsp vals number = {}", revocation_data.size());
  boost::json::array ocsp_info; // resulting ocsp info for the signer's cert
  for (const auto &revoc_pair : revocation_data) {
    // find the ocsp certificate hash (sha1)
    auto ocsp_cert_hash = revoc_pair.second.tbsResponseData.responderID_hash;
    auto ocsp_cert_name = revoc_pair.second.tbsResponseData.responderID_name;
    if (!ocsp_cert_hash && !ocsp_cert_name) {
      return false;
    }
    // find the ocsp certificate in certVals
    auto it_ocsp_cert = xdata_.cert_vals.cend();
    if (ocsp_cert_hash && !ocsp_cert_hash->empty()) {
      it_ocsp_cert = FindCertByPublicKeySHA1(xdata_, ocsp_cert_hash.value());
    } else if (ocsp_cert_name && !ocsp_cert_name->empty()) {
      // look for certificate with expected name and OCSP signing key
      it_ocsp_cert =
          FindOCSPCertByResponderName(xdata_, ocsp_cert_name.value());
    }
    if (it_ocsp_cert == xdata_.cert_vals.cend()) {
      return false;
    }

    // params for Certificate::IsOcspOk
    const OcspCheckParams ocsp_check_params{
        &revoc_pair.second, &(*it_ocsp_cert), &xdata_.last_timestamp,
        &additional_store};
    for (const auto &response : revoc_pair.second.tbsResponseData.responses) {
      // find corresponding cert for the OCSP response
      auto cert_it =
          std::find_if(xdata_.cert_vals.cbegin(), xdata_.cert_vals.cend(),
                       [&response](const Certificate &cert) {
                         return cert.Serial() == response.certID.serialNumber;
                       });
      if (cert_it == xdata_.cert_vals.cend()) {
        symbols()->log->error("no cert found for an OCSP response");
        return false;
      }
      symbols()->log->info("Found subject cert for the OCSP response");
      // check the ocsp response for this cert
      if (!cert_it->IsOcspStatusOK(ocsp_check_params)) {
        symbols()->log->error("ocsp status is bad");
        return false;
      }
      // save ocsp info for the signer's certificate
      if (cert_it == signers_cert) {
        ocsp_info.push_back(
            check_utils::BuildJsonOCSPResult(ocsp_check_params));
        res().bres.x_singers_cert_has_ocsp_response = true;
        res().bres.certificate_ocsp_ok = true;
      }
    }
  }
  res().signers_cert_ocsp_json_info = boost::json::serialize(ocsp_info);
  return true;
}

/**
 * @brief Parse all revocation lists and look for certificates with matching
 * serial numbers.
 * @param crl_data
 * @param additional_store
 * @param signers_cert
 * @throws runtime_error
 */
[[nodiscard]] bool XChecks::CheckAllCrlValues(          // NOLINT
    const std::vector<CrlReferenceValuePair> &crl_data, // NOLINT
    const StoreHandler &additional_store, CertIterator signers_cert) {
  const std::string func_name = "[XChecks::CheckAllCrlValues] ";
  symbols()->log->info("{} number of crls", func_name, crl_data.size());
  if (crl_data.empty()) {
    return true;
  }
  BytesVector root_serial;
  // find the root certificate
  PCCERT_CHAIN_CONTEXT p_chain_context = nullptr;
  try {
    FILETIME time_to_check_chain = TimetToFileTime(xdata_.last_timestamp);
    p_chain_context = utils::cert::CreateCertChain(
        signers_cert->GetContext(), symbols(), &time_to_check_chain,
        additional_store.RawHandler());
    const auto *root_cert =
        utils::cert::GetRootCertificateCtxFromChain(p_chain_context);
    if (root_cert != nullptr) {
      root_serial = BytesVector(root_cert->pCertInfo->SerialNumber.pbData,
                                root_cert->pCertInfo->SerialNumber.pbData +
                                    root_cert->pCertInfo->SerialNumber.cbData);
      std::reverse(root_serial.begin(), root_serial.end());
    }
  } catch (const std::exception &ex) {
    utils::cert::FreeChainContext(p_chain_context, symbols());
    symbols()->log->error("{} {}", func_name, ex.what());
    return false;
  }
  utils::cert::FreeChainContext(p_chain_context, symbols());
  auto it_root_cert =
      std::find_if(xdata_.cert_vals.cbegin(), xdata_.cert_vals.cend(),
                   [&root_serial](const Certificate &cert) {
                     return cert.Serial() == root_serial;
                   });

  if (it_root_cert == xdata_.cert_vals.cend()) {
    symbols()->log->error("Root certificate was not found");
    return false;
  }

  for (const auto &crl_pair : crl_data) {
    const asn::CertificateList &crl = crl_pair.second;
    // find the certificate of crl issuer
    auto it_crl_issuer_cert =
        crl_pair.first.crlIdentifier.has_value()
            ? FindCertBySubjectSimpleName(
                  xdata_, crl_pair.first.crlIdentifier->crlissuer)
            : xdata_.cert_vals.cend();
    if (it_crl_issuer_cert == xdata_.cert_vals.cend()) {
      symbols()->log->warn("crl issuer cert was not found,using chain root");
      it_crl_issuer_cert = it_root_cert;
    }
    if (!CanSignCRL(it_crl_issuer_cert)) {
      return false;
    }
    // if crl issuer == signer's certificate issuer
    if (it_crl_issuer_cert->DecomposedSubjectName().DistinguishedName() ==
        signers_cert->DecomposedIssuerName().DistinguishedName()) {
      res().bres.x_singers_cert_has_crl_response = true;
    }
    // check the signature
    if (crl.signatureAlgorithm.algorithm != szOID_CP_GOST_R3411_12_256_R3410) {
      throw std::runtime_error(func_name + "unsupported signature algorithm");
    }
    HashHandler hash(szOID_CP_GOST_R3411_12_256, symbols());
    hash.SetData(crl.tbsCertList.der_encoded);
    // import public key
    HCRYPTKEY handler_pub_key = 0;
    CERT_PUBLIC_KEY_INFO *p_ocsp_public_key_info =
        &it_crl_issuer_cert->GetContext()->pCertInfo->SubjectPublicKeyInfo;
    ResCheck(symbols()->dl_CryptImportPublicKeyInfo(
                 hash.get_csp_hanler(), PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
                 p_ocsp_public_key_info, &handler_pub_key),
             "CryptImportPublicKeyInfo", symbols());

    if (handler_pub_key == 0) {
      throw std::runtime_error("Import public key failed");
    }
    // verify signature
    BytesVector signature = crl.signatureValue;
    std::reverse(signature.begin(), signature.end());
    //  delete last 0 byte from signature
    signature.pop_back();
    const BOOL sig_verify_res = symbols()->dl_CryptVerifySignatureA(
        hash.get_hash_handler(), signature.data(), signature.size(),
        handler_pub_key, nullptr, 0);
    symbols()->log->info("CRL signature check ... {}",
                         (sig_verify_res == TRUE ? "OK" : "FALSE"));
    if (sig_verify_res != TRUE) {
      return false;
    }
    // If any of the certificates are revoced, return false.
    for (const auto &revoced_cert : crl.tbsCertList.revokedCertificates) {
      const auto revoc_date_parsed = // NOLINT
          UTCTimeToTimeT(revoced_cert.revocationDate);
      const time_t revoc_time_stamp =
          revoc_date_parsed.time + revoc_date_parsed.gmt_offset;
      // certVals to result
      if (revoc_time_stamp <= xdata_.last_timestamp &&
          std::any_of(xdata_.cert_vals.cbegin(), xdata_.cert_vals.cend(),
                      [&revoced_cert, this](const Certificate &cert) {
                        if (cert.Serial() == revoced_cert.userCertificate) {
                          res().revoced_cers_serials.push_back(
                              revoced_cert.userCertificate);
                          return true;
                        }
                        return false;
                      })) {
        return false;
      }
    }
  }
  return true;
}

/**
 * @brief Find a certificate by it's public key SHA1 hash
 * @param sha1 BytesVector with sha1 hash to look for
 * @return CertIterator iterator to the corresponding certificate
 */
CertIterator XChecks::FindCertByPublicKeySHA1(const XLCertsData &xdata,
                                              const BytesVector &sha1) {
  return std::find_if(xdata.cert_vals.cbegin(), xdata.cert_vals.cend(),
                      [&sha1, this](const Certificate &cert) {
                        HashHandler tmp_hash("SHA1", symbols());
                        tmp_hash.SetData(cert.PublicKey());
                        return sha1 == tmp_hash.GetValue();
                      });
}

void XChecks::CertificateStatus(bool ocsp_enable_check) noexcept {
  res().bres.certificate_ok = false;
  if (Fatal()) {
    return;
  }
  constexpr const char *const func_name = "[XChecks::CertificateStatus] ";
  const auto &opt_signers_cert = signers_cert();
  if (!opt_signers_cert) {
    symbols()->log->error("{} An empty signers certificate value", func_name);
    SetFatal();
    return;
  }

  res().bres.certificate_usage_signing = false;
  FILETIME *p_ftime = nullptr;
  try {
    // save the certificate info
    res().cert_issuer = opt_signers_cert->DecomposedIssuerName();
    res().cert_subject = opt_signers_cert->DecomposedSubjectName();
    res().cert_public_key = opt_signers_cert->PublicKey();

    FILETIME ftime{};
    if (xdata_.last_timestamp != 0) {
      ftime = TimetToFileTime(xdata_.last_timestamp);
      p_ftime = &ftime;
    }
    if (!opt_signers_cert->IsTimeValid(p_ftime)) {
      symbols()->log->error("{} Invaid certificate time for signer {}",
                            func_name, signer_index());
      SetFatal();
      return;
    }
    res().bres.certificate_time_ok = true;
    // check if it is suitable for signing
    if (!utils::cert::CertificateHasKeyUsageBit(opt_signers_cert->GetContext(),
                                                0)) {
      symbols()->log->error("{} The certificate is not suitable for signing",
                            func_name);
      SetFatal();
      return;
    }
    res().bres.certificate_usage_signing = true;
  } catch (const std::exception &ex) {
    symbols()->log->error("{} {}", func_name, ex.what());
    SetFatal();
    return;
  }
  // if the certificate is expired now, ignore revocation check errors
  const bool ignore_revoc_check_errors_for_expired =
      !opt_signers_cert->IsTimeValid();
  res().signers_chain_json = opt_signers_cert->ChainInfo(
      p_ftime, xdata_.tmp_store_ ? xdata_.tmp_store_->RawHandler() : nullptr,
      ignore_revoc_check_errors_for_expired);
  // check the certificate chain
  if (!opt_signers_cert->IsChainOK(
          p_ftime,
          xdata_.tmp_store_ ? xdata_.tmp_store_->RawHandler() : nullptr,
          ignore_revoc_check_errors_for_expired)) {
    symbols()->log->error("{} The certificate chain status is not ok",
                          func_name);
    SetFatal();
    return;
  }
  res().bres.certificate_chain_ok = true;
  try {
    res().bres.ocsp_online_used = ocsp_enable_check;
    symbols()->log->info("Last timestamp {}", xdata_.last_timestamp);
    // mock time and add store, but don't mock response to get it from server
    const OcspCheckParams params{nullptr, nullptr, &xdata_.last_timestamp,
                                 xdata_.tmp_store_ ? xdata_.tmp_store_.get()
                                                   : nullptr};
    // if online ocsp request is enabled
    if (ocsp_enable_check && !opt_signers_cert->IsOcspStatusOK(params)) {
      symbols()->log->error("{} OCSP status is not ok", func_name);
      res().bres.certificate_ocsp_ok = false;
      return; // not fatal
    }
    // when no ocsp connection
  } catch (const std::exception &ex) {
    symbols()->log->error("{} {}", func_name, ex.what());
    res().bres.certificate_ocsp_check_failed = true;
    // not fatal
  }
  if (ocsp_enable_check) {
    res().bres.certificate_ocsp_ok = true;
  }
  res().bres.certificate_ok =
      res().bres.certificate_usage_signing && res().bres.certificate_chain_ok &&
      res().bres.certificate_hash_ok &&
      (!ocsp_enable_check || (res().bres.certificate_ocsp_ok ||
                              res().bres.certificate_ocsp_check_failed)) &&
      res().bres.certificate_time_ok;
  res().bres.bes_fatal = !res().bres.certificate_ok;
}

bool CanSignCRL(CertIterator it_cert) {
  // check for signing crls key Usage
  const bool has_singing_crl_bit =
      utils::cert::CertificateHasKeyUsageBit(it_cert->GetContext(), 6);
  //  const bool is_CA = utils::cert::CertificateIsCA(it_cert->GetContext());
  return has_singing_crl_bit;
}

/**
 * @brief Find a certificate by it's public subject name
 * @param responder_name string name
 * @return CertIterator iterator to the corresponding certificate
 */
CertIterator FindCertByResponderName(const XLCertsData &xdata,
                                     const std::string &responder_name) {
  return std::find_if(
      xdata.cert_vals.cbegin(), xdata.cert_vals.cend(),
      [&responder_name](const Certificate &cert) {
        return cert.DecomposedSubjectName().DistinguishedName() ==
               responder_name;
      });
}

/**
 * @brief Find a certificate with OCSP signing key by it's public subject name
 * @param responder_name string name
 * @return CertIterator iterator to the corresponding certificate
 */
CertIterator FindOCSPCertByResponderName(const XLCertsData &xdata,
                                         const std::string &responder_name) {
  return std::find_if(
      xdata.cert_vals.cbegin(), xdata.cert_vals.cend(),
      [&responder_name](const Certificate &cert) {
        return cert.DecomposedSubjectName().DistinguishedName() ==
                   responder_name &&
               utils::cert::CertificateHasExtendedKeyUsage(
                   cert.GetContext(), asn::kOID_id_kp_OCSPSigning);
      });
}

CertIterator FindCertBySubjectSimpleName(const XLCertsData &xdata,
                                         const std::string &simple_name) {
  return std::find_if(xdata.cert_vals.cbegin(), xdata.cert_vals.cend(),
                      [&simple_name](const Certificate &cert) {
                        return cert.DecomposedSubjectName().SimpleString() ==
                               simple_name;
                      });
}

} // namespace pdfcsp::csp::checks