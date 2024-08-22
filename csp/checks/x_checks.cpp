#include "x_checks.hpp"
#include "asn_tsp.hpp"
#include "oids.hpp"
#include "store_hanler.hpp"
#include "t_checks.hpp"
#include "utils.hpp"
#include "utils_cert.hpp"
#include "utils_msg.hpp"
#include "xl_certs.hpp"
#include <algorithm>
#include <exception>
#include <iostream>
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
    res().cades_type_ok = false;
    SetFatal();
  }
  DataHash(data);
  ComputedHash();
  CertificateHash();
  CertificateStatus(ocsp_online());
  Signature();
  FinalDecision();
  if (res().bes_fatal) {
    std::cerr
        << "XLONG Checks can not be performed,because BES checks failed\n";
    SetFatal();
    Free();
    return res();
  }
  // Xlong Checks
  CadesXL1();
  // TChecks
  if (Fatal()) {
    std::cerr << "XLONG Checks failed\n";
    Free();
    return res();
  }
  CheckAllCadesTStamps();
  res().check_summary = res().bes_all_ok && res().t_all_ok && res().x_all_ok;
  Free();
  return res();
}

/// @brief Calls all the necessary X_LONG checks.
void XChecks::CadesXL1() noexcept {
  constexpr const char *const func_name = "[XChecks::CadesXL1] ";
  const auto unsigned_attributes =
      msg()->GetAttributes(signer_index(), AttributesType::kUnsigned);
  if (!unsigned_attributes || unsigned_attributes->get_bunch().empty()) {
    std::cerr << func_name << "Unsigned attributes not found\n";
    res().x_esc_tsp_ok = false;
    SetFatal();
    return;
  }
  // check the escTimeStamp
  EscTimeStamp(unsigned_attributes.value());
  if (Fatal()) {
    std::cerr << func_name << "escTimeStamp check failed\n";
    res().x_esc_tsp_ok = false;
    return;
  }
  // Extract the XLONG data
  ExtractXlongData(unsigned_attributes.value());
  if (Fatal()) {
    std::cerr << func_name << "Extract XLONG attributes failed\n";
    return;
  }
  // XLongCertsCheckResult
  XDataCheck();
  if (Fatal()) {
    std::cerr << func_name << "Check embedded certificates failed\n";
    return;
  }
  // summary
  res().x_all_ok =
      res().x_all_cert_refs_have_value && res().x_all_revoc_refs_have_value &&
      res().x_signing_cert_found && res().x_signing_cert_chain_ok &&
      res().x_singers_cert_has_ocsp_response &&
      res().x_all_ocsp_responses_valid && res().x_all_crls_valid;
  res().x_fatal = !res().x_all_ok;
}

//   The value of the messageImprint field within TimeStampToken shall be
//   a hash of the concatenated values (without the type or length
//   encoding for that value) of the following data objects:
//   - OCTETSTRING of the SignatureValue field within SignerInfo;
//   - signature-time-stamp, or a time-mark operated by a Time-Marking
//    Authority;
//   - complete-certificate-references attribute; and

/// @brief Checks escTimeStam, the CADES_X timestamp over the CADES_C message.
void XChecks::EscTimeStamp(
    const CryptoAttributesBunch &unsigned_attrs) noexcept {
  constexpr const char *const func_name = "[XChecks::EscTimeStamp] ";
  // if this is tspMessage with xlong fields, but without a timestamp for
  // itself take a time from content
  if (CountAttributesWithOid(unsigned_attrs,
                             asn::kOid_id_aa_ets_escTimeStamp) == 0) {
    if (msg()->is_tsp_message_) {
      const BytesVector data = msg()->GetContentFromAttached();
      const asn::AsnObj obj(data.data(), data.size());
      const asn::TSTInfo tst(obj);
      auto parsed_time = GeneralizedTimeToTimeT(tst.genTime);
      xdata_.last_timestamp = parsed_time.time + parsed_time.gmt_offset;
      res().x_esc_tsp_ok = true;
      ResetFatal();
      return;
    }
    std::cerr << func_name << "No escTimeStamp found\n";
    res().x_esc_tsp_ok = false;
    SetFatal();
    return;
  }
  // calculate a value for hashing to compare with TSP imprint
  BytesVector val_for_hashing;
  {
    const asn::AsnObj attrs = msg()->ExtractUnsignedAttributes(signer_index());
    // 1. signature value
    std::reverse_copy(res().encrypted_digest.cbegin(),
                      res().encrypted_digest.cend(),
                      std::back_inserter(val_for_hashing));
    // 2. TimeStamp from CADES_C
    CopyRawAttributeExceptAsnHeader(
        attrs, asn::kOID_id_aa_signatureTimeStampToken, val_for_hashing);
    // 3. Certificate references
    CopyRawAttributeExceptAsnHeader(attrs, asn::kOID_id_aa_ets_certificateRefs,
                                    val_for_hashing);
    // 4. Revocation references
    CopyRawAttributeExceptAsnHeader(attrs, asn::kOID_id_aa_ets_revocationRefs,
                                    val_for_hashing);
  }
  // for each escTimeStamp
  for (const auto &tsp_attr : unsigned_attrs.get_bunch()) {
    if (tsp_attr.get_id() != asn::kOid_id_aa_ets_escTimeStamp) {
      continue;
    }
    if (!CheckOneCadesTStmap(tsp_attr, val_for_hashing)) {
      std::cerr << func_name << "escTimeStamp is not valid\n";
      SetFatal();
      res().x_esc_tsp_ok = false;
      return;
    }
  }
  // find the time of last timestamp
  auto it_max_time =
      std::max_element(times_collection().cbegin(), times_collection().cend());
  if (it_max_time == times_collection().cend()) {
    std::cerr << "cant find last timestamp\n";
    SetFatal();
    res().x_esc_tsp_ok = false;
    return;
  }
  xdata_.last_timestamp = *it_max_time;
  ResetFatal();
  res().x_esc_tsp_ok = true;
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
    xdata_.cert_refs = ExtractCertRefs(unsigned_attrs);
    std::cout << "number of certificate references = "
              << xdata_.cert_refs.size() << "\n";
    // parse revocationRefs - The complete-revocation-references
    // attribute contains references to the CRLs and/or OCSPs responses used
    // for verifying the signature.
    xdata_.revoc_refs = ExtractRevocRefs(unsigned_attrs);
    std::cout << "number of revoc references =" << xdata_.revoc_refs.size()
              << "\n";
    // extract certificates - contains the whole
    // certificate path required for verifying the signature;
    xdata_.cert_vals = ExtractCertVals(unsigned_attrs, symbols());
    std::cout << "certifates extracted " << xdata_.cert_vals.size() << "\n";
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
    std::cerr << func_name << ex.what() << "\n";
    SetFatal();
    res().x_data_ok = false;
    return;
  }
  res().x_data_ok = true;
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
    res().x_all_revoc_refs_have_value =
        xdata_.revoc_refs.size() == revocation_data.size() + crl_data.size();
    // match all certificate values
    const std::vector<CertReferenceValueIteratorPair> certs_data =
        MatchCertRefsToValueIterators();
    res().x_all_cert_refs_have_value =
        certs_data.size() == xdata_.cert_refs.size();
    // find the signer's certificate
    auto it_signers_cert = FindSignersCert();
    res().x_signing_cert_found = it_signers_cert != xdata_.cert_vals.cend();
    if (!res().x_all_revoc_refs_have_value ||
        !res().x_all_cert_refs_have_value || !res().x_signing_cert_found) {
      throw std::runtime_error(
          "Not all values for the referenced data were found.");
    }
    // create a temporary storage for certs
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-cstyle-cast)
    StoreHandler tmp_store(CERT_STORE_PROV_MEMORY, 0, nullptr, symbols());
    // add all certificates to store
    if (res().x_signing_cert_found) {
      tmp_store.AddCertificate(*it_signers_cert);
    }
    for (const auto &cert_pair : certs_data) {
      if (cert_pair.second != xdata_.cert_vals.cend()) {
        tmp_store.AddCertificate(*cert_pair.second);
      }
    }
    // check all responses
    res().x_all_ocsp_responses_valid =
        CheckAllOcspValues(revocation_data, tmp_store, it_signers_cert);
    std::cout << "Check all revoces ..."
              << (res().x_all_ocsp_responses_valid ? "OK" : "FAILED") << "\n";
    //  check a signer's certificate chain
    if (res().x_signing_cert_found) {
      FILETIME time_to_check_chain = TimetToFileTime(xdata_.last_timestamp);
      res().x_signing_cert_chain_ok = it_signers_cert->IsChainOK(
          &time_to_check_chain, tmp_store.RawHandler());
    }
    if (res().x_signing_cert_chain_ok) {
      std::cout << "signers certificate chain OK\n";
    }
    // check CRLS
    if (res().x_signing_cert_found) {
      res().x_all_crls_valid =
          CheckAllCrlValues(crl_data, tmp_store, it_signers_cert);
    }
  } catch (const std::exception &ex) {
    std::cerr << "[XDataCheck] " << ex.what() << "\n";
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
};

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
  std::cout << "total ocsp vals number =" << revocation_data.size() << "\n";
  for (const auto &revoc_pair : revocation_data) {
    // find the ocsp certificate hash (sha1)
    auto ocsp_cert_hash = revoc_pair.second.tbsResponseData.responderID_hash;
    if (!ocsp_cert_hash) {
      return false;
    }
    // find the ocsp certificate in certVals
    auto it_ocsp_cert = FindCertByPublicKeySHA1(xdata_, ocsp_cert_hash.value());
    // TODO(Oleg) implement find by name as alernative to hash
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
        std::cerr << "no cert found for an OCSP response\n";
        return false;
      }
      std::cout << "Found subject cert for the OCSP response\n";
      // check the ocsp response for this cert
      if (!cert_it->IsOcspStatusOK(ocsp_check_params)) {
        std::cout << "ocsp status is bad\n";
        return false;
      }
      if (cert_it == signers_cert) {
        res().x_singers_cert_has_ocsp_response = true;
      }
    }
  }
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
[[nodiscard]] bool
XChecks::CheckAllCrlValues(const std::vector<CrlReferenceValuePair> &crl_data,
                           const StoreHandler &additional_store,
                           CertIterator signers_cert) {
  const std::string func_name = "[XChecks::CheckAllCrlValues] ";
  std::cout << "number of crls" << crl_data.size() << "\n";
  if (crl_data.empty()) {
    return true;
  }

  BytesVector root_serial;
  // find the root certificate
  PCCERT_CHAIN_CONTEXT p_chain_context = nullptr;
  try {
    FILETIME time_to_check_chain = TimetToFileTime(xdata_.last_timestamp);
    p_chain_context =
        CreateCertChain(signers_cert->GetContext(), symbols(),
                        &time_to_check_chain, additional_store.RawHandler());
    const auto *root_cert = GetRootCertificateCtxFromChain(p_chain_context);
    if (root_cert != nullptr) {
      root_serial = BytesVector(root_cert->pCertInfo->SerialNumber.pbData,
                                root_cert->pCertInfo->SerialNumber.pbData +
                                    root_cert->pCertInfo->SerialNumber.cbData);
      std::reverse(root_serial.begin(), root_serial.end());
    }
  } catch (const std::exception &ex) {
    FreeChainContext(p_chain_context, symbols());
    std::cerr << func_name << ex.what() << "\n";
    return false;
  }
  FreeChainContext(p_chain_context, symbols());
  auto it_root_cert =
      std::find_if(xdata_.cert_vals.cbegin(), xdata_.cert_vals.cend(),
                   [&root_serial](const Certificate &cert) {
                     return cert.Serial() == root_serial;
                   });
  if (it_root_cert == xdata_.cert_vals.cend()) {
    std::cerr << "Root certificate was not found\n";
    return false;
  }
  // check for signing crls key Usage
  if (!CertificateHasKeyUsageBit(it_root_cert->GetContext(), 6)) {
    std::cerr << "The root certificate is not intended for CRL lists signing\n";
    return false;
  }

  for (const auto &crl_pair : crl_data) {
    const asn::CertificateList &crl = crl_pair.second;
    // check the signature
    if (crl.signatureAlgorithm.algorithm != szOID_CP_GOST_R3411_12_256_R3410) {
      throw std::runtime_error(func_name + "unsupported signature algorithm");
    }
    HashHandler hash(szOID_CP_GOST_R3411_12_256, symbols());
    hash.SetData(crl.tbsCertList.der_encoded);
    // import public key
    HCRYPTKEY handler_pub_key = 0;
    CERT_PUBLIC_KEY_INFO *p_ocsp_public_key_info =
        &it_root_cert->GetContext()->pCertInfo->SubjectPublicKeyInfo;
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
    std::cout << "CRL signature check ..."
              << (sig_verify_res == TRUE ? "OK" : "FALSE") << "\n";
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

} // namespace pdfcsp::csp::checks