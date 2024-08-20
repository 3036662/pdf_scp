#include "xl_certs.hpp"
#include "cert_refs.hpp"
#include "certificate.hpp"
#include "certificate_id.hpp"
#include "cms.hpp"
#include "hash_handler.hpp"
#include "ocsp.hpp"
#include "resolve_symbols.hpp"
#include "store_hanler.hpp"
#include "typedefs.hpp"
#include "utils.hpp"
#include "utils_cert.hpp"
#include <algorithm>
#include <cassert>
#include <cstddef>
#include <ctime>
#include <exception>
#include <iostream>
#include <stdexcept>
#include <variant>

namespace pdfcsp::csp {

XLongCertsCheckResult CheckXCerts(const XLCertsData &xdata,
                                  const PtrSymbolResolver &symbols) {
  XLongCertsCheckResult res{};
  // match all revocation references to their values
  std::cout << "CheckXCerts\n";
  // match all OCSP responses
  const std::vector<OcspReferenceValuePair> revocation_data =
      MatchOcspRevocRefsToValues(xdata, symbols);
  // match all CRL lists
  const std::vector<CrlReferenceValuePair> crl_data =
      MatchCrlRevocRefsToValues(xdata, symbols);
  // check if all referenced revocation values where found
  res.all_revoc_refs_have_value =
      xdata.revoc_refs.size() == revocation_data.size() + crl_data.size();
  std::cout << "Find all referenced revoc vals..."
            << (res.all_revoc_refs_have_value ? "OK" : "FAILED") << "\n";
  // match all certificate values
  const std::vector<CertReferenceValueIteratorPair> certs_data =
      MatchCertRefsToValueIterators(xdata, symbols);
  res.all_cert_refs_have_value = certs_data.size() == xdata.cert_refs.size();
  std::cout << "Find all referenced certificates ..."
            << (res.all_cert_refs_have_value ? "OK" : "FAIL") << "\n";
  // find the signer's certificate
  auto it_signers_cert = FindSignersCert(xdata, symbols);
  res.signing_cert_found = it_signers_cert != xdata.cert_vals.cend();
  std::cout << "Find singers cerificate ..."
            << (res.signing_cert_found ? "OK" : "FAIL") << "\n";
  // create a temporary storage for certs
  StoreHandler tmp_store(CERT_STORE_PROV_MEMORY, 0, 0, symbols); // NOLINT
  std::cout << "Create temp store OK\n";
  // add all certificates to store
  if (res.signing_cert_found) {
    tmp_store.AddCertificate(*it_signers_cert);
  }
  for (const auto &cert_pair : certs_data) {
    if (cert_pair.second != xdata.cert_vals.cend()) {
      tmp_store.AddCertificate(*cert_pair.second);
    }
  }
  std::cout << "Add certificates to temporary store OK\n";
  // check all responses
  res.all_ocsp_responses_valid = CheckAllOcspValues(
      xdata, revocation_data, tmp_store, it_signers_cert, res, symbols);
  std::cout << "Check all revoces ..."
            << (res.all_ocsp_responses_valid ? "OK" : "FAILED") << "\n";

  //  check a signer's certificate chain
  if (res.signing_cert_found) {
    FILETIME time_to_check_chain = TimetToFileTime(xdata.last_timestamp);
    res.signing_cert_chaing_ok = it_signers_cert->IsChainOK(
        &time_to_check_chain, tmp_store.RawHandler());
  }

  // check CRLS
  if (res.signing_cert_found) {
    res.all_crls_valid =
        CheckAllCrlValues(xdata, crl_data, tmp_store, it_signers_cert, symbols);
  }

  if (res.signing_cert_chaing_ok) {
    std::cout << "signers certificate chain OK\n";
  }
  res.summary = res.all_revoc_refs_have_value && res.all_cert_refs_have_value &&
                res.signing_cert_found && res.all_ocsp_responses_valid &&
                res.signing_cert_chaing_ok && res.all_crls_valid &&
                res.singers_cert_has_ocsp_response;

  return res;
}

std::vector<CrlReferenceValuePair>
MatchCrlRevocRefsToValues(const XLCertsData &xdata,
                          const PtrSymbolResolver &symbols) {
  std::vector<CrlReferenceValuePair> res;
  constexpr const char *const expl_unsupported_hash_algo =
      "[MatchCrlRevocRefsToValues] unsupported hash type";
  for (const auto &crl_ref : xdata.revoc_refs) {
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
        auto it_crl_val = std::find_if(
            xdata.revoc_vals.crlVals.cbegin(), xdata.revoc_vals.crlVals.cend(),
            [&hashing_algo, &hash_val,
             &symbols](const asn::CertificateList &cert_list) {
              HashHandler tmp_hash(hashing_algo, symbols);
              tmp_hash.SetData(cert_list.der_encoded);
              return tmp_hash.GetValue() == hash_val;
            });
        if (it_crl_val != xdata.revoc_vals.crlVals.cend()) {
          res.emplace_back(crl_id, *it_crl_val);
        }
      }
    }
  }
  return res;
}

/**
 * @brief Matches each revocation reference to the coressponding OCSP response
 * @param xdata XLCertsData structure
 * @param symbols
 * @return std::vector<OcspReferenceValuePair>
 */
std::vector<OcspReferenceValuePair>
MatchOcspRevocRefsToValues(const XLCertsData &xdata,
                           const PtrSymbolResolver &symbols) {
  std::vector<OcspReferenceValuePair> res;
  for (const auto &ocsp_ref : xdata.revoc_refs) {
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
            xdata.revoc_vals.ocspVals.cbegin(),
            xdata.revoc_vals.ocspVals.cend(),
            [&responder_hash, &responder_name,
             &responder_time](const asn::BasicOCSPResponse &resp) {
              return responder_hash == resp.tbsResponseData.responderID_hash &&
                     responder_name == resp.tbsResponseData.responderID_name &&
                     responder_time == resp.tbsResponseData.producedAt;
            });
        // found a match - compare a hash
        if (it_val != xdata.revoc_vals.ocspVals.cend()) {
          HashHandler tmp_hash(hashing_algo, symbols);
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
 * @brief Matches each certificate referense to the corresponding certificate
 * @param xdata XLCertsData structure
 * @param symbols
 * @return std::vector<CertReferenceValueIteratorPair>
 */
std::vector<CertReferenceValueIteratorPair>
MatchCertRefsToValueIterators(const XLCertsData &xdata,
                              const PtrSymbolResolver &symbols) {
  std::vector<CertReferenceValueIteratorPair> res;
  for (const auto &cert_ref : xdata.cert_refs) {
    if (std::holds_alternative<asn::OtherHashAlgAndValue>(
            cert_ref.otherCertHash)) {
      const auto &hash_and_val =
          std::get<asn::OtherHashAlgAndValue>(cert_ref.otherCertHash);
      const std::string &hash_algo = hash_and_val.hashAlgorithm.algorithm;
      const BytesVector &hash_val = hash_and_val.hashValue;
      // find a corresponding certificate in xdata
      auto it_cert_val = std::find_if(
          xdata.cert_vals.cbegin(), xdata.cert_vals.cend(),
          [&hash_algo, &hash_val, &symbols](const Certificate &cert_val) {
            HashHandler tmp_hash(hash_algo, symbols);
            tmp_hash.SetData(cert_val.GetRawCopy());
            return hash_val == tmp_hash.GetValue();
          });
      if (it_cert_val != xdata.cert_vals.cend()) {
        res.emplace_back(cert_ref, it_cert_val);
      }
    }
  }
  return res;
}

/**
 * @brief Finds a signer's certificate in XLCertsData
 * @param xdata XLCertsData struct
 * @param symbols
 * @return CertIterator  iterator to signer's certificate
 */
[[nodiscard]] CertIterator FindSignersCert(const XLCertsData &xdata,
                                           const PtrSymbolResolver &symbols) {
  return std::find_if(
      xdata.cert_vals.cbegin(), xdata.cert_vals.cend(),
      [&xdata, &symbols](const Certificate &cert) {
        if (xdata.signers_cert.serial == cert.Serial()) {
          HashHandler tmp_hash(xdata.signers_cert.hashing_algo_oid, symbols);
          tmp_hash.SetData(cert.GetRawCopy());
          return xdata.signers_cert.hash_cert == tmp_hash.GetValue();
        }
        return false;
      });
};

// check OCSP answers embedded within message
[[nodiscard]] bool
CheckAllOcspValues(const XLCertsData &xdata,
                   const std::vector<OcspReferenceValuePair> &revocation_data,
                   const StoreHandler &additional_store,
                   CertIterator signers_cert, XLongCertsCheckResult &result,
                   const PtrSymbolResolver &symbols) {
  std::cout << "total ocsp vals number =" << revocation_data.size() << "\n";
  for (const auto &revoc_pair : revocation_data) {
    // find the ocsp certificate hash (sha1)
    auto ocsp_cert_hash = revoc_pair.second.tbsResponseData.responderID_hash;
    if (!ocsp_cert_hash) {
      return false;
    }
    // find the ocsp certificate in certVals
    auto it_ocsp_cert =
        FindCertByPublicKeySHA1(xdata, ocsp_cert_hash.value(), symbols);
    // TODO(Oleg) implement find by name as alernative to hash
    if (it_ocsp_cert == xdata.cert_vals.cend()) {
      return false;
    }
    // params for Certificate::IsOcspOk
    const OcspCheckParams ocsp_check_params{
        &revoc_pair.second, &(*it_ocsp_cert), &xdata.last_timestamp,
        &additional_store};
    for (const auto &response : revoc_pair.second.tbsResponseData.responses) {
      // find corresponding cert for the OCSP response
      auto cert_it =
          std::find_if(xdata.cert_vals.cbegin(), xdata.cert_vals.cend(),
                       [&response](const Certificate &cert) {
                         return cert.Serial() == response.certID.serialNumber;
                       });
      if (cert_it == xdata.cert_vals.cend()) {
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
        result.singers_cert_has_ocsp_response = true;
      }
      std::cout << "Checked ocsp response for the cert\n";
    }
  }
  return true;
}

bool CheckAllCrlValues(const XLCertsData &xdata,
                       const std::vector<CrlReferenceValuePair> &crl_data,
                       const StoreHandler &additional_store,
                       CertIterator signers_cert,
                       const PtrSymbolResolver &symbols) {
  const std::string func_name = "[CheckAllCrlValues] ";
  std::cout << "number of crls" << crl_data.size() << "\n";
  if (crl_data.empty()) {
    return true;
  }

  BytesVector root_serial;
  // find the root certificate
  PCCERT_CHAIN_CONTEXT p_chain_context = nullptr;
  try {
    FILETIME time_to_check_chain = TimetToFileTime(xdata.last_timestamp);
    p_chain_context =
        CreateCertChain(signers_cert->GetContext(), symbols,
                        &time_to_check_chain, additional_store.RawHandler());
    const auto *root_cert = GetRootCertificateCtxFromChain(p_chain_context);
    if (root_cert != nullptr) {
      root_serial = BytesVector(root_cert->pCertInfo->SerialNumber.pbData,
                                root_cert->pCertInfo->SerialNumber.pbData +
                                    root_cert->pCertInfo->SerialNumber.cbData);
      std::reverse(root_serial.begin(), root_serial.end());
    }
  } catch (const std::exception &ex) {
    FreeChainContext(p_chain_context, symbols);
    std::cerr << func_name << ex.what() << "\n";
    return false;
  }
  FreeChainContext(p_chain_context, symbols);

  auto it_root_cert =
      std::find_if(xdata.cert_vals.cbegin(), xdata.cert_vals.cend(),
                   [&root_serial](const Certificate &cert) {
                     return cert.Serial() == root_serial;
                   });
  if (it_root_cert == xdata.cert_vals.cend()) {
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
    // TODO(Oleg) check the signature
    if (crl.signatureAlgorithm.algorithm != szOID_CP_GOST_R3411_12_256_R3410) {
      throw std::runtime_error(func_name + "unsupported signature algorithm");
    }
    HashHandler hash(szOID_CP_GOST_R3411_12_256, symbols);
    hash.SetData(crl.tbsCertList.der_encoded);
    // import public key
    HCRYPTKEY handler_pub_key = 0;
    CERT_PUBLIC_KEY_INFO *p_ocsp_public_key_info =
        &it_root_cert->GetContext()->pCertInfo->SubjectPublicKeyInfo;
    ResCheck(symbols->dl_CryptImportPublicKeyInfo(
                 hash.get_csp_hanler(), PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
                 p_ocsp_public_key_info, &handler_pub_key),
             "CryptImportPublicKeyInfo", symbols);

    if (handler_pub_key == 0) {
      throw std::runtime_error("Import public key failed");
    }
    // verify signature
    BytesVector signature = crl.signatureValue;
    std::reverse(signature.begin(), signature.end());
    //  delete last 0 byte from signature
    signature.pop_back();
    const BOOL res = symbols->dl_CryptVerifySignatureA(
        hash.get_hash_handler(), signature.data(), signature.size(),
        handler_pub_key, nullptr, 0);
    std::cout << "CRL signature check ..." << (res == TRUE ? "OK" : "FALSE")
              << "\n";
    if (res != TRUE) {
      return false;
    }
    for (const auto &revoced_cert : crl.tbsCertList.revokedCertificates) {
      const auto revoc_date_parsed = // NOLINT
          UTCTimeToTimeT(revoced_cert.revocationDate);
      const time_t revoc_time_stamp =
          revoc_date_parsed.time + revoc_date_parsed.gmt_offset;
      // TODO(Oleg) push serial numbers of all recvoced cetificates  matching
      // certVals to result
      if (revoc_time_stamp <= xdata.last_timestamp &&
          std::any_of(xdata.cert_vals.cbegin(), xdata.cert_vals.cend(),
                      [&revoced_cert](const Certificate &cert) {
                        return cert.Serial() == revoced_cert.userCertificate;
                      })) {
        return false;
      }
    }
  }
  return true;
}

/**
 * @brief Find a certificate by it's public key SHA1 hash
 * @param xdata XLCertsData struct
 * @param sha1 BytesVector with sha1 hash to look for
 * @param symbols
 * @return CertIterator iterator to the corresponding certificate
 */
CertIterator FindCertByPublicKeySHA1(const XLCertsData &xdata,
                                     const BytesVector &sha1,
                                     const PtrSymbolResolver &symbols) {
  return std::find_if(xdata.cert_vals.cbegin(), xdata.cert_vals.cend(),
                      [&sha1, &symbols](const Certificate &cert) {
                        HashHandler tmp_hash("SHA1", symbols);
                        tmp_hash.SetData(cert.PublicKey());
                        return sha1 == tmp_hash.GetValue();
                      });
}

} // namespace pdfcsp::csp