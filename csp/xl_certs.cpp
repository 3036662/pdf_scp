#include "xl_certs.hpp"
#include "cert_refs.hpp"
#include "certificate.hpp"
#include "hash_handler.hpp"
#include "ocsp.hpp"
#include "resolve_symbols.hpp"
#include "typedefs.hpp"
#include "utils.hpp"
#include <algorithm>
#include <cassert>
#include <iostream>
#include <stdexcept>
#include <variant>

namespace pdfcsp::csp {

XLongCertsCheckResult CheckXCerts(const XLCertsData &xdata,
                                  const PtrSymbolResolver &symbols) {
  XLongCertsCheckResult res{};
  // match all revocation references to their values
  const std::vector<OcspReferenceValuePair> revocation_data =
      MatchRevocRefsToValues(xdata, symbols);
  res.all_revoc_refs_have_value =
      xdata.revoc_refs.size() == revocation_data.size();
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

  res.all_ocsp_responses_valid = CheckAllRevocValues(xdata, revocation_data);
  std::cout << "Check all revoces ..."
            << (res.all_ocsp_responses_valid ? "OK" : "FAILED") << "\n";

  // loop through the revocation data
  // for each OcspResponse find a certificate
  // check ocsp response for this certificate
  //   for (const auto& revoc_pair:revocation_data){
  //     for (const auto& response:revoc_pair.second.tbsResponseData.responses){
  //         //response.certID.serialNumber
  //     }
  //   }
  return res;
}

/**
 * @brief Matches each revocation reference to the coressponding OCSP response
 * @param xdata XLCertsData structure
 * @param symbols 
 * @return std::vector<OcspReferenceValuePair> 
 */
std::vector<OcspReferenceValuePair>
MatchRevocRefsToValues(const XLCertsData &xdata,
                       const PtrSymbolResolver &symbols) {
  std::vector<OcspReferenceValuePair> res;
  for (const auto &ocsp_ref : xdata.revoc_refs) {
    if (!ocsp_ref.ocspids.has_value()) {
      continue;
    }
    // TODO(Oleg) implement for these values
    if (ocsp_ref.crlids.has_value() || ocsp_ref.otherRev.has_value()) {
      throw std::runtime_error(
          "[MatchRevocRefsToValues] unsupported type of revocation ref");
    }
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
          xdata.revoc_vals.ocspVals.cbegin(), xdata.revoc_vals.ocspVals.cend(),
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

[[nodiscard]] bool CheckAllRevocValues(
    const XLCertsData &xdata,
    const std::vector<OcspReferenceValuePair> &revocation_data) {
  for (const auto &revoc_pair : revocation_data) {
    for (const auto &response : revoc_pair.second.tbsResponseData.responses) {
      // find corresponding cert
      // response.certID.serialNumber
      auto cert_it =
          std::find_if(xdata.cert_vals.cbegin(), xdata.cert_vals.cend(),
                       [&response](const Certificate &cert) {
                         return cert.Serial() == response.certID.serialNumber;
                       });
      if (cert_it == xdata.cert_vals.cend()) {
        return false;
      }
      // TODO(Oleg) check ocsp response for this cert
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
  // print key hashes
  return std::find_if(xdata.cert_vals.cbegin(), xdata.cert_vals.cend(),
                      [&sha1, &symbols](const Certificate &cert) {
                        HashHandler tmp_hash("SHA1", symbols);
                        tmp_hash.SetData(cert.PublicKey());
                        return sha1 == tmp_hash.GetValue();
                      });
}

} // namespace pdfcsp::csp