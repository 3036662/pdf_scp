#include "t_checks.hpp"
#include "asn_tsp.hpp"
#include "bes_checks.hpp"
#include "message.hpp"
#include "oids.hpp"
#include "typedefs.hpp"
#include "utils_cert.hpp"
#include "utils_msg.hpp"
#include <algorithm>
#include <exception>
#include <iostream>
#include <stdexcept>

namespace pdfcsp::csp::checks {

TChecks::TChecks(const Message *pmsg, unsigned int signer_index,
                 bool ocsp_online, PtrSymbolResolver symbols)
    : BesChecks{pmsg, signer_index, ocsp_online, std::move(symbols)} {}

/// @brief Performs all checks
/// @param data - a raw pdf data (extacted with a byterange)
const CheckResult &TChecks::All(const BytesVector &data) noexcept {
  SignerIndex();
  CadesTypeFind();
  if (res().cades_type < CadesType::kCadesT) {
    res().cades_type_ok = false;
    SetFatal();
  }
  DataHash(data);
  ComputedHash();
  CertificateHash();
  CertificateStatus(ocsp_online());
  Signature();
  FinalDecision();
  // T CHECKS
  if (res().bes_fatal) {
    std::cerr << "T Checks can not be performed,because BES checks failed\n";
    SetFatal();
    return res();
  }
  CheckAllCadesTStamps();
  Free();
  return res();
}

void TChecks::CheckAllCadesTStamps() noexcept {
  constexpr const char *const func_name = "[CheckAllCadesTStamps] ";
  if (Fatal() || !cert()) {
    return;
  }
  auto unsigned_attributes =
      msg()->GetAttributes(signer_index(), AttributesType::kUnsigned);
  if (!unsigned_attributes) {
    SetFatal();
    std::cerr << func_name << "Get unsigned attributes ... FAILED\n";
    return;
  }
  for (const auto &tsp_attribute : unsigned_attributes->get_bunch()) {
    if (tsp_attribute.get_id() != asn::kOID_id_aa_signatureTimeStampToken) {
      continue;
    }
    BytesVector val_for_hashing;
    // value of messageImprint field within TimeStampToken shall be a
    // hash of the value of signature field within SignerInfo for the
    // signedData being time-stamped
    std::reverse_copy(res().encrypted_digest.cbegin(),
                      res().encrypted_digest.cend(),
                      std::back_inserter(val_for_hashing));
    try {
      if (!CheckOneCadesTStmap(tsp_attribute, val_for_hashing)) {
        SetFatal();
        res().t_all_tsp_contents_ok = false;
        return;
      }
    } catch (const std::exception &ex) {
      SetFatal();
      res().t_all_tsp_contents_ok = false;
      std::cerr << func_name << ex.what() << "\n";
      return;
    }
  }
  res().t_all_tsp_contents_ok = true;
  res().t_all_tsp_msg_signatures_ok = true;
  res().t_all_ok =
      res().t_all_tsp_contents_ok && res().t_all_tsp_msg_signatures_ok;
  res().t_fatal = !res().t_all_ok;
  res().times_collection = times_collection_;
}

bool TChecks::CheckOneCadesTStmap(const CryptoAttribute &tsp_attribute,
                                  const BytesVector &val_for_hashing) {
  const std::string func_name = "[CheckOneCadesTStmap] ";
  if (tsp_attribute.get_blobs_count() != 1) {
    throw std::runtime_error(func_name + "invalid blobs count in tsp attibute");
  }
  // decode message
  auto tsp_message =
      Message(PtrSymbolResolver(symbols()), tsp_attribute.get_blobs()[0],
              MessageType::kAttached);
  tsp_message.is_tsp_message_ = true;
  // check signatures for all signers of tsp message
  if (!CheckAllSignaturesInTsp(tsp_message)) {
    std::cerr << func_name << " Tsp message signature check ... FAILED\n";
    return false;
  }
  // check the content of the tsp message
  if (!CheckTspContent(tsp_message, val_for_hashing)) {
    std::cerr << func_name << " Tsp message signature check ... FAILED\n";
    return false;
  }
  return true;
}

[[nodiscard]] bool TChecks::CheckAllSignaturesInTsp(Message &tsp_message) {
  // for each signers
  for (uint tsp_signer_i = 0; tsp_signer_i < tsp_message.GetSignersCount();
       ++tsp_signer_i) {
    // find signer's certificate
    const auto decoded_cert = msg()->FindTspCert(tsp_message, tsp_signer_i);
    if (!decoded_cert) {
      throw std::runtime_error("Can't find a TSP certificate");
    }
    // check the usage key
    if (!CertificateHasExtendedKeyUsage(decoded_cert->GetContext(),
                                        asn::kOID_id_kp_timeStamping)) {
      std::cerr << "TSP certificate is not suitable for timestamping\n";
      return false;
    }
    // if no certificate in message, place one
    if (!tsp_message.GetRawCertificate(tsp_signer_i).has_value()) {
      tsp_message.SetExplicitCertForSigner(tsp_signer_i,
                                           decoded_cert->GetRawCopy());
    }
    // verify message
    std::cout << "TSP MESSAGE TYPE ="
              << InternalCadesTypeToString(
                     tsp_message.GetCadesTypeEx(tsp_signer_i))
              << "\n";
    const bool check_uttached_result =
        tsp_message.CheckAttached(tsp_signer_i, true);
    if (!check_uttached_result) {
      std::cerr << "[CheckCadesT] check TSP stamp signature failed\n";
      res().t_all_tsp_msg_signatures_ok = false;
      SetFatal();
      return false;
    }
  }
  res().t_all_tsp_msg_signatures_ok = true;
  return true;
}

bool TChecks::CheckTspContent(const Message &tsp_message,
                              const BytesVector &val_for_hashing) {
  const BytesVector data = tsp_message.GetContentFromAttached();
  const asn::AsnObj obj(data.data(), data.size());
  const asn::TSTInfo tst(obj);
  const std::string hashing_algo = tst.messageImprint.hashAlgorithm.algorithm;
  if (hashing_algo != szOID_CP_GOST_R3411_12_256) {
    throw std::runtime_error("unknown hashing algorithm in tsp stamp");
  }
  HashHandler sig_hash(hashing_algo, symbols());
  sig_hash.SetData(val_for_hashing);
  if (sig_hash.GetValue() != tst.messageImprint.hashedMessage) {
    std::cerr << "Tsp message imprint verify ... FAILED\n";
    return false;
  }
  std::cerr << "Tsp message imprint verify ... OK\n";
  // check certificate be revoked, then the date/time of
  //          revocation shall be later than the date/time indicated by
  //          the TSA.
  auto tsa_time = GeneralizedTimeToTimeT(tst.genTime);
  auto tsa_gmt = tsa_time.time + tsa_time.gmt_offset;
  times_collection_.push_back(tsa_gmt);
  const auto &certifcate = cert();
  if (!certifcate) {
    throw std::runtime_error("[CheckTspContent] No signers certificate found");
  }
  auto cert_timebounds = certifcate->GetTimeBounds();
  if (cert_timebounds.revocation &&
      cert_timebounds.revocation.value() <= tsa_gmt) {
    std::cerr << "The certifacte was revoced before signing\n";
    return false;
  }
  if (cert_timebounds.not_before > tsa_gmt &&
      cert_timebounds.not_after < tsa_gmt) {
    std::cerr << "The certificat was expired before signing\n";
    return false;
  }
  return true;
}

} // namespace pdfcsp::csp::checks