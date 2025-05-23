/* File: t_checks.cpp
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

#include "t_checks.hpp"

#include <algorithm>
#include <exception>
#include <iostream>
#include <iterator>
#include <optional>
#include <stdexcept>
#include <utility>
#include <vector>

#include "asn_tsp.hpp"
#include "bes_checks.hpp"
#include "cert_common_info.hpp"
#include "check_result.hpp"
#include "check_utils.hpp"
#include "message.hpp"
#include "oids.hpp"
#include "typedefs.hpp"
#include "utils.hpp"
#include "utils_cert.hpp"
#include "utils_msg.hpp"

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
    res().bres.cades_type_ok = false;
    SetFatal();
  }
  DataHash(data);
  ComputedHash();
  DecodeCertificate();
  SaveDigest();
  CertificateHash();
  CertificateStatus(ocsp_online());
  Signature();
  FinalDecision();
  // T CHECKS
  if (res().bres.bes_fatal) {
    symbols()->log->error(
      "T Checks can not be performed,because BES checks failed");
    SetFatal();
    return res();
  }
  CheckAllCadesTStamps();
  res().bres.check_summary = res().bres.bes_all_ok && res().bres.t_all_ok;
  Free();
  return res();
}

/// @brief Check all CADES_T timestamps
void TChecks::CheckAllCadesTStamps() noexcept {
  constexpr const char *const func_name = "[CheckAllCadesTStamps] ";
  if (Fatal() || !cert()) {
    return;
  }
  auto unsigned_attributes =
    msg()->GetAttributes(signer_index(), AttributesType::kUnsigned);
  if (!unsigned_attributes) {
    SetFatal();
    symbols()->log->error("{} Get unsigned attributes ... FAILED", func_name);
    return;
  }
  times_collection_.clear();
  // store results for all TSP stamps to vector
  std::vector<CheckOneCadesTSPResult> check_all_tsp_res;
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
      CheckOneCadesTSPResult one_tsp_res =
        CheckOneCadesTStmap(tsp_attribute, val_for_hashing);
      if (!one_tsp_res.result) {
        SetFatal();
        res().bres.t_all_tsp_contents_ok = false;
        return;
      }
      check_all_tsp_res.emplace_back(std::move(one_tsp_res));
    } catch (const std::exception &ex) {
      SetFatal();
      res().bres.t_all_tsp_contents_ok = false;
      symbols()->log->error("{} {}", func_name, ex.what());
      return;
    }
  }
  // build json result for tsp
  res().tsp_json_info = check_utils::BuildJsonTSPResult(check_all_tsp_res);
  res().bres.t_all_tsp_contents_ok = true;
  res().bres.t_all_tsp_msg_signatures_ok = true;
  res().bres.t_all_ok =
    res().bres.t_all_tsp_contents_ok && res().bres.t_all_tsp_msg_signatures_ok;
  res().bres.t_fatal = !res().bres.t_all_ok;
  res().times_collection = std::move(times_collection_);
}

CheckOneCadesTSPResult TChecks::CheckOneCadesTStmap(
  const CryptoAttribute &tsp_attribute, const BytesVector &val_for_hashing) {
  CheckOneCadesTSPResult result_struct{false, {}, std::nullopt};
  const std::string func_name = "[CheckOneCadesTStmap] ";
  if (tsp_attribute.get_blobs_count() != 1) {
    throw std::runtime_error(func_name + "invalid blobs count in tsp attibute");
  }
  // decode message
  auto tsp_message =
    Message(PtrSymbolResolver(symbols()), tsp_attribute.get_blobs()[0],
            MessageType::kAttached);
  tsp_message.SetIsTspMessage(true);
  //------------------------------------------------
  // check signatures for all signers of tsp message
  CheckAllSignaturesInTspResult check_all_tsp_sigs =
    CheckAllSignaturesInTsp(tsp_message);
  // save certificate json chains to result_struct
  for (CheckResult &ch_res : check_all_tsp_sigs.tsp_check_result) {
    result_struct.chain_json_obj.emplace_back(
      std::move(ch_res.signers_chain_json));
  }
  if (!check_all_tsp_sigs.result) {
    symbols()->log->error(" Tsp message signature check ... FAILED");
    return result_struct;
  }
  // ----------------------------------------------
  // check the content of the tsp message
  CheckTspContentResult check_tsp_content_result =
    CheckTspContent(tsp_message, val_for_hashing);
  // save tsp content to result_struct
  result_struct.tst_content = std::move(check_tsp_content_result.tst_content);
  if (!check_tsp_content_result.result) {
    symbols()->log->error("{} Tsp message signature check ... FAILED",
                          func_name);
    return result_struct;
  }
  result_struct.result =
    check_all_tsp_sigs.result && check_tsp_content_result.result;
  return result_struct;
}

[[nodiscard]] CheckAllSignaturesInTspResult TChecks::CheckAllSignaturesInTsp(
  Message &tsp_message) {
  CheckAllSignaturesInTspResult result_struct{false, {}};
  // for each signers
  for (uint tsp_signer_i = 0; tsp_signer_i < tsp_message.GetSignersCount();
       ++tsp_signer_i) {
    // find signer's certificate
    const auto decoded_cert = msg()->FindTspCert(tsp_message, tsp_signer_i);
    if (!decoded_cert) {
      throw std::runtime_error("Can't find a TSP certificate");
    }
    auto cert_info = CertCommonInfo(decoded_cert->GetContext()->pCertInfo);
    symbols()->log->info("TSP certificate: subject {} issuer {} s/n {}",
                         cert_info.subj_common_name,
                         cert_info.issuer_common_name,
                         VecBytesStringRepresentation(cert_info.serial));

    // check the usage key
    if (!utils::cert::CertificateHasExtendedKeyUsage(
          decoded_cert->GetContext(), asn::kOID_id_kp_timeStamping)) {
      symbols()->log->error("TSP certificate is not suitable for timestamping");
      return result_struct;
    }
    // if no certificate in message, place one
    if (!tsp_message.GetRawCertificate(tsp_signer_i).has_value()) {
      tsp_message.SetExplicitCertForSigner(tsp_signer_i,
                                           decoded_cert->GetRawCopy());
    }
    // verify message
    symbols()->log->info("TSP MESSAGE TYPE = {}",
                         utils::message::InternalCadesTypeToString(
                           tsp_message.GetCadesTypeEx(tsp_signer_i)));
    CheckResult check_uttached_result =
      tsp_message.ComprehensiveCheckAttached(tsp_signer_i, ocsp_online());
    if (!check_uttached_result.bres.check_summary) {
      symbols()->log->error("[CheckCadesT] check TSP stamp signature failed");
      res().bres.t_all_tsp_msg_signatures_ok = false;
      SetFatal();
      return result_struct;
    }
    result_struct.tsp_check_result.emplace_back(
      std::move(check_uttached_result));
  }
  result_struct.result = true;
  res().bres.t_all_tsp_msg_signatures_ok = true;
  return result_struct;
}

CheckTspContentResult TChecks::CheckTspContent(
  const Message &tsp_message, const BytesVector &val_for_hashing) {
  CheckTspContentResult result_struct{false, std::nullopt};
  const BytesVector data = tsp_message.GetContentFromAttached();
  const asn::AsnObj obj(data.data(), data.size());
  asn::TSTInfo tst(obj);
  const std::string hashing_algo = tst.messageImprint.hashAlgorithm.algorithm;
  if (hashing_algo != szOID_CP_GOST_R3411_12_256) {
    throw std::runtime_error("unknown hashing algorithm in tsp stamp");
  }
  HashHandler sig_hash(hashing_algo, symbols());
  sig_hash.SetData(val_for_hashing);
  if (sig_hash.GetValue() != tst.messageImprint.hashedMessage) {
    symbols()->log->error("Tsp message imprint verify ... FAILED");
    return result_struct;
  }
  symbols()->log->info("Tsp message imprint verify ... OK");
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
    symbols()->log->error("The certifacte was revoced before signing");
    return result_struct;
  }
  if (cert_timebounds.not_before > tsa_gmt &&
      cert_timebounds.not_after < tsa_gmt) {
    symbols()->log->error("The certificat was expired before signing");
    return result_struct;
  }
  result_struct.result = true;
  result_struct.tst_content = std::move(tst);
  return result_struct;
}

}  // namespace pdfcsp::csp::checks