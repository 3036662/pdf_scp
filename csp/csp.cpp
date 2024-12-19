/* File: csp.cpp  
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


#include "altcsp.hpp"
#include "cades.h"
#include "cert_common_info.hpp"
#include "hash_handler.hpp"
#include "message.hpp"
#include "p_key_handler.hpp"
#include "resolve_symbols.hpp"
#include "store_hanler.hpp"
#include "typedefs.hpp"
#include "utils.hpp"
#include "utils_cert.hpp"
#include "utils_msg.hpp"
#include <exception>
#include <iostream>
#include <iterator>
#include <memory>
#include <stdexcept>

namespace pdfcsp::csp {

/**
 * @brief Open a detached message
 * @param message raw message data
 * @param data data signed by this message
 * @return Message (smart pointer)
 */
PtrMsg Csp::OpenDetached(const BytesVector &message) noexcept {
  try {
    return std::make_shared<Message>(dl_, message, MessageType::kDetached);
  } catch (const std::exception &ex) {
    dl_->log->error("[CSP::OpenDetached] {}", ex.what());
    return nullptr;
  }
}

/**
 * @brief Get the list of certificates for current user
 * @return std::vector<CertCommonInfo>
 */
std::vector<CertCommonInfo> Csp::GetCertList() noexcept {
  std::vector<CertCommonInfo> res;
  try {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-cstyle-cast)
    const StoreHandler store(CERT_STORE_PROV_SYSTEM,
                             CERT_SYSTEM_STORE_CURRENT_USER |
                                 CERT_STORE_OPEN_EXISTING_FLAG |
                                 CERT_STORE_READONLY_FLAG,
                             L"MY", dl_);
    PCCERT_CONTEXT p_cert_context = nullptr;
    while ((p_cert_context = dl_->dl_CertEnumCertificatesInStore(
                store.RawHandler(), p_cert_context)) != nullptr) {
      if (p_cert_context->pCertInfo != nullptr) {
        res.emplace_back(p_cert_context->pCertInfo);
      }
    }
  } catch (const std::exception &ex) {
    dl_->log->error("[CSP][GetCertList] {}", ex.what());
    return {};
  }
  return res;
}

/**
 * @brief Construct a CADES message
 *
 * @param cert_serial string
 * @param cert_subject string, common name
 * @param cades_type
 * @param data
 * @return BytesVector - result message
 */
BytesVector Csp::SignData(const std::string &cert_serial,
                          const std::string &cert_subject, CadesType cades_type,
                          const BytesVector &data,
                          const std::wstring &tsp_link) const {
  const PtrSymbolResolver &symbols = dl_;
  const std::string func_name = "Csp::SignData ";
  // get the certificate
  auto cert = utils::cert::FindCertInUserStoreBySerial(cert_subject,
                                                       cert_serial, symbols);
  if (!cert) {
    throw std::runtime_error(func_name +
                             "failed to find the user's certificate");
  }
  {
    const CertCommonInfo cert_info(cert->GetContext()->pCertInfo);
    if (cert_info.pub_key_algo != szOID_CP_GOST_R3410_12_256) {
      throw std::runtime_error(func_name + " unsupported signature algo");
    }
  }
  // calculate hash
  BytesVector hash_val;
  {
    HashHandler hash(szOID_CP_GOST_R3411_12_256, symbols);
    hash.SetData(data);
    hash_val = hash.GetValue();
  }
  // get private key
  const PKeyHandler h_key(cert->GetContext(), symbols);
  // sign hash
  CRYPT_SIGN_MESSAGE_PARA crypt_sign_params{};
  std::memset(&crypt_sign_params, 0x00, sizeof(CRYPT_SIGN_MESSAGE_PARA));
  crypt_sign_params.cbSize = sizeof(CRYPT_SIGN_MESSAGE_PARA);
  crypt_sign_params.dwMsgEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
  crypt_sign_params.pSigningCert = cert->GetContext(); // signer's certificate
  crypt_sign_params.HashAlgorithm.pszObjId =
      const_cast<char *>(szOID_CP_GOST_R3411_12_256); // NOLINT
  // save signer's cert to message
  crypt_sign_params.cMsgCert = 1;
  std::array<PCCERT_CONTEXT, 1> certs{cert->GetContext()};
  crypt_sign_params.rgpMsgCert = certs.data();
  // TSP params
  CADES_SERVICE_CONNECTION_PARA tsp_param{};
  tsp_param.dwSize = sizeof(CADES_SERVICE_CONNECTION_PARA);
  tsp_param.wszUri = tsp_link.empty() ? nullptr : tsp_link.c_str();
  // CADES sign params
  CADES_SIGN_PARA cades_sign_params{};
  std::memset(&cades_sign_params, 0x00, sizeof(CADES_SIGN_PARA));
  cades_sign_params.dwSize = sizeof(CADES_SIGN_PARA);
  cades_sign_params.dwCadesType =
      utils::message::InternalCadesTypeToCspType(cades_type);
  cades_sign_params.pSignerCert =
      cert->GetContext(); // TODO(Oleg) do we need this?
  cades_sign_params.pTspConnectionPara =
      tsp_link.empty() ? nullptr : &tsp_param;
  // CADES msg params
  CADES_SIGN_MESSAGE_PARA cades_sign_msg_params{};
  cades_sign_msg_params.dwSize = sizeof(CADES_SIGN_MESSAGE_PARA);
  cades_sign_msg_params.pSignMessagePara = &crypt_sign_params;
  cades_sign_msg_params.pCadesSignPara = &cades_sign_params;
  // create a signature
  PCRYPT_DATA_BLOB p_signed_message = nullptr;
  ResCheck(symbols->dl_CadesSignHash(&cades_sign_msg_params, hash_val.data(),
                                     hash_val.size(), szOID_RSA_data,
                                     &p_signed_message),
           func_name + "CadesSignHash", symbols);
  if (p_signed_message == nullptr || p_signed_message->cbData == 0 ||
      p_signed_message->pbData == nullptr) {
    throw std::runtime_error(func_name + "Failed to create signature");
  }
  BytesVector res;
  res.reserve(p_signed_message->cbData + 1);
  std::copy(p_signed_message->pbData,
            p_signed_message->pbData + p_signed_message->cbData,
            std::back_inserter(res));
  symbols->dl_CadesFreeBlob(p_signed_message);
  return res;
}

} // namespace pdfcsp::csp