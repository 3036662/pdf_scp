/* File: csp.cpp
Copyright (C) Basealt LLC,  2025
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

#include <boost/algorithm/string/predicate.hpp>
#include <boost/algorithm/string/trim.hpp>
#include <exception>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>
#include <stdexcept>
#include <string>

#include "altcsp.hpp"
#include "asn1.hpp"
#include "cades.h"
#include "cert_common_info.hpp"
#include "common_utils.hpp"
#include "hash_handler.hpp"
#include "message.hpp"
#include "oids.hpp"
#include "p_key_handler.hpp"
#include "resolve_symbols.hpp"
#include "store_hanler.hpp"
#include "typedefs.hpp"
#include "utils.hpp"
#include "utils_cert.hpp"
#include "utils_msg.hpp"

namespace pdfcsp::csp {

namespace comm_utils = ::pdfcsp::utils;

/**
 * @brief Open a detached message
 * @param message raw message data (ANS1 encoded)
 * @return Message (shared pointer)
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
 * @brief Open an attached message
 * @param message raw message data (ANS1 encoded)
 * @return Message (shared pointer)
 */
PtrMsg Csp::OpenAttached(const BytesVector &message) noexcept {
  try {
    return std::make_shared<Message>(dl_, message, MessageType::kAttached);
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
    symbols->log->error("Can't find certificate s/n {} subject {}", cert_serial,
                        cert_subject);
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
  // get private key just to make sure it exists
  {
    const PKeyHandler h_key(cert->GetContext(), symbols);
  }
  // sign hash
  CRYPT_SIGN_MESSAGE_PARA crypt_sign_params{};
  std::memset(&crypt_sign_params, 0x00, sizeof(CRYPT_SIGN_MESSAGE_PARA));
  crypt_sign_params.cbSize = sizeof(CRYPT_SIGN_MESSAGE_PARA);
  crypt_sign_params.dwMsgEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
  crypt_sign_params.pSigningCert = cert->GetContext();  // signer's certificate
  crypt_sign_params.HashAlgorithm.pszObjId =
    const_cast<char *>(szOID_CP_GOST_R3411_12_256);  // NOLINT
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
    cert->GetContext();  // TODO(Oleg) do we need this?
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

/**
 * @brief Construct a CADES attached message
 *
 * @param cert_serial string
 * @param cert_subject string, common name
 * @param cades_type
 * @param data
 * @param tsp_link wide char string,the TSP server url
 * @return BytesVector - result message
 * @throws
 */
[[nodiscard]] BytesVector Csp::CreateAttached(
  const std::string &cert_serial, const std::string &cert_subject,
  CadesType cades_type, const BytesVector &data,
  const std::wstring &tsp_link) const {
  const PtrSymbolResolver &symbols = dl_;
  const std::string func_name = "[Csp::CreateAttached] ";
  if (data.empty()) {
    throw std::invalid_argument(func_name + "data is empty");
  }
  // get the certificate
  auto cert = utils::cert::FindCertInUserStoreBySerial(cert_subject,
                                                       cert_serial, symbols);
  if (!cert) {
    symbols->log->error("Can't find certificate s/n {} subject {}", cert_serial,
                        cert_subject);
    throw std::runtime_error(func_name +
                             "failed to find the user's certificate");
  }
  {
    const CertCommonInfo cert_info(cert->GetContext()->pCertInfo);
    if (cert_info.pub_key_algo != szOID_CP_GOST_R3410_12_256) {
      throw std::runtime_error(func_name + " unsupported signature algo");
    }
  }
  // get private key just to make sure it exists
  {
    const PKeyHandler h_key(cert->GetContext(), symbols);
  }
  // TSP params
  CADES_SERVICE_CONNECTION_PARA tsp_param{};
  tsp_param.dwSize = sizeof(CADES_SERVICE_CONNECTION_PARA);
  tsp_param.wszUri = tsp_link.empty() ? nullptr : tsp_link.c_str();
  // CRYPT_SIGN_MESSAGE_PARA
  CRYPT_SIGN_MESSAGE_PARA crypt_sign_params;
  std::memset(&crypt_sign_params, 0x00, sizeof(CRYPT_SIGN_MESSAGE_PARA));
  crypt_sign_params.cbSize = sizeof(CRYPT_SIGN_MESSAGE_PARA);
  crypt_sign_params.dwMsgEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
  crypt_sign_params.pSigningCert = cert->GetContext();
  crypt_sign_params.HashAlgorithm.pszObjId =
    const_cast<char *>(szOID_CP_GOST_R3411_12_256);  // NOLINT
  // save signer's cert to message
  crypt_sign_params.cMsgCert = 1;
  std::array<PCCERT_CONTEXT, 1> certs{cert->GetContext()};
  crypt_sign_params.rgpMsgCert = certs.data();

  // CADES_SIGN_PARA
  CADES_SIGN_PARA cades_sign_params{};
  std::memset(&cades_sign_params, 0x00, sizeof(CADES_SIGN_PARA));
  cades_sign_params.dwSize = sizeof(CADES_SIGN_PARA);
  cades_sign_params.dwCadesType =
    utils::message::InternalCadesTypeToCspType(cades_type);
  cades_sign_params.pSignerCert = cert->GetContext();
  cades_sign_params.pTspConnectionPara =
    tsp_link.empty() ? nullptr : &tsp_param;

  // CADES_SIGN_MESSAGE_PARA
  CADES_SIGN_MESSAGE_PARA cades_sign_msg_params{};
  cades_sign_msg_params.dwSize = sizeof(CADES_SIGN_MESSAGE_PARA);
  cades_sign_msg_params.pSignMessagePara = &crypt_sign_params;
  cades_sign_msg_params.pCadesSignPara = &cades_sign_params;

  // sign data
  PCRYPT_DATA_BLOB p_signed_message = nullptr;
  const unsigned char *p_data = data.data();
  std::array<unsigned int, 1> sz_data{static_cast<unsigned int>(data.size())};
  ResCheck(symbols->dl_CadesSignMessage(&cades_sign_msg_params, 0, 1, &p_data,
                                        sz_data.data(), &p_signed_message),
           func_name + "CadesSignMessage", symbols);
  if (p_signed_message == nullptr || p_signed_message->cbData == 0 ||
      p_signed_message->pbData == nullptr) {
    throw std::runtime_error(func_name + "Failed to create signature");
  }
  BytesVector res;
  res.reserve(p_signed_message->cbData);
  res.reserve(p_signed_message->cbData + 1);
  std::copy(p_signed_message->pbData,
            p_signed_message->pbData + p_signed_message->cbData,
            std::back_inserter(res));
  symbols->dl_CadesFreeBlob(p_signed_message);
  return res;
}

/**
 * @brief Check the header of signature file
 *
 * @param filename
 * @return true if file is BASE64 encoded
 * @return false
 * @throws on open file failed
 */
bool Csp::IsBase64Encoded(const std::string &filename) {
  if (filename.empty() || !std::filesystem::exists(filename)) {
    throw std::runtime_error("[Csp::IsBase64Encoded] file not found");
  }
  // check the header
  std::ifstream file(filename);
  if (!file.is_open()) {
    throw std::runtime_error("Can't open file");
  }
  std::string header_line;
  std::getline(file, header_line);
  file.close();
  boost::algorithm::trim(header_line);
  return boost::algorithm::contains(header_line, "-----BEGIN CMS-----");
}

bool Csp::IsAttached(const std::string &filename) {
  if (filename.empty() || !std::filesystem::exists(filename)) {
    throw std::runtime_error("[Csp::IsAttached] file not found");
  }
  const bool base64 = Csp::IsBase64Encoded(filename);
  std::optional<BytesVector> sig_data;
  if (base64) {
    sig_data = DecodeBase64CMS(filename);
  } else {
    sig_data = ::pdfcsp::utils::FileToVector(filename);
  };
  if (!sig_data.has_value() || sig_data->empty()) {
    throw std::runtime_error("[Csp::IsAttached] error reading file");
  }
  constexpr const char *const parse_err_expl = "parse message failed";
  const asn::AsnObj asn_sig(sig_data->data(), sig_data->size());
  if (asn_sig.Size() < 2 ||
      asn_sig.at(0).StringData().value_or("") != asn::kOID_SignedData ||
      asn_sig.at(1).ParseChoiceNumber() != 0) {
    throw std::runtime_error(parse_err_expl);
  }
  // content
  const asn::AsnObj asn_content = asn_sig.at(1).ParseAs(asn::AsnTag::kSequence);
  if (asn_content.Size() < 1 || asn_content.at(0).Size() < 3) {
    throw std::runtime_error(parse_err_expl);
  }
  // SignedData
  const asn::AsnObj &asn_signed_data = asn_content.at(0);
  // encapContentInfo
  const asn::AsnObj &asn_encap_content_info = asn_signed_data.at(2);
  if (asn_encap_content_info.Size() < 1 ||
      asn_encap_content_info.at(0).GetAsnTag() != asn::AsnTag::kOid) {
    throw std::runtime_error(parse_err_expl);
  }
  const asn::AsnObj &asn_e_content_type = asn_encap_content_info.at(0);
  if (asn_e_content_type.StringData().value_or("") != asn::kOid_id_data) {
    throw std::runtime_error(parse_err_expl);
  }
  return asn_encap_content_info.Size() > 1;  // true if attached
}

/**
 * @brief Create a Attached File
 *
 * @param cert_serial string (lower-case) serial
 * @param cert_subject string certificate name
 * @param cades_type BES | T | X
 * @param data data to sign
 * @param dest_file full path to the destination file
 * @param tsp_link TSP service URL
 * @param encoding ASN1 | BASE64
 * @return true  on success
 */
[[nodiscard]] bool Csp::CreateSigFile(const std::string &cert_serial,
                                      const std::string &cert_subject,
                                      MessageType type, CadesType cades_type,
                                      const std::string &src_file,
                                      const std::string &dest_file,
                                      const std::wstring &tsp_link,
                                      MessageEncoding encoding) const noexcept {
  constexpr const char *func_name = "[Csp::CreateAttachedFile]";
  auto file_data = comm_utils::FileToVector(src_file);
  if (!file_data) {
    dl_->log->error("{} error reading the file, or file is empty", func_name);
    return false;
  }
  try {
    BytesVector sig_data;
    switch (type) {
      case MessageType::kAttached:
        sig_data = CreateAttached(cert_serial, cert_subject, cades_type,
                                  file_data.value(), tsp_link);
        break;
      case MessageType::kDetached:
        sig_data = SignData(cert_serial, cert_subject, cades_type,
                            file_data.value(), tsp_link);
        break;
    }
    if (sig_data.empty()) {
      dl_->log->error("{} error signing the file, signature data is empty",
                      func_name);
      return false;
    }
    switch (encoding) {
      case MessageEncoding::kAsn1:
        return comm_utils::VecToFile(sig_data, dest_file);
      case pdfcsp::csp::MessageEncoding::kBase64: {
        auto encoded = CmsEncodeBase64(sig_data);
        sig_data.clear();
        return encoded.has_value() &&
               comm_utils::VecToFile(encoded.value(), dest_file);
      }
    }
  } catch (const std::exception &ex) {
    dl_->log->error("{} error {}", func_name, ex.what());
    return false;
  }
  return true;
}

}  // namespace pdfcsp::csp