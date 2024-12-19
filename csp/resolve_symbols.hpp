/* File: resolve_symbols.hpp  
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

#include "logger_utils.hpp"
#include <spdlog/logger.h>

// NOLINTBEGIN
#define UNIX

#ifndef SIZEOF_VOID_P
#define SIZEOF_VOID_P 8
#endif

#define IGNORE_LEGACY_FORMAT_MESSAGE_MSG
#undef _WIN32

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Winvalid-utf8"
#include <CSP_WinCrypt.h> /// NOLINT
#include <CSP_WinDef.h>   /// NOLINT
#include <cades.h>        /// NOLINT
#include <cstdarg>
#undef __out
#undef __in
#undef __in_opt
#undef __out_opt
#undef __reserved

#pragma GCC diagnostic pop

// these macros can be redefined by cades.h - conflicts with std library
#undef __out
#undef __in
#undef __in_opt
#undef __out_opt
#undef __reserved

#include <memory>
#include <type_traits>

// using type ptr_function = pointer to function
#define FUNCTION_POINTER_TYPEDEF(funcName)                                     \
  using ptr_##funcName = std::add_pointer_t<decltype(funcName)>;

// declare ptr_function dl_function=nullptr;
#define DECLARE_MEMBER(functionName)                                           \
  ptr_##functionName dl_##functionName = nullptr;

// resolve a symbol with dlsym
#define RESOLVE_SYMBOL(functionName, libHandle)                                \
  dl_##functionName =                                                          \
      reinterpret_cast<ptr_##functionName>(dlsym(libHandle, #functionName));   \
  if (dl_##functionName == nullptr) {                                          \
    throw std::runtime_error(std::string("Can't resolve symbol") +             \
                             #functionName);                                   \
  };

namespace pdfcsp::csp {

FUNCTION_POINTER_TYPEDEF(CertOpenSystemStoreA)
FUNCTION_POINTER_TYPEDEF(CertCloseStore)
FUNCTION_POINTER_TYPEDEF(CertEnumCertificatesInStore)
FUNCTION_POINTER_TYPEDEF(CertNameToStrA)
FUNCTION_POINTER_TYPEDEF(CertNameToStrW)
FUNCTION_POINTER_TYPEDEF(CertFindCertificateInStore)
FUNCTION_POINTER_TYPEDEF(CryptAcquireCertificatePrivateKey)
FUNCTION_POINTER_TYPEDEF(CertGetCertificateContextProperty)
FUNCTION_POINTER_TYPEDEF(CadesMsgOpenToEncode)
FUNCTION_POINTER_TYPEDEF(CryptMsgUpdate)
FUNCTION_POINTER_TYPEDEF(CryptMsgGetParam)
FUNCTION_POINTER_TYPEDEF(CryptMsgClose)
FUNCTION_POINTER_TYPEDEF(CryptReleaseContext)
FUNCTION_POINTER_TYPEDEF(CertFreeCertificateContext)
FUNCTION_POINTER_TYPEDEF(CryptMsgOpenToDecode)
FUNCTION_POINTER_TYPEDEF(CadesMsgEnhanceSignature)
FUNCTION_POINTER_TYPEDEF(GetLastError)
FUNCTION_POINTER_TYPEDEF(CadesMsgIsType)
FUNCTION_POINTER_TYPEDEF(CadesMsgVerifySignature)
FUNCTION_POINTER_TYPEDEF(CadesFreeVerificationInfo)
FUNCTION_POINTER_TYPEDEF(CryptVerifyDetachedMessageSignature)
FUNCTION_POINTER_TYPEDEF(CadesMsgGetSigningCertId)
FUNCTION_POINTER_TYPEDEF(CadesFreeBlob)
FUNCTION_POINTER_TYPEDEF(FileTimeToSystemTime)
FUNCTION_POINTER_TYPEDEF(CertCreateCertificateContext)
FUNCTION_POINTER_TYPEDEF(CryptImportKey)
FUNCTION_POINTER_TYPEDEF(CryptAcquireContextA)
FUNCTION_POINTER_TYPEDEF(CryptDestroyKey)
FUNCTION_POINTER_TYPEDEF(CryptImportPublicKeyInfo)
FUNCTION_POINTER_TYPEDEF(CryptDecrypt)
FUNCTION_POINTER_TYPEDEF(CryptCreateHash)
FUNCTION_POINTER_TYPEDEF(CryptDestroyHash)
FUNCTION_POINTER_TYPEDEF(CryptHashData)
FUNCTION_POINTER_TYPEDEF(CryptGetHashParam)
FUNCTION_POINTER_TYPEDEF(CryptVerifySignatureA)
FUNCTION_POINTER_TYPEDEF(CryptVerifySignatureW)
FUNCTION_POINTER_TYPEDEF(CryptDecodeObjectEx)
FUNCTION_POINTER_TYPEDEF(LocalFree)
FUNCTION_POINTER_TYPEDEF(CadesVerifyHash)
FUNCTION_POINTER_TYPEDEF(CryptEncodeObject)
FUNCTION_POINTER_TYPEDEF(CryptSetHashParam)
FUNCTION_POINTER_TYPEDEF(CryptImportPublicKeyInfoEx)
FUNCTION_POINTER_TYPEDEF(CryptMsgControl)
FUNCTION_POINTER_TYPEDEF(CryptSignHashA)
FUNCTION_POINTER_TYPEDEF(CryptSignHashW)
FUNCTION_POINTER_TYPEDEF(CryptHashSessionKey)
FUNCTION_POINTER_TYPEDEF(CryptStringToBinaryA)
FUNCTION_POINTER_TYPEDEF(CadesMsgGetSigningCertIdEx)
FUNCTION_POINTER_TYPEDEF(CertVerifyTimeValidity)
FUNCTION_POINTER_TYPEDEF(CertGetCertificateChain)
FUNCTION_POINTER_TYPEDEF(CertFreeCertificateChain)
FUNCTION_POINTER_TYPEDEF(CertVerifyCertificateChainPolicy)
FUNCTION_POINTER_TYPEDEF(CertOpenServerOcspResponse)
FUNCTION_POINTER_TYPEDEF(CertCloseServerOcspResponse)
FUNCTION_POINTER_TYPEDEF(CertGetServerOcspResponseContext)
FUNCTION_POINTER_TYPEDEF(CertOpenStore)
FUNCTION_POINTER_TYPEDEF(CertFreeServerOcspResponseContext)
FUNCTION_POINTER_TYPEDEF(CertAddCertificateContextToStore)
FUNCTION_POINTER_TYPEDEF(CadesSignHash)
/**
 * @brief Resolve CSP symbols.All functions will have prefix dl_ (dl_funcName)
 * @throws std::runtime_error if can't resolve
 */
struct ResolvedSymbols {
  void *handler_capi20 = nullptr;
  void *handler_cades = nullptr;
  DECLARE_MEMBER(CertOpenSystemStoreA)
  DECLARE_MEMBER(CertCloseStore)
  DECLARE_MEMBER(CertEnumCertificatesInStore)
  DECLARE_MEMBER(CertNameToStrA)
  DECLARE_MEMBER(CertNameToStrW)
  DECLARE_MEMBER(CertFindCertificateInStore)
  DECLARE_MEMBER(CryptAcquireCertificatePrivateKey)
  DECLARE_MEMBER(CertGetCertificateContextProperty)
  DECLARE_MEMBER(CadesMsgOpenToEncode)
  DECLARE_MEMBER(CryptMsgUpdate)
  DECLARE_MEMBER(CryptMsgGetParam)
  DECLARE_MEMBER(CryptMsgClose)
  DECLARE_MEMBER(CryptReleaseContext)
  DECLARE_MEMBER(CertFreeCertificateContext)
  DECLARE_MEMBER(CryptMsgOpenToDecode)
  DECLARE_MEMBER(CadesMsgEnhanceSignature)
  DECLARE_MEMBER(GetLastError)
  DECLARE_MEMBER(CadesMsgIsType)
  DECLARE_MEMBER(CadesMsgVerifySignature)
  DECLARE_MEMBER(CadesFreeVerificationInfo)
  DECLARE_MEMBER(CryptVerifyDetachedMessageSignature)
  DECLARE_MEMBER(CadesMsgGetSigningCertId)
  DECLARE_MEMBER(CadesFreeBlob)
  DECLARE_MEMBER(FileTimeToSystemTime)
  DECLARE_MEMBER(CertCreateCertificateContext)
  DECLARE_MEMBER(CryptImportKey)
  DECLARE_MEMBER(CryptAcquireContextA)
  DECLARE_MEMBER(CryptDestroyKey)
  DECLARE_MEMBER(CryptImportPublicKeyInfo)
  DECLARE_MEMBER(CryptDecrypt)
  DECLARE_MEMBER(CryptCreateHash)
  DECLARE_MEMBER(CryptDestroyHash)
  DECLARE_MEMBER(CryptHashData)
  DECLARE_MEMBER(CryptGetHashParam)
  DECLARE_MEMBER(CryptVerifySignatureA)
  DECLARE_MEMBER(CryptVerifySignatureW)
  DECLARE_MEMBER(CryptDecodeObjectEx)
  DECLARE_MEMBER(LocalFree)
  DECLARE_MEMBER(CadesVerifyHash)
  DECLARE_MEMBER(CryptEncodeObject)
  DECLARE_MEMBER(CryptSetHashParam)
  DECLARE_MEMBER(CryptImportPublicKeyInfoEx)
  DECLARE_MEMBER(CryptMsgControl)
  DECLARE_MEMBER(CryptSignHashA)
  DECLARE_MEMBER(CryptSignHashW)
  DECLARE_MEMBER(CryptHashSessionKey)
  DECLARE_MEMBER(CryptStringToBinaryA)
  DECLARE_MEMBER(CadesMsgGetSigningCertIdEx)
  DECLARE_MEMBER(CertVerifyTimeValidity)
  DECLARE_MEMBER(CertGetCertificateChain)
  DECLARE_MEMBER(CertFreeCertificateChain)
  DECLARE_MEMBER(CertVerifyCertificateChainPolicy)
  DECLARE_MEMBER(CertOpenServerOcspResponse)
  DECLARE_MEMBER(CertCloseServerOcspResponse)
  DECLARE_MEMBER(CertGetServerOcspResponseContext)
  DECLARE_MEMBER(CertOpenStore)
  DECLARE_MEMBER(CertFreeServerOcspResponseContext)
  DECLARE_MEMBER(CertAddCertificateContextToStore)
  DECLARE_MEMBER(CadesSignHash)

  std::shared_ptr<spdlog::logger> log;

  /**
   * @brief Construct a new Resolved Symbols object
   * @throws std::runtime_error
   */
  ResolvedSymbols();
  ~ResolvedSymbols();
};

using PtrSymbolResolver = std::shared_ptr<ResolvedSymbols>;

constexpr const char *kLibDir = "/opt/cprocsp/lib/amd64/";
constexpr const char *kCapi20 = "libcapi20.so";
constexpr const char *kCades = "libcades.so";

} // namespace pdfcsp::csp

// NOLINTEND