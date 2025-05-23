/* File: resolve_symbols.cpp
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

#include "resolve_symbols.hpp"

#include <dlfcn.h>

#include <stdexcept>
#include <string>

ResolvedSymbols::ResolvedSymbols() {
  std::string libcapi20(kLibDir);
  libcapi20 += kCapi20;
  std::string libcades(kLibDir);
  libcades += kCades;
  handler_capi20 = dlopen(libcapi20.c_str(), RTLD_LAZY);
  if (handler_capi20 == 0) {
    throw std::runtime_error("Can't load " + libcapi20);
  }
  handler_cades = dlopen(libcades.c_str(), RTLD_LAZY);
  if (handler_cades == 0) {
    throw std::runtime_error("Can't load " + libcades);
  }
  RESOLVE_SYMBOL(CertOpenSystemStoreA, handler_capi20)
  RESOLVE_SYMBOL(CertCloseStore, handler_capi20)
  RESOLVE_SYMBOL(CertEnumCertificatesInStore, handler_capi20)
  RESOLVE_SYMBOL(CertNameToStrA, handler_capi20)
  RESOLVE_SYMBOL(CertFindCertificateInStore, handler_capi20)
  RESOLVE_SYMBOL(CryptAcquireCertificatePrivateKey, handler_capi20)
  RESOLVE_SYMBOL(CertGetCertificateContextProperty, handler_capi20)
  RESOLVE_SYMBOL(CadesMsgOpenToEncode, handler_cades)
  RESOLVE_SYMBOL(CryptMsgUpdate, handler_capi20)
  RESOLVE_SYMBOL(CryptMsgGetParam, handler_capi20)
  RESOLVE_SYMBOL(CryptMsgClose, handler_capi20)
  RESOLVE_SYMBOL(CryptReleaseContext, handler_capi20)
  RESOLVE_SYMBOL(CertFreeCertificateContext, handler_capi20)
  RESOLVE_SYMBOL(CryptMsgOpenToDecode, handler_capi20)
  RESOLVE_SYMBOL(CadesMsgEnhanceSignature, handler_cades)
  RESOLVE_SYMBOL(GetLastError, handler_capi20)
  RESOLVE_SYMBOL(CadesMsgIsType, handler_cades)
  RESOLVE_SYMBOL(CadesMsgVerifySignature, handler_cades)
  RESOLVE_SYMBOL(CadesFreeVerificationInfo, handler_cades)
  RESOLVE_SYMBOL(CryptVerifyDetachedMessageSignature, handler_cades)
  RESOLVE_SYMBOL(CadesMsgGetSigningCertId, handler_cades)
  RESOLVE_SYMBOL(CadesFreeBlob, handler_cades)
  RESOLVE_SYMBOL(FileTimeToSystemTime, handler_cades)
  RESOLVE_SYMBOL(CertCreateCertificateContext, handler_cades)
  RESOLVE_SYMBOL(CryptImportKey, handler_cades)
  RESOLVE_SYMBOL(CryptAcquireContextA, handler_capi20)
  RESOLVE_SYMBOL(CryptDestroyKey, handler_capi20)
  RESOLVE_SYMBOL(CryptImportPublicKeyInfo, handler_capi20)
  RESOLVE_SYMBOL(CryptDecrypt, handler_capi20)
  RESOLVE_SYMBOL(CryptCreateHash, handler_capi20)
  RESOLVE_SYMBOL(CryptDestroyHash, handler_capi20)
  RESOLVE_SYMBOL(CryptHashData, handler_capi20)
  RESOLVE_SYMBOL(CryptGetHashParam, handler_capi20)
  RESOLVE_SYMBOL(CryptVerifySignatureA, handler_capi20)
  RESOLVE_SYMBOL(CryptVerifySignatureW, handler_capi20)
  RESOLVE_SYMBOL(CryptDecodeObjectEx, handler_capi20)
  RESOLVE_SYMBOL(LocalFree, handler_capi20)
  RESOLVE_SYMBOL(CadesVerifyHash, handler_cades)
  RESOLVE_SYMBOL(CryptEncodeObject, handler_capi20)
  RESOLVE_SYMBOL(CryptSetHashParam, handler_capi20)
  RESOLVE_SYMBOL(CryptImportPublicKeyInfoEx, handler_capi20)
  RESOLVE_SYMBOL(CryptMsgControl, handler_capi20)
  RESOLVE_SYMBOL(CryptSignHashA, handler_capi20)
  RESOLVE_SYMBOL(CryptSignHashW, handler_capi20)
  RESOLVE_SYMBOL(CryptHashSessionKey, handler_capi20)
}

ResolvedSymbols::~ResolvedSymbols() {
  if (handler_cades != nullptr) {
    dlclose(handler_cades);
  }
  if (handler_capi20 != nullptr) {
    dlclose(handler_capi20);
  }
}
