// NOLINTBEGIN
#include "resolve_symbols.hpp"
#include <dlfcn.h>
#include <stdexcept>
#include <string>

namespace pdfcsp::csp {

// NOLINTBEGIN
ResolvedSymbols::ResolvedSymbols() : log(logger::InitLog()) {
  if (!log) {
    throw std::runtime_error("Can't create log file");
  }
  std::string libcapi20(kLibDir);
  libcapi20 += kCapi20;
  std::string libcades(kLibDir);
  libcades += kCades;
  handler_capi20 = dlopen(libcapi20.c_str(), RTLD_LAZY);
  if (handler_capi20 == nullptr) {
    throw std::runtime_error("Can't load " + libcapi20);
  }
  handler_cades = dlopen(libcades.c_str(), RTLD_LAZY);
  if (handler_cades == nullptr) {
    throw std::runtime_error("Can't load " + libcades);
  }

  RESOLVE_SYMBOL(CertOpenSystemStoreA, handler_capi20)
  RESOLVE_SYMBOL(CertCloseStore, handler_capi20)
  RESOLVE_SYMBOL(CertEnumCertificatesInStore, handler_capi20)
  RESOLVE_SYMBOL(CertNameToStrA, handler_capi20)
  RESOLVE_SYMBOL(CertNameToStrW, handler_capi20)
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
  RESOLVE_SYMBOL(CryptVerifyDetachedMessageSignature, handler_capi20)
  RESOLVE_SYMBOL(CadesMsgGetSigningCertId, handler_cades)
  RESOLVE_SYMBOL(CadesFreeBlob, handler_cades)
  RESOLVE_SYMBOL(FileTimeToSystemTime, handler_capi20)
  RESOLVE_SYMBOL(CertCreateCertificateContext, handler_capi20)
  RESOLVE_SYMBOL(CryptImportKey, handler_capi20)
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
  RESOLVE_SYMBOL(CryptStringToBinaryA, handler_capi20)
  RESOLVE_SYMBOL(CadesMsgGetSigningCertIdEx, handler_cades)
  RESOLVE_SYMBOL(CertVerifyTimeValidity, handler_capi20)
  RESOLVE_SYMBOL(CertGetCertificateChain, handler_capi20)
  RESOLVE_SYMBOL(CertFreeCertificateChain, handler_capi20)
  RESOLVE_SYMBOL(CertVerifyCertificateChainPolicy, handler_capi20)
  RESOLVE_SYMBOL(CertOpenServerOcspResponse, handler_capi20)
  RESOLVE_SYMBOL(CertCloseServerOcspResponse, handler_capi20)
  RESOLVE_SYMBOL(CertGetServerOcspResponseContext, handler_capi20)
  RESOLVE_SYMBOL(CertOpenStore, handler_capi20)
  RESOLVE_SYMBOL(CertFreeServerOcspResponseContext, handler_capi20)
  RESOLVE_SYMBOL(CertAddCertificateContextToStore, handler_capi20)
  RESOLVE_SYMBOL(CadesSignHash, handler_cades);
}
// NOLINTEND

ResolvedSymbols::~ResolvedSymbols() {
  if (handler_cades != nullptr) {
    dlclose(handler_cades);
  }
  if (handler_capi20 != nullptr) {
    dlclose(handler_capi20);
  }
}

} // namespace pdfcsp::csp

// NOLINTEND