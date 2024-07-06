#include "lib_resolve.hpp"
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
}

ResolvedSymbols::~ResolvedSymbols(){
    if (handler_cades != nullptr){
        dlclose(handler_cades);
    }
    if (handler_capi20 != nullptr){
        dlclose(handler_capi20);
    }
}
