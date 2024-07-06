#pragma once
#define UNIX
#define SIZEOF_VOID_P 8
#define IGNORE_LEGACY_FORMAT_MESSAGE_MSG
#undef _WIN32

#include <type_traits>

#include "CSP_WinCrypt.h"
#include "cades.h"

// these macros can be redefined by cades.h
#undef __out
#undef __in
#undef __in_opt
#undef __out_opt
#undef __reserved

// using type ptr_function = pointer to function
#define FUNCTION_POINTER_TYPEDEF(funcName)                                     \
  using ptr_##funcName = std::add_pointer<decltype(funcName)>::type;

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

FUNCTION_POINTER_TYPEDEF(CertOpenSystemStoreA)
FUNCTION_POINTER_TYPEDEF(CertCloseStore)
FUNCTION_POINTER_TYPEDEF(CertEnumCertificatesInStore)
FUNCTION_POINTER_TYPEDEF(CertNameToStrA)
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

struct ResolvedSymbols {
  DECLARE_MEMBER(CertOpenSystemStoreA)
  DECLARE_MEMBER(CertCloseStore)
  DECLARE_MEMBER(CertEnumCertificatesInStore)
  DECLARE_MEMBER(CertNameToStrA)
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
  ResolvedSymbols();
};

constexpr const char *kLibDir = "/opt/cprocsp/lib/amd64/";
constexpr const char *kCapi20 = "libcapi20.so";
constexpr const char *kCades = "libcades.so";

// #define RESOLVE_FUNCTION_TYPE(returnType, functionName, ...) \
//    typedef returnType (*ptr_##functionName)(__VA_ARGS__);
// RESOLVE_FUNCTION_TYPE(HCERTSTORE,CertOpenSystemStoreA,HCRYPTPROV,LPCSTR)
// RESOLVE_FUNCTION_TYPE(BOOL, CertCloseStore,HCERTSTORE,DWORD);
// RESOLVE_FUNCTION_TYPE(PCCERT_CONTEXT,
// CertEnumCertificatesInStore,HCERTSTORE,PCCERT_CONTEXT)
// RESOLVE_FUNCTION_TYPE(DWORD, CertNameToStrA,
// DWORD,PCERT_NAME_BLOB,DWORD,LPSTR,DWORD)
// RESOLVE_FUNCTION_TYPE(PCCERT_CONTEXT,CertFindCertificateInStore,HCERTSTORE,DWORD,DWORD,DWORD,const
// void *,PCCERT_CONTEXT)
// RESOLVE_FUNCTION_TYPE(BOOL,CryptAcquireCertificatePrivateKey,PCCERT_CONTEXT,DWORD,void
// * ,HCRYPTPROV *,DWORD *,BOOL *) RESOLVE_FUNCTION_TYPE(BOOL,
// CertGetCertificateContextProperty,PCCERT_CONTEXT,DWORD,void *,DWORD *)
// RESOLVE_FUNCTION_TYPE(HCRYPTMSG,
// CadesMsgOpenToEncode,DWORD,DWORD,PCADES_ENCODE_INFO,LPSTR,PCMSG_STREAM_INFO)