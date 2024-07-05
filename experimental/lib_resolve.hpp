#pragma once
#define UNIX
#define SIZEOF_VOID_P 8
#define IGNORE_LEGACY_FORMAT_MESSAGE_MSG

#include "CSP_WinCrypt.h"
#include "CSP_WinDef.h"



#define RESOLVE_FUNCTION_TYPE(returnType, functionName, ...) \
   typedef returnType (*ptr_##functionName)(__VA_ARGS__);

#define DECLARE_MEMBER(functionName) \
   ptr_##functionName dl_##functionName=nullptr;

#define RESOLVE_SYMBOL(functionName,libHandle) \
    dl_##functionName = reinterpret_cast<ptr_##functionName>(dlsym(libHandle,#functionName));


RESOLVE_FUNCTION_TYPE(HCERTSTORE,CertOpenSystemStoreA,HCRYPTPROV,LPCSTR)

constexpr const char* kLibDir="/opt/cprocsp/lib/amd64/";
constexpr const char* kCapi20="libcapi20.so";

struct ResolvedSymbols{
    //ptr_CertOpenSystemStoreA dl_CertOpenSystemStoreA=nullptr;
    DECLARE_MEMBER(CertOpenSystemStoreA)

    ResolvedSymbols();
};

void ResolveSymbols();