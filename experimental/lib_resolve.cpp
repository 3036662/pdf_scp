
#include "lib_resolve.hpp"
#include <string>
#include <dlfcn.h>
#include <string>
#include <iostream>
#include "cades.h"


ResolvedSymbols::ResolvedSymbols(){
    std::string libcapi20(kLibDir);
    libcapi20+=kCapi20;
    void* handle_capi20 = dlopen(libcapi20.c_str(),RTLD_LAZY);
    // dl_CertOpenSystemStoreA=reinterpret_cast<ptr_CertOpenSystemStoreA>(dlsym(handle_capi20,"CertOpenSystemStoreA"));
    RESOLVE_SYMBOL(CertOpenSystemStoreA,handle_capi20)
    //std::cout<<std::hex <<dl_CertOpenSystemStoreA;
}


//int main(){
//   //  ResolveSymbols();
//     return 0;
// }