#include "CSP_WinDef.h"
#include <iostream>
#include <vector>

#define UNIX
#define SIZEOF_VOID_P 8
#define IGNORE_LEGACY_FORMAT_MESSAGE_MSG

#include "cades.h"

constexpr const char* const delimiter="--------------------------------------------\n";

BOOL CertEnumSystemStoreCallback(const void *pvSystemStore,DWORD dwFlags,PCERT_SYSTEM_STORE_INFO pStoreInfo,void *pvReserved,void *pvArg){
    std::cout << static_cast<const char*>(pvSystemStore)<<"\n";
    std::cout <<"dwFlags = "<< std::hex << dwFlags<<"\n";
    switch (dwFlags){
        case CERT_SYSTEM_STORE_LOCATION_MASK:
            std::cout <<"CERT_SYSTEM_STORE_LOCATION_MASK\n";
            break;
        case CERT_SYSTEM_STORE_RELOCATE_FLAG:
            std::cout << "CERT_SYSTEM_STORE_RELOCATE_FLAG\n";
            break;
         case (CERT_SYSTEM_STORE_RELOCATE_FLAG | CERT_SYSTEM_STORE_LOCATION_MASK):
            std::cout <<"CERT_SYSTEM_STORE_RELOCATE_FLAG | CERT_SYSTEM_STORE_LOCATION_MASK\n";
            break;
    }
    std::cout << "pStoreInfo = "<< pStoreInfo<<"\n";
    return TRUE;
}

int main(){
    //enum stores
    // void* ptr=nullptr;
    // int res=CertEnumSystemStore(CERT_SYSTEM_STORE_CURRENT_USER,0,ptr,CertEnumSystemStoreCallback);
    // std::cout << "res = "<< res <<"\n";
    // if (res==FALSE){
    //     std::cout << std::hex<<GetLastError() <<"\n";
    // }

    // open store
    // Only current user certificates are accessible using this method, not the local machine store.
     HCERTSTORE h_store= CertOpenSystemStoreA(0,"MY");
     if (h_store==nullptr) {
        std::cout << "error opening store\n";
     }
     else {
        std::cout << "Open store ... OK\n";
     }

     // enum certificates
     std::cout << "List of certificates:\n";
     PCCERT_CONTEXT p_cert_context=nullptr;
     while((p_cert_context= CertEnumCertificatesInStore(h_store,p_cert_context))){
        std::cout << delimiter;
        // encoding 
        switch (p_cert_context->dwCertEncodingType) {
            case X509_ASN_ENCODING:
                std::cout <<"X509_ASN_ENCODING\n";
                break;
            case PKCS_7_ASN_ENCODING:
                std::cout <<"PKCS_7_ASN_ENCODING\n";
            case X509_ASN_ENCODING | PKCS_7_ASN_ENCODING:
                std::cout << "PKCS_7_ASN_ENCODING | X509_ASN_ENCODING\n";
                break;
            default:
                std::cout << "Unclear "<< std::hex << p_cert_context->dwCertEncodingType;            
        }        
        // certificate info
        if (p_cert_context->pCertInfo==nullptr){
            std::cout << "No certificate info\n";
            continue;
        }
        std::cout << "version = " << p_cert_context->pCertInfo->dwVersion << "\n";
        DWORD index_last= p_cert_context->pCertInfo->SerialNumber.cbData-1;
        std::cout << "serial = ";
        for (int i=index_last;i>=0;--i){
            std::cout <<std::hex<< static_cast<int>(p_cert_context->pCertInfo->SerialNumber.pbData[i]);
        }
        std::cout <<"\n";
        std::cout << "signature algorithm = ";
        std::string alg(p_cert_context->pCertInfo->SignatureAlgorithm.pszObjId);
        if (alg==std::string(szOID_CP_GOST_R3411_12_256_R3410)){
            std::cout << "Алгоритм цифровой подписи ГОСТ Р 34.10-2012 для ключей длины 256 бит \n";
        }
        else {
            std::cout << p_cert_context->pCertInfo->SignatureAlgorithm.pszObjId;   
        }        
        // issuer
        {        
            CERT_NAME_BLOB& issuerNameBlob = p_cert_context->pCertInfo->Issuer;
            DWORD dwSize = CertNameToStrA(X509_ASN_ENCODING, &issuerNameBlob, CERT_X500_NAME_STR, nullptr, 0);
            std::string issuerString(dwSize, '\0');
            CertNameToStrA(X509_ASN_ENCODING, &issuerNameBlob, CERT_X500_NAME_STR, &issuerString[0], dwSize);
            std::cout <<issuerString<<"\n";
        }
        // name
        {
         CERT_NAME_BLOB& subject_blob = p_cert_context->pCertInfo->Subject;
         DWORD dwSize = CertNameToStrA(X509_ASN_ENCODING, &subject_blob, CERT_X500_NAME_STR, nullptr, 0);
         std::cout << "Name = ";
         std::string cert_name(dwSize, '\0');
         CertNameToStrA(X509_ASN_ENCODING, &subject_blob, CERT_X500_NAME_STR, &cert_name[0], dwSize);
         std::cout << cert_name << "\n";
        }
     }



     // close the store
     CertCloseStore(h_store,0);
     

}