#include "CSP_WinCrypt.h"
#include "CSP_WinDef.h"
#include <iostream>
#include <string>
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

    //// ------------------------------------------------------------------
    // open store
    // Only current user certificates are accessible using this method, not the local machine store.
     HCERTSTORE h_store= CertOpenSystemStoreA(0,"MY");
     if (h_store==nullptr) {
        std::cout << "error opening store\n";
     }
     else {
        std::cout << "Open store ... OK\n";
     }

     // ------------------------------------------------------------------   
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


     // ------------------------------------------------------------------
     // now test CertFindCertificateInStore
     // [in] hCertStore - A handle of the certificate store
     // [in] dwCertEncodingType X509_ASN_ENCODING | PKCS_7_ASN_ENCODING
     // [in] dwFindFlags Used with some dwFindType values to modify the search criteria. For most dwFindType values, dwFindFlags is not used and should be set to zero. For detailed information, see Remarks.
     // [in] dwFindType  CERT_FIND_SUBJECT_STR = CERT_FIND_SUBJECT_STR_W = 0x80007 Data type of pvFindPara: Null-terminated Unicode string. Searches for a certificate that contains the specified subject name 
     // [in] pvFindPara Points to a data item or structure used with dwFindType.
     // [in] pPrevCertContext A pointer to the last CERT_CONTEXT structure returned by this function. This parameter must be NULL on the first call of the function.   
     //      CERT_FIND_ANY No search criteria used. Returns the next certificate in the store.
     // return If the function succeeds, the function returns a pointer to a read-only CERT_CONTEXT structure.
     //  must be freed by CertFreeCertificateContext or by being passed as the pPrevCertContext parameter on a subsequent call to CertFindCertificateInStore.

     /*
      A CERT_CONTEXT structure that contains a handle to a certificate store, 
      a pointer to the original encoded certificate BLOB, a pointer to a CERT_INFO structure,
      and an encoding type member. It is the CERT_INFO structure that contains most of the certificate information.
     */
    
     PCCERT_CONTEXT p_cert_ctx = CertFindCertificateInStore(h_store,X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,0,CERT_FIND_ANY,nullptr,nullptr);
     if (p_cert_ctx == nullptr){
        std::cout << "can't get any sertificates\n";
     }
     else{
        std::cout << "Get certificate context ... OK\n";
     }


    std::cout <<delimiter;
    if (p_cert_ctx==nullptr){
         CertCloseStore(h_store,0);
         return 0;
    }

    // ------------------------------------------------------------------
    // now try to get a private key for certificate
    /*
    BOOL CryptAcquireCertificatePrivateKey(
    [in]           PCCERT_CONTEXT                  pCert, The address of a CERT_CONTEXT structure 
    [in]           DWORD                           dwFlags,
    [in, optional] void                            *pvParameters,
    [out]          HCRYPTPROV_OR_NCRYPT_KEY_HANDLE *phCryptProvOrNCryptKey, The address of an HCRYPTPROV_OR_NCRYPT_KEY_HANDLE 
                                                    variable that receives the handle of either the CryptoAPI provider or the CNG key. 
    [out]          DWORD                           *pdwKeySpec,
    [out]          BOOL                            *pfCallerFreeProvOrNCryptKey
    );
    */
    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE csp_provider=0;
    DWORD key_additional_info = 0;
    /*
    If this variable receives TRUE, the caller is responsible for releasing the handle returned in 
    the phCryptProvOrNCryptKey variable. If the pdwKeySpec variable receives the CERT_NCRYPT_KEY_SPEC value, 
    the handle must be released by passing it to the NCryptFreeObject function; otherwise, 
    the handle is released by passing it to the CryptReleaseContext function.
    */
    BOOL caller_must_free =0;
    //function obtains the private key for a certificate
    BOOL res= CryptAcquireCertificatePrivateKey(
        p_cert_ctx,
        0,
        0,
        &csp_provider,
        &key_additional_info,
        &caller_must_free);
        if (res==FALSE){
    std::cout << "error getting private key\n";
    }
    else {
    std::cout << "get private key ...OK\n";
    }
    // additional info about the key
    if (res!=FALSE){
    switch (key_additional_info) {
        case AT_KEYEXCHANGE:
            std::cout<< "The key is AT_KEYEXCHANGE\n";
            break;
        case AT_SIGNATURE:
            std::cout << "The key is AT_SIGNATURE\n";
            break;
        default:
            std::cout << "Additional key info flag is not recognized\n";
            break;
    }
    }
    // must free
    std::cout << ( caller_must_free == TRUE ? "caller must free the handle" : "caller must NOT free the handle") <<"\n";
    // ------------------------------------------------------------------
    // retrieve the information contained in an extended property of certiface context
    
    /*
    retrieves the information contained in an extended property of a certificate context.
    BOOL CertGetCertificateContextProperty(
        [in]      PCCERT_CONTEXT pCertContext, A pointer to the CERT_CONTEXT 
        [in]      DWORD          dwPropId, The property to be retrieved. 
        [out]     void           *pvData, 
        [in, out] DWORD          *pcbData
        );
    */

    /*
      CERT_KEY_PROV_INFO_PROP_ID
      it stores the key provider information within the certificate context. 
      The key provider information includes details such as the cryptographic provider type, 
      provider name, key container name, and other relevant parameters needed to access the private 
      key associated with the certificate.
    */

    DWORD buff_size = 0;
    res = CertGetCertificateContextProperty(p_cert_ctx,CERT_KEY_PROV_INFO_PROP_ID,0,&buff_size);
    if (res == FALSE){
        std::cout << "Get certificate property ... FAILED\n";
    }
    std::vector<BYTE> buff(buff_size,0);
    res = CertGetCertificateContextProperty(p_cert_ctx,CERT_KEY_PROV_INFO_PROP_ID,buff.data(),&buff_size);
    std::cout << "Get certificate property ..."<< (res == TRUE ? "OK" : "FAILED") <<"\n";
    // debug print prop
    // std::string prop;
    // prop.assign(reinterpret_cast<const char*>(buff.data()),buff_size);
    // std::cout << prop<<"\n";
    // ------------------------------------------------------------------
    // free csp context
    if (caller_must_free==TRUE){
        int res= CryptReleaseContext(csp_provider, 0);
        std::cout << "release crypto context ..."<< (res==TRUE ? "OK" : "FAILED") <<"\n";        
    }
    // free cert context
    if (p_cert_ctx!=nullptr){
        CertFreeCertificateContext(p_cert_ctx);
    }
    // close the store
    CertCloseStore(h_store,0);
     

}