#include "CSP_WinCrypt.h"
#include "CSP_WinDef.h"
#include "resolve_symbols.hpp"

#include <cstddef>
#include <fstream>
#include <ios>
#include <iterator>
#include <qpdf/QPDF.hh>
#include <qpdf/QPDFAcroFormDocumentHelper.hh>
#include <qpdf/QPDFAnnotationObjectHelper.hh>
#include <qpdf/QPDFObjectHandle.hh>
#include <qpdf/QPDFPageObjectHelper.hh>
#include <qpdf/QUtil.hh>
#include <vector>

constexpr const char* file_win="/home/oleg/dev/eSign/pdf_tool/test_files/0207_signed_win.pdf";
constexpr const char* file_fns="/home/oleg/dev/eSign/pdf_tool/test_files/fns_1.pdf";
constexpr const char* file_okular="/home/oleg/dev/eSign/pdf_tool/test_files/02_07_okular.pdf";

void CheckRes(BOOL res,const std::string& func_name,const ResolvedSymbols& symbols){
    std::cout << func_name << "..." << (res==TRUE ? "OK" : "FALSE")<<"\n";
    if (res != TRUE){
        std::cout << "Error "<<std::hex<< symbols.dl_GetLastError() << "\n";
    }
}

std::string VecToStr(const std::vector<BYTE>& vec){
    std::string res;
    std::copy(vec.cbegin(),vec.cend(),std::back_inserter(res));
    return res;
}

int main(){
    QPDF pdf;
    pdf.processFile(file_win);
    std::cout << "Vesrion = " << pdf.getPDFVersion() << "\n";
    std::cout << "Number of objects = " << pdf.getObjectCount() << "\n";
    auto obj_root = pdf.getRoot();
    if (!obj_root.hasKey("/AcroForm")){
        std::cout << "AcroForm is not found\n";
        return 0;
    }
    auto obj_acro =obj_root.getKey("/AcroForm");
    if (!obj_acro.isDictionary()){
        std::cout << "No DICT in AcroForm\n";
        return 0;
    }
    if (!obj_acro.hasKey("/Fields")){
        std::cout << "No fields in the AcroForm\n";
        return 0;
    }
    auto acro_fields=obj_acro.getKey("/Fields");
    if (!acro_fields.isArray()){
        std::cout << "Acro /Fields is not an array\n";
        return 0;
    }
    std::string signature_content;
    for (int i=0;i<acro_fields.getArrayNItems();++i){
        QPDFObjectHandle field = acro_fields.getArrayItem(i);
        if (field.isDictionary() && 
            field.hasKey("/FT") && 
            field.getKey("/FT").isName() &&
            field.getKey("/FT").getName() == "/Sig"
            ){
              std::cout << "Found the signature field\n";
              if (field.hasKey("/T")){
                std::cout << field.getKey("/T").getStringValue() <<"\n";
              }
              if (!field.hasKey("/V")){
                std::cout << "No value of signature\n";
                return 0;
              } 
              auto signature_v = field.getKey("/V");
              // optional check
              if (!signature_v.isDictionary() || 
                  !signature_v.hasKey("/Type") ||
                  !signature_v.getKey("/Type").isName() ||
                  signature_v.getKey("/Type").getName() != "/Sig"){
                    std::cout << "Invalid Signature\n";
                    return 0;
             }
             if (!signature_v.hasKey("/Filter") || 
                 !signature_v.getKey("/Filter").isName()){
                 std::cout << "Invalid /Filter field in signature";
                 return 0;       
             }
             std::cout << "Signature handler "<< signature_v.getKey("/Filter").getName() <<"\n";
             if (!signature_v.hasKey("/Contents")){
                std::cout << "No signature content was found\n";
             }  
             signature_content=signature_v.getKey("/Contents").unparse();
             std::cout << "Extract signature value ... OK\n";
             std::cout << "The signature size = " << signature_content.size() << "\n";
             break;    
        }
    }

    // not try to do something with signature
    ResolvedSymbols symbols;
    
    std::vector<unsigned char> sig_data;
    {
        std::string decoded_sign_content=QUtil::hex_decode(signature_content);
        //std::cout << decoded_sign_content <<"\n";
        std::copy(decoded_sign_content.data(),decoded_sign_content.data()+decoded_sign_content.size(),std::back_inserter(sig_data));
    }
    std::cout << "vector size = "<< sig_data.size() << "\n";
    HCRYPTMSG handler_message =symbols.dl_CryptMsgOpenToDecode(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, 0, 0, 0, 0);
    if (handler_message==nullptr){
        std::cout << "Open to Decode ... FAILED\n";
        symbols.dl_CryptMsgClose(handler_message);
        return 0;
    }
    BOOL res = symbols.dl_CryptMsgUpdate(handler_message,sig_data.data(),sig_data.size(),TRUE);
    std::cout << "Update msg ... "<<(res==TRUE ? "OK" : "FAIL" ) << "\n";
    // check the sign type
    BOOL check_result=false;
    symbols.dl_CadesMsgIsType(handler_message,0,CADES_BES,&check_result);
    std::cout << "Check for BES ..." << (check_result==TRUE ? "OK": "FAIL") <<"\n";
    symbols.dl_CadesMsgIsType(handler_message,0,CADES_T,&check_result);
    std::cout << "Check for CADES_T ..." << (check_result==TRUE ? "OK": "FAIL") <<"\n";
    symbols.dl_CadesMsgIsType(handler_message,0,CADES_X_LONG_TYPE_1,&check_result);
    std::cout << "Check for CADES_X_LONG_TYPE_1 ..." << (check_result==TRUE ? "OK": "FAIL") <<"\n";
    symbols.dl_CadesMsgIsType(handler_message,0,PKCS7_TYPE,&check_result);
    std::cout << "Check for PKCS7_TYPE ..." << (check_result==TRUE ? "OK": "FAIL") <<"\n";

    // write signature to file
    // std::ofstream output_file("sig_from_pdf.dat",std::ios_base::binary);
    // std::string decoded_sign_content=QUtil::hex_decode(signature_content);
    // output_file.write(decoded_sign_content.data(), decoded_sign_content.size());
    // output_file.close();
    // std::cout << "write to file ... OK\n";

    // TODO get certificate and public key
    // TODO verify certificate chain
    
    // get the signer certificate
    
    // get number of signers
    {
        std::cout<<"---\n";
        DWORD buff_size=sizeof(DWORD);
        DWORD number_of_singners=0;
        res = symbols.dl_CryptMsgGetParam(handler_message,CMSG_SIGNER_COUNT_PARAM,0,&number_of_singners,&buff_size);
        CheckRes(res,"Get CMSG_SIGNER_COUNT_PARAM number of signers",symbols);
        std::cout << "number of signers = " << number_of_singners <<std::endl;
    }

    // get number of revoked certificates
    {
        std::cout<<"---\n";
        DWORD buff_size=sizeof(DWORD);
        DWORD number_of_revoces=0;
        res = symbols.dl_CryptMsgGetParam(handler_message,CMSG_CRL_COUNT_PARAM,0,&number_of_revoces,&buff_size);
        CheckRes(res,"Get CMSG_CRL_COUNT_PARAM number of revoces",symbols);
        std::cout << "number of revoces = " << number_of_revoces <<std::endl;
    }

    // Signer sertificate 
    {
        std::cout<<"---\n";
        DWORD buff_size=0;
        res = symbols.dl_CryptMsgGetParam(handler_message,CMSG_CERT_PARAM,0,0,&buff_size);
        CheckRes(res,"Get CMSG_CERT_PARAM signer certificate size",symbols);
        std::cout << " certificate size = "<< buff_size << "\n";
        std::vector<BYTE> buff(buff_size,0);
        res = symbols.dl_CryptMsgGetParam(handler_message,CMSG_CERT_PARAM,0,buff.data(),&buff_size);
        CheckRes(res,"Get CMSG_CERT_PARAM signer certificate",symbols);
        //std::cout << "Certificate = " << VecToStr(buff) <<std::endl;
    }


    // get  hash COMPUTED_HASH
    {
        std::cout<<"---\n";
        DWORD buff_size=0;
        res = symbols.dl_CryptMsgGetParam(handler_message,CMSG_COMPUTED_HASH_PARAM,0,0,&buff_size);
        CheckRes(res,"Get CMSG_COMPUTED_HASH_PARAM hash size",symbols);
        std::cout << " hash size = "<< buff_size << "\n";
        std::vector<BYTE> buff(buff_size,0);
        res = symbols.dl_CryptMsgGetParam(handler_message,CMSG_COMPUTED_HASH_PARAM,0,buff.data(),&buff_size);
        CheckRes(res,"Get CMSG_COMPUTED_HASH_PARAM hash",symbols);
        std::cout << "COMPUTED_HASH = " << VecToStr(buff) <<std::endl;
    }  


     // get  CMSG_HASH_DATA_PARAM 
    {
        std::cout<<"---\n";
        DWORD buff_size=0;
        res = symbols.dl_CryptMsgGetParam(handler_message,CMSG_HASH_DATA_PARAM,0,0,&buff_size);
        CheckRes(res,"Get CMSG_HASH_DATA_PARAM size",symbols);
        std::cout << " CMSG_HASH_DATA_PARAM size = "<< buff_size << "\n";
        std::vector<BYTE> buff(buff_size,0);
        res = symbols.dl_CryptMsgGetParam(handler_message,CMSG_HASH_DATA_PARAM,0,buff.data(),&buff_size);
        CheckRes(res,"Get CMSG_HASH_DATA_PARAM",symbols);
        std::cout << "hash = " << VecToStr(buff) <<std::endl;
    } 

    // get  CMSG_ENCRYPTED_DIGEST 
    {
        std::cout<<"---\n";
        DWORD buff_size=0;
        res = symbols.dl_CryptMsgGetParam(handler_message,CMSG_ENCRYPTED_DIGEST,0,0,&buff_size);
        CheckRes(res,"Get CMSG_ENCRYPTED_DIGEST size",symbols);
        std::cout << " CMSG_ENCRYPTED_DIGEST size = "<< buff_size << "\n";
        std::vector<BYTE> buff(buff_size,0);
        res = symbols.dl_CryptMsgGetParam(handler_message,CMSG_ENCRYPTED_DIGEST,0,buff.data(),&buff_size);
        CheckRes(res,"Get CMSG_ENCRYPTED_DIGEST",symbols);
        std::cout << "CMSG_ENCRYPTED_DIGEST = " << VecToStr(buff) <<std::endl;
    } 

    // get hash ENCODED_SIGNER
    {
        std::cout<<"---\n";
        DWORD buff_size=0;
        res = symbols.dl_CryptMsgGetParam(handler_message,CMSG_ENCODED_SIGNER,0,0,&buff_size);
        CheckRes(res,"Get CMSG_ENCODED_SIGNER size",symbols);
        std::cout << " CMSG_ENCODED_SIGNER size = "<< buff_size << "\n";
        std::vector<BYTE> buff(buff_size,0);
        res = symbols.dl_CryptMsgGetParam(handler_message,CMSG_ENCODED_SIGNER,0,buff.data(),&buff_size);
        CheckRes(res,"Get  CMSG_ENCODED_SIGNER",symbols);
        //std::cout << "CMSG_ENCODED_SIGNER = " << VecToStr(buff) <<std::endl;
    }      

    // get CMSG_SIGNER_CERT_INFO_PARAM
    {
        std::cout<<"---\n";
        DWORD buff_size=0;
        res = symbols.dl_CryptMsgGetParam(handler_message,CMSG_SIGNER_CERT_INFO_PARAM,0,0,&buff_size);
        CheckRes(res,"Get CMSG_SIGNER_CERT_INFO_PARAM size",symbols);
        std::cout << " CMSG_SIGNER_CERT_INFO_PARAM size = "<< buff_size << "\n";
        std::vector<BYTE> buff(buff_size*2,0);
        res = symbols.dl_CryptMsgGetParam(handler_message,CMSG_SIGNER_CERT_INFO_PARAM,0,buff.data(),&buff_size);
        CheckRes(res,"Get CMSG_SIGNER_CERT_INFO_PARAM ",symbols);
    }   

       // get CMSG_SIGNER_CERT_ID_PARAM
    {
        std::cout<<"---\n";
        DWORD buff_size=0;
        res = symbols.dl_CryptMsgGetParam(handler_message,CMSG_SIGNER_CERT_ID_PARAM,0,0,&buff_size);
        CheckRes(res,"Get CMSG_SIGNER_CERT_ID_PARAM size",symbols);
        std::cout << " CMSG_SIGNER_CERT_ID_PARAM size = "<< buff_size << "\n";
        std::vector<BYTE> buff(buff_size*2,0);
        res = symbols.dl_CryptMsgGetParam(handler_message,CMSG_SIGNER_CERT_ID_PARAM,0,buff.data(),&buff_size);
        CheckRes(res,"Get CMSG_SIGNER_CERT_ID_PARAM ",symbols);
        CERT_ID* ptr_cert_id=reinterpret_cast<CERT_ID*>(buff.data());
        std::cout << "Recieved ";
        switch (ptr_cert_id->dwIdChoice) {
            case CERT_ID_ISSUER_SERIAL_NUMBER:
                std::cout << "CERT_ID_ISSUER_SERIAL_NUMBER\n";
                break;
            case CERT_ID_KEY_IDENTIFIER:
                std::cout << "CERT_ID_KEY_IDENTIFIER\n";
                break;
            case CERT_ID_SHA1_HASH:
                std::cout << "CERT_ID_SHA1_HASH\n";
                break;
        }

    }   

       // get hash algo CMSG_SIGNER_HASH_ALGORITHM_PARAM
    {
        std::cout<<"---\n";
        DWORD buff_size=0;
        res = symbols.dl_CryptMsgGetParam(handler_message,CMSG_SIGNER_HASH_ALGORITHM_PARAM,0,0,&buff_size);
        CheckRes(res,"Get CMSG_SIGNER_HASH_ALGORITHM_PARAM size",symbols);
        std::cout << "CMSG_SIGNER_HASH_ALGORITHM_PARAM size = "<< buff_size << "\n";
        std::vector<BYTE> buff(buff_size*2,0);
        res = symbols.dl_CryptMsgGetParam(handler_message,CMSG_SIGNER_HASH_ALGORITHM_PARAM,0,buff.data(),&buff_size);
        CheckRes(res,"Get CMSG_SIGNER_HASH_ALGORITHM_PARAM ",symbols);
        CRYPT_ALGORITHM_IDENTIFIER* ptr_ctypt_id=reinterpret_cast<CRYPT_ALGORITHM_IDENTIFIER*>(buff.data());
        std::cout << "Hash algo used by signer = ";
        if (std::string(ptr_ctypt_id->pszObjId)==szOID_CP_GOST_R3411_12_256){
            std::cout << "Функция хэширования ГОСТ Р 34.11-2012, длина выхода 256 бит\n";
        }
        std::cout <<"algo id ="<< ptr_ctypt_id->pszObjId <<"\n";
    }   

    // get hash algo CMSG_SIGNER_INFO_PARAM
    {
        std::cout<<"---\n";
        DWORD buff_size=0;
        res = symbols.dl_CryptMsgGetParam(handler_message,CMSG_SIGNER_INFO_PARAM,0,0,&buff_size);
        CheckRes(res,"Get CMSG_SIGNER_INFO_PARAM size",symbols);
        std::cout << "CMSG_SIGNER_INFO_PARAM size = "<< buff_size << "\n";
        std::vector<BYTE> buff(buff_size*2,0);
        res = symbols.dl_CryptMsgGetParam(handler_message,CMSG_SIGNER_INFO_PARAM,0,buff.data(),&buff_size);
        CheckRes(res,"Get CMSG_SIGNER_INFO_PARAM ",symbols);
        CMSG_SIGNER_INFO* ptr_signer_info =reinterpret_cast<CMSG_SIGNER_INFO*>(buff.data());
        std::cout<<"Algo used for data hashing : "<< ptr_signer_info->HashAlgorithm.pszObjId<<"\n";
        if (std::string(ptr_signer_info->HashAlgorithm.pszObjId)==szOID_CP_GOST_R3411_12_256){
            std::cout <<"Hashing algo name: Функция хэширования ГОСТ Р 34.11-2012, длина выхода 256 бит\n";
        }
        std::cout<<"Algo used for encrypting hash :" << ptr_signer_info->HashEncryptionAlgorithm.pszObjId<<"\n";
        if (std::string(ptr_signer_info->HashEncryptionAlgorithm.pszObjId)==szOID_CP_GOST_R3410_12_256){
            std::cout <<"Hash encoding algo name: "<<"Алгоритм ГОСТ Р 34.10-2012 для ключей длины 256 бит"<<"\n";
        }
        std::cout << "Crypted hash size = " << ptr_signer_info->EncryptedHash.cbData << "\n";
    }   

    // get CMSG_SIGNER_AUTH_ATTR_PARAM
     {
        std::cout<<"---\n";
        DWORD buff_size=0;
        res = symbols.dl_CryptMsgGetParam(handler_message,CMSG_SIGNER_AUTH_ATTR_PARAM,0,0,&buff_size);
        CheckRes(res,"Get CMSG_SIGNER_AUTH_ATTR_PARAM size",symbols);
        std::cout << "CMSG_SIGNER_AUTH_ATTR_PARAM size = "<< buff_size << "\n";
        std::vector<BYTE> buff(buff_size*2,0);
        res = symbols.dl_CryptMsgGetParam(handler_message,CMSG_SIGNER_AUTH_ATTR_PARAM,0,buff.data(),&buff_size);
        CheckRes(res,"Get CMSG_SIGNER_AUTH_ATTR_PARAM ",symbols);
        CRYPT_ATTRIBUTES* ptr_crypt_attr=reinterpret_cast<CRYPT_ATTRIBUTES*>(buff.data());
        std::cout <<"number of crypt attributes = "<< ptr_crypt_attr->cAttr<<"\n";
        for (int i=0;i<ptr_crypt_attr->cAttr;++i){
             CRYPT_ATTRIBUTE* attr= (ptr_crypt_attr->rgAttr)+i;
             std::cout << attr->pszObjId<<"\n";
             std::string oid(attr->pszObjId);
             if (oid==szOID_PKCS_9_CONTENT_TYPE){
                std::cout << "szOID_PKCS_9_CONTENT_TYPE the content type of the data that is being carried\n";
             }
             if (oid==szOID_PKCS_9_MESSAGE_DIGEST){
                std::cout << "szOID_PKCS_9_MESSAGE_DIGEST attribute is typically used to store the hash value of the content\n";
             }
             if (oid==szOID_RSA_signingTime){
                std::cout << "szOID_RSA_signingTime information about the timing of the signature creation process\n";
             }
             if (oid==szCPOID_RSA_SMIMEaaSigningCertificateV2){
                std::cout << "szCPOID_RSA_SMIMEaaSigningCertificateV2 crypto pro cpecific attr for storing id of certificate of sign key\n";
             }
        }
     }   


     // TODO  compare CMSG_SIGNER_AUTH_ATTR_PARAM signer certificate and CMSG_SIGNER_CERT_ID_PARAM
     //  and signer cerrificate
        
    // CMSG_ENCRYPT_PARAM CMSG_HASH_ALGORITHM_PARAM CMSG_ENCRYPT_PARAM do not work

    // // try another way
    // //CRYPT_DATA_BLOB cert_data_blob{};
    // PCRYPT_DATA_BLOB ptr_cert_data_blob=nullptr;
    // //CERT_ID cert_id;
    // res = symbols.dl_CadesMsgGetSigningCertId(handler_message,0,&ptr_cert_data_blob);
    // std::cout << "res =" << res;
    // if (ptr_cert_data_blob !=nullptr){
    //     symbols.dl_CadesFreeBlob(ptr_cert_data_blob);
    // }

    symbols.dl_CryptMsgClose(handler_message);

    return 0;
}