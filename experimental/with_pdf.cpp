#include "CSP_WinDef.h"
#include "resolve_symbols.hpp"

#include <cstddef>
#include <iterator>
#include <qpdf/QPDF.hh>
#include <qpdf/QPDFAcroFormDocumentHelper.hh>
#include <qpdf/QPDFAnnotationObjectHelper.hh>
#include <qpdf/QPDFObjectHandle.hh>
#include <qpdf/QPDFPageObjectHelper.hh>
#include <qpdf/QUtil.hh>
#include <vector>

constexpr const char* file_win="/home/oleg/dev/eSign/pdf_tool/test_files/0207_signed_win.pdf";

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
    symbols.dl_CryptMsgClose(handler_message);

    // verify signature

    
    return 0;
}