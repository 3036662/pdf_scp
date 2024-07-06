#include "resolve_symbols.hpp"

#include <cstddef>
#include <qpdf/QPDF.hh>
#include <qpdf/QPDFAcroFormDocumentHelper.hh>
#include <qpdf/QPDFAnnotationObjectHelper.hh>
#include <qpdf/QPDFObjectHandle.hh>
#include <qpdf/QPDFPageObjectHelper.hh>
#include <qpdf/QUtil.hh>

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
    

    return 0;
}