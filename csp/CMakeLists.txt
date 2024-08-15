include_directories( /opt/cprocsp/include/pki /opt/cprocsp/include/cpcsp/ /opt/cprocsp/include/)
include_directories(${CMAKE_SOURCE_DIR}/common)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/asn1)
include_directories(${CMAKE_CURRENT_SOURCE_DIR})

include(Format)



add_library(csp OBJECT 
    resolve_symbols.cpp 
    csp.cpp 
    message.cpp  
    message_handler.cpp  
    utils.cpp
    crypto_attribute.cpp
    certificate_id.cpp
    hash_handler.cpp
    certificate.cpp
    utils_cert.cpp
    utils_msg.cpp
    xl_certs.cpp
    store_handler.cpp
)

#target_link_libraries(csp asn)

add_subdirectory(asn1)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
 FormatDir(csp_pre .)
 add_dependencies(csp csp_pre)
 add_subdirectory(test)
 include(ClangTidy)
 AddClangTidy(csp)
 include (CppCheck)
 AddCppCheck(csp_cppcheck)
 add_dependencies(csp csp_cppcheck)
endif()