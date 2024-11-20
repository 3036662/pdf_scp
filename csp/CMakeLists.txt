include_directories( ${CRYPTOPRO_INCLUDE_DIRS})
include_directories(${CMAKE_SOURCE_DIR}/common)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/asn1)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/checks)
include_directories(${CMAKE_CURRENT_SOURCE_DIR})

include(Format)

if(DEFINED SIZEOF_VOID_P)
add_compile_definitions(SIZEOF_VOID_P=${SIZEOF_VOID_P})
message(SIZEOF_VOID_P=${SIZEOF_VOID_P})
endif()

add_library(csp OBJECT 
    resolve_symbols.cpp 
    csp.cpp 
    message.cpp  
    message_handler.cpp  
    utils.cpp
    crypto_attribute.cpp
    hash_handler.cpp
    certificate.cpp
    cert_common_info.cpp
    utils_cert.cpp
    utils_msg.cpp
    store_handler.cpp
)

set_target_properties(csp PROPERTIES POSITION_INDEPENDENT_CODE ON)

target_link_libraries(csp PUBLIC boost_json)
target_link_libraries(csp PUBLIC dl)

target_include_directories(csp PUBLIC ${CMAKE_SOURCE_DIR}/thirdparty)


add_subdirectory(asn1)
add_subdirectory(checks)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
 #relax a time check strictness for 5 seconds only for bebug,
 #because  of time on OCSP and TSP test servers is not synchronized
 set(TIME_RELAX 20) 
 target_compile_definitions(csp PRIVATE TIME_RELAX=${TIME_RELAX}) 
 FormatDir(csp_pre .)
 add_dependencies(csp csp_pre)
 add_subdirectory(test)
 include(ClangTidy)
 AddClangTidy(csp)
 include (CppCheck)
 AddCppCheck(csp_cppcheck)
 add_dependencies(csp csp_cppcheck)
else()
    set(TIME_RELAX 20) 
    target_compile_definitions(csp PRIVATE TIME_RELAX=${TIME_RELAX})
endif()


add_library(altcsp SHARED 
    $<TARGET_OBJECTS:logger>  
    $<TARGET_OBJECTS:csp>  
    $<TARGET_OBJECTS:asn>  
    $<TARGET_OBJECTS:checking_strategies>  
    $<TARGET_OBJECTS:boost_json>      
)
target_link_libraries(altcsp PUBLIC dl)
target_link_libraries(altcsp PUBLIC fmt)
target_link_libraries(altcsp PUBLIC spdlog)


set_target_properties(altcsp PROPERTIES VERSION ${PROJECT_VERSION})
set_target_properties(altcsp PROPERTIES SOVERSION ${PROJECT_VERSION_MAJOR})
target_compile_options(altcsp PRIVATE  -fvisibility=hidden )

SET(ALT_CSP_HEADERS
    altcsp.hpp
    message.hpp
    asn1/asn1.hpp
    typedefs.hpp
    certificate.hpp
    asn1/d_name.hpp
    asn1/ocsp.hpp
    resolve_symbols.hpp
    cert_common_info.hpp)    
list (JOIN ALT_CSP_HEADERS ";" CSP_HEADERS_STR)

set_target_properties(altcsp PROPERTIES PUBLIC_HEADER "${CSP_HEADERS_STR}")


install(TARGETS altcsp
LIBRARY DESTINATION ${LIB_INSTALL_DIR}
PUBLIC_HEADER DESTINATION ${INCLUDE_INSTALL_DIR}/pdfcsp)

    