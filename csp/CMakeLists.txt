include_directories( /opt/cprocsp/include/pki /opt/cprocsp/include/cpcsp/ /opt/cprocsp/include/)
include_directories(${CMAKE_SOURCE_DIR}/common)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/asn1)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/checks)
include_directories(${CMAKE_CURRENT_SOURCE_DIR})

include(Format)



add_library(csp OBJECT 
    resolve_symbols.cpp 
    csp.cpp 
    message.cpp  
    message_handler.cpp  
    utils.cpp
    crypto_attribute.cpp
    hash_handler.cpp
    certificate.cpp
    utils_cert.cpp
    utils_msg.cpp
    store_handler.cpp
)

#target_compile_options(csp PRIVATE  -fvisibility=hidden -fvisibility-inlines-hidden )

set_target_properties(csp PROPERTIES POSITION_INDEPENDENT_CODE ON)

add_subdirectory(asn1)
add_subdirectory(checks)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
 #relax a time check strictness for 5 seconds only for bebug,
 #because  of time on OCSP and TSP test servers is not synchronized
 set(TIME_RELAX 5) 
 target_compile_definitions(csp PRIVATE TIME_RELAX=${TIME_RELAX}) 
 FormatDir(csp_pre .)
 add_dependencies(csp csp_pre)
 add_subdirectory(test)
 include(ClangTidy)
 AddClangTidy(csp)
 include (CppCheck)
 AddCppCheck(csp_cppcheck)
 add_dependencies(csp csp_cppcheck)
endif()


add_library(altcsp SHARED 
    $<TARGET_OBJECTS:csp>  
    $<TARGET_OBJECTS:asn>  
    $<TARGET_OBJECTS:checking_strategies>  
)

set_target_properties(altcsp PROPERTIES VERSION ${PROJECT_VERSION})
set_target_properties(altcsp PROPERTIES SOVERSION ${PROJECT_VERSION_MAJOR})
target_compile_options(altcsp PRIVATE  -fvisibility=hidden )
