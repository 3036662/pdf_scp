include_directories(${CMAKE_SOURCE_DIR}/csp)
message(${CMAKE_SOURCE_DIR}/csp)
include_directories(/opt/cprocsp/include/pki /opt/cprocsp/include/cpcsp/ /opt/cprocsp/include/)
include_directories(${CMAKE_SOURCE_DIR}/common)

add_library(asn OBJECT
    asn1.cpp
    ocsp.cpp
    asn_tsp.cpp
    cms.cpp
    cert_refs.cpp
    revoc_refs.cpp
    revoc_vals.cpp
    certificate_id.cpp
    d_name.cpp
)

target_include_directories(asn PUBLIC ${CMAKE_SOURCE_DIR}/thirdparty)

set_target_properties(asn PROPERTIES POSITION_INDEPENDENT_CODE ON)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
 FormatDir(asn_pre .)
 add_dependencies(asn asn_pre)
 include(ClangTidy)
 AddClangTidy(asn)
 include (CppCheck)
 AddCppCheck(asn_cppcheck)
 add_dependencies(asn csp_cppcheck)
endif()