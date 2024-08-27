include_directories( /opt/cprocsp/include/pki /opt/cprocsp/include/cpcsp/ /opt/cprocsp/include/)
include_directories(${CMAKE_SOURCE_DIR}/common)
include_directories(${CMAKE_SOURCE_DIR}/csp/asn1)
include_directories(${CMAKE_SOURCE_DIR}/csp/checks)
include_directories(${CMAKE_SOURCE_DIR}/csp)
include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_SOURCE_DIR})

include(Format)



add_library(for_poppler OBJECT 
    c_interface.cpp
)

target_link_libraries(for_poppler csp)


if(CMAKE_BUILD_TYPE STREQUAL "Debug")
 FormatDir(for_poppler_pre .)
 add_dependencies(for_poppler for_poppler_pre)
 #add_subdirectory(test)
 include(ClangTidy)
 AddClangTidy(for_poppler)
 include (CppCheck)
 AddCppCheck(for_poppler_cppcheck)
 add_dependencies(for_poppler for_poppler_cppcheck)
endif()