include_directories(/opt/cprocsp/include/pki /opt/cprocsp/include/cpcsp/ /opt/cprocsp/include/)
include_directories(${CMAKE_SOURCE_DIR}/common)

include(Format)


add_library(csp OBJECT 
    resolve_symbols.cpp
    csp.cpp
    message.cpp
    message_handler.cpp
)

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