include_directories( /opt/cprocsp/include/pki /opt/cprocsp/include/cpcsp/ /opt/cprocsp/include/)
include_directories(${CMAKE_SOURCE_DIR}/common)
include_directories(${CMAKE_SOURCE_DIR}/csp/asn1)
include_directories(${CMAKE_SOURCE_DIR}/csp/checks)
include_directories(${CMAKE_SOURCE_DIR}/csp)
include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_SOURCE_DIR})

include(Format)

add_library(csp_c_brigde SHARED
c_bridge.cpp
utils_c_bridge.cpp
)


target_include_directories(csp_c_brigde PUBLIC ${CMAKE_SOURCE_DIR}/thirdparty)
target_link_libraries(csp_c_brigde altcsp)
target_compile_options(csp_c_brigde PRIVATE  -fvisibility=hidden -fvisibility-inlines-hidden)
set_target_properties(csp_c_brigde PROPERTIES VERSION ${PROJECT_VERSION})
set_target_properties(csp_c_brigde PROPERTIES SOVERSION ${PROJECT_VERSION_MAJOR})

#set_target_properties(c_pod_interface PROPERTIES PUBLIC_HEADER "csp_for_poppl.hpp;structs.hpp;obj_storage.hpp;")

install(TARGETS csp_c_brigde
LIBRARY DESTINATION ${LIB_INSTALL_DIR}
PUBLIC_HEADER DESTINATION ${INCLUDE_INSTALL_DIR}/pdfcsp)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
 FormatDir(csp_c_brigde_pre .)
 add_dependencies(csp_c_brigde csp_c_brigde_pre)
 #add_subdirectory(test)
 include(ClangTidy)
 AddClangTidy(csp_c_brigde)
 include (CppCheck)
 AddCppCheck(csp_c_brigde_cppcheck)
 add_dependencies(csp_c_brigde csp_c_brigde_cppcheck)
endif()