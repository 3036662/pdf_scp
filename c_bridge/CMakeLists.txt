include_directories(${CMAKE_SOURCE_DIR}/common)
include_directories(${CMAKE_SOURCE_DIR}/csp/asn1)
include_directories(${CMAKE_SOURCE_DIR}/csp/checks)
include_directories(${CMAKE_SOURCE_DIR}/csp)
include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_SOURCE_DIR})

include(Format)

add_library(csp_c_bridge SHARED
c_bridge.cpp
)

set_target_properties(csp_c_bridge PROPERTIES POSITION_INDEPENDENT_CODE ON)

target_include_directories(csp_c_bridge PUBLIC ${CMAKE_SOURCE_DIR}/thirdparty)
target_compile_options(csp_c_bridge PRIVATE  -fvisibility=hidden -fvisibility-inlines-hidden)
set_target_properties(csp_c_bridge PROPERTIES VERSION ${PROJECT_VERSION})
set_target_properties(csp_c_bridge PROPERTIES SOVERSION ${PROJECT_VERSION_MAJOR})

target_link_libraries(csp_c_bridge csp_ipc_client spdlog fmt logger)


set_target_properties(csp_c_bridge PROPERTIES PUBLIC_HEADER "c_bridge.hpp;pod_structs.hpp;bridge_obj_storage.hpp;")

install(TARGETS csp_c_bridge
LIBRARY DESTINATION ${LIB_INSTALL_DIR}
PUBLIC_HEADER DESTINATION ${INCLUDE_INSTALL_DIR}/pdfcsp)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
 FormatDir(csp_c_bridge_pre .)
 add_dependencies(csp_c_bridge csp_c_bridge_pre)
 include(ClangTidy)
 AddClangTidy(csp_c_bridge)
 include (CppCheck)
 AddCppCheck(csp_c_bridge_cppcheck)
 add_dependencies(csp_c_bridge csp_c_bridge_cppcheck)
 add_subdirectory(test)
endif()