add_library(csp_ipc_client OBJECT
 ipc_client.cpp
)

find_package(Boost REQUIRED)

include_directories(${CMAKE_SOURCE_DIR})
target_include_directories(csp_ipc_client PUBLIC ${CMAKE_SOURCE_DIR}/csp)
target_include_directories(csp_ipc_client PUBLIC ${CMAKE_SOURCE_DIR}/c_bridge)
target_include_directories(csp_ipc_client PUBLIC ${CMAKE_SOURCE_DIR}/csp/checks)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    FormatDir(ipc_pre .)
    add_dependencies(csp_ipc_client ipc_pre)
    include(ClangTidy)
    AddClangTidy(csp_ipc_client)
    include (CppCheck)
    AddCppCheck(csp_ipc_cppcheck)
    add_dependencies(csp_ipc_client csp_ipc_cppcheck)
endif()