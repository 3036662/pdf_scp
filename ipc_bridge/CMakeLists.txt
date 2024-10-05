add_library(csp_ipc_client SHARED
 ipc_client.cpp
)

set_target_properties(csp_ipc_client PROPERTIES POSITION_INDEPENDENT_CODE ON)



SET(IPC_EXEC_NAME \"altcspIpcProvider\")
add_executable(altcspIpcProvider
    ipc_provider.cpp
    ipc_provider_utils.cpp
)
target_compile_definitions(csp_ipc_client PRIVATE
    IPC_PROV_EXEC_NAME=${IPC_EXEC_NAME}
)
target_link_libraries(altcspIpcProvider altcsp
)



find_package(Boost REQUIRED)

include_directories(${CMAKE_SOURCE_DIR})
target_include_directories(csp_ipc_client PUBLIC ${CMAKE_SOURCE_DIR}/csp)
target_include_directories(csp_ipc_client PUBLIC ${CMAKE_SOURCE_DIR}/c_bridge)
target_include_directories(csp_ipc_client PUBLIC ${CMAKE_SOURCE_DIR}/csp/checks)

target_include_directories(altcspIpcProvider PUBLIC ${CMAKE_SOURCE_DIR}/csp)
target_include_directories(altcspIpcProvider PUBLIC ${CMAKE_SOURCE_DIR}/c_bridge)
target_include_directories(altcspIpcProvider PUBLIC ${CMAKE_SOURCE_DIR}/csp/checks)
target_include_directories(altcspIpcProvider PUBLIC ${CMAKE_SOURCE_DIR}/csp/asn1)
target_include_directories(altcspIpcProvider PRIVATE ${CRYPTOPRO_INCLUDE_DIRS})


if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    FormatDir(ipc_pre .)
    add_dependencies(csp_ipc_client ipc_pre)
    include(ClangTidy)
    AddClangTidy(csp_ipc_client)
    include (CppCheck)
    AddCppCheck(csp_ipc_cppcheck)
    add_dependencies(csp_ipc_client csp_ipc_cppcheck)
endif()