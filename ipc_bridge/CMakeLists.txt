add_library(csp_ipc_client SHARED
 ipc_client.cpp
)

set_target_properties(csp_ipc_client PROPERTIES VERSION ${PROJECT_VERSION})
set_target_properties(csp_ipc_client PROPERTIES SOVERSION ${PROJECT_VERSION_MAJOR})

set_target_properties(csp_ipc_client PROPERTIES POSITION_INDEPENDENT_CODE ON)
set_target_properties(csp_ipc_client PROPERTIES PUBLIC_HEADER "ipc_client.hpp;ipc_result.hpp;ipc_typedefs.hpp")


if (NOT DEFINED IPC_EXEC_DIR)
    set(IPC_EXEC_DIR /home/oleg/dev/eSign/csp_pdf/build/ipc_bridge/)
endif()

message("Ipc executable path ${IPC_EXEC_DIR}")

SET(IPC_EXEC_NAME altcspIpcProvider)
add_executable(altcspIpcProvider
    ipc_provider.cpp
    ipc_provider_utils.cpp
)
target_include_directories(altcspIpcProvider PUBLIC ${CMAKE_SOURCE_DIR}/thirdparty)

target_compile_definitions(csp_ipc_client PRIVATE
    IPC_PROV_EXEC_NAME="${IPC_EXEC_NAME}"
    IPC_EXEC_DIR="${IPC_EXEC_DIR}"
)
target_link_libraries(altcspIpcProvider pthread)
target_link_libraries(altcspIpcProvider rt)
target_link_libraries(altcspIpcProvider dl)
target_link_libraries(altcspIpcProvider altcsp)
target_link_libraries(altcspIpcProvider logger)

target_link_libraries(csp_ipc_client pthread)
target_link_libraries(csp_ipc_client rt)
target_link_libraries(csp_ipc_client dl)
target_link_libraries(csp_ipc_client fmt)
target_link_libraries(csp_ipc_client spdlog)
target_link_libraries(csp_ipc_client logger)

find_package(Boost CONFIG)

include_directories(${CMAKE_SOURCE_DIR}/common)
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

install(TARGETS csp_ipc_client
LIBRARY DESTINATION ${LIB_INSTALL_DIR}
PUBLIC_HEADER DESTINATION ${INCLUDE_INSTALL_DIR}/pdfcsp)

install(TARGETS altcspIpcProvider
  DESTINATION ${IPC_EXEC_DIR}
)

