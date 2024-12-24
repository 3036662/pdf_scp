cmake_minimum_required(VERSION 3.5)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
add_compile_options(-Wall -Wextra -pedantic)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")

project(pdf_csp LANGUAGES CXX VERSION 0.1)


# CryptoPto dirs
SET(CRYPTOPRO_INCLUDE_DIRS
    /opt/cprocsp/include/pki    
    /opt/cprocsp/include/cpcsp/ 
    /opt/cprocsp/include/
    ${CMAKE_SOURCE_DIR}/thirdparty
 )  
include_directories(${CRYPTOPRO_INCLUDE_DIRS})

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -gdwarf-4")
    if (DEFINED BUILD_EXPERIMENTAL)
        add_subdirectory(experimental)
    endif()
    include(ClangTidy)
    find_package(Catch2  REQUIRED)
    set(LOG_TO_JOURNAL 0)
endif()
add_subdirectory(pdf)


# logger
find_package(spdlog REQUIRED)
find_package(fmt REQUIRED)

if (NOT DEFINED LOG_TO_JOURNAL)
    set(LOG_TO_JOURNAL 1)
endif()

if (NOT DEFINED LOGTAG)
    set(LOGTAG altpdfcsp)
endif()

add_compile_definitions(
    LOG_TO_JOURNAL=${LOG_TO_JOURNAL}
    LOG_TAG="${LOGTAG}"
)

add_subdirectory(ipc_bridge)
add_subdirectory(common)
add_subdirectory(csp)
add_subdirectory(for_poppler)
add_subdirectory(c_bridge)
add_subdirectory(cli)



