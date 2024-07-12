cmake_minimum_required(VERSION 3.5)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
add_compile_options(-Wall -Wextra -pedantic)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")

project(pdf_csp LANGUAGES CXX VERSION 0.1)

if (DEFINED BUILD_EXPERIMENTAL)
    add_subdirectory(experimental)
    include(ClangTidy)
    AddClangTidy(pdf_csp)
endif()
add_subdirectory(pdf)


