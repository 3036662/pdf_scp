cmake_minimum_required(VERSION 3.5)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
add_compile_options(-Wall -Wextra -pedantic)



list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")

project(pdf_csp LANGUAGES CXX VERSION 0.1)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -gdwarf-4")
    add_subdirectory(experimental)
    include(ClangTidy)
    find_package(Catch2  REQUIRED)
endif()
add_subdirectory(pdf)

add_subdirectory(csp)
add_subdirectory(for_poppler)

#clang-tidy -p /home/oleg/dev/eSign/pdf_tool/build pdf/*.hpp --header-filter=*.hpp
#clang-tidy -p /home/oleg/dev/eSign/pdf_tool/build pdf/*.cpp --header-filter=*.hpp
#clang-tidy -p /home/oleg/dev/eSign/pdf_tool/build csp/*.hpp --header-filter=*.hpp
#clang-tidy -p /home/oleg/dev/eSign/pdf_tool/build csp/*.hpp --header-filter=*.cpp