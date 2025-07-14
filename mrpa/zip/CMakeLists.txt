include(Format)

add_library(zipcpp SHARED 
 zip_cpp.cpp
)

target_link_libraries(zipcpp zip)

# libzip wrapper

if(CMAKE_BUILD_TYPE STREQUAL "Debug") 
     add_compile_options(-fprofile-instr-generate -fcoverage-mapping  -O0 -g )
     add_link_options(-fprofile-instr-generate -fcoverage-mapping  -O0 -g )
     add_compile_definitions(-DTEST_BUILD=1)
endif()

pkg_check_modules(zip REQUIRED IMPORTED_TARGET libzip)
#pkg_check_modules(icu REQUIRED IMPORTED_TARGET icu-uc)

add_subdirectory(test_zip)