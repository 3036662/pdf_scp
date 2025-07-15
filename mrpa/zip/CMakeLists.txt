include(Format)

add_library(zipcpp SHARED 
 zip_cpp.cpp
)

target_link_libraries(zipcpp zip)

# libzip wrapper

if(CMAKE_BUILD_TYPE STREQUAL "Debug") 
     add_compile_options(-fprofile-instr-generate -fcoverage-mapping  -O0 -g )
     add_link_options(-fprofile-instr-generate -fcoverage-mapping  -O0 -g )
     add_compile_definitions(TEST_BUILD)
endif()

pkg_check_modules(zip REQUIRED IMPORTED_TARGET libzip)

# unused
#pkg_check_modules(ICU REQUIRED IMPORTED_TARGET icu-uc)
#pkg_check_modules(ICU18N REQUIRED IMPORTED_TARGET icu-i18n)

#target_link_libraries(zipcpp PkgConfig::ICU)
#target_link_libraries(zipcpp PkgConfig::ICU18N)

find_package(Boost CONFIG REQUIRED COMPONENTS locale)
target_link_libraries(zipcpp Boost::locale)


add_subdirectory(test_zip)