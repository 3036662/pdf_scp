include(Format)

add_library(zipcpp SHARED 
 zip_cpp.cpp
 file_handler.cpp
 file_stat.cpp
)

include_directories(${CMAKE_SOURCE_DIR}/common)

target_link_libraries(zipcpp zip common_utils)
set_target_properties(zipcpp PROPERTIES POSITION_INDEPENDENT_CODE ON)

# libzip wrapper

if(CMAKE_BUILD_TYPE STREQUAL "Debug") 
     add_compile_options(-fprofile-instr-generate -fcoverage-mapping  -O0 -g )
     add_link_options(-fprofile-instr-generate -fcoverage-mapping  -O0 -g )
     add_compile_definitions(TEST_BUILD)
     FormatDir(zipcpp_pre .)
     add_dependencies(zipcpp zipcpp_pre)
     include (ClangTidy)
     AddClangTidy(zipcpp)
     include (CppCheck)
     AddCppCheck(zipcpp_cppcheck)
     add_dependencies(zipcpp zipcpp_cppcheck)

     add_subdirectory(test_zip)
endif()

pkg_check_modules(zip REQUIRED IMPORTED_TARGET libzip)

# unused
#pkg_check_modules(ICU REQUIRED IMPORTED_TARGET icu-uc)
#pkg_check_modules(ICU18N REQUIRED IMPORTED_TARGET icu-i18n)

#target_link_libraries(zipcpp PkgConfig::ICU)
#target_link_libraries(zipcpp PkgConfig::ICU18N)

find_package(Boost CONFIG REQUIRED COMPONENTS locale)
target_link_libraries(zipcpp Boost::locale)



