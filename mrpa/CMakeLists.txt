include(Format)

# MRPA for "Machine-Readable Power of Attorney." 

if(CMAKE_BUILD_TYPE STREQUAL "Debug") 
     add_compile_options(-fprofile-instr-generate -fcoverage-mapping  -O0 -g )
     add_link_options(-fprofile-instr-generate -fcoverage-mapping  -O0 -g )
endif()

add_library(mrpa_obj OBJECT 
     xsd1.cpp
     mrpa.cpp
     utils_mrpa.cpp
)


add_library(mrpa SHARED 
    $<TARGET_OBJECTS:mrpa_obj>  
)


find_package(PkgConfig REQUIRED)
pkg_check_modules(XML REQUIRED IMPORTED_TARGET "libxml++-3.0")

include_directories(${CMAKE_SOURCE_DIR}/c_bridge)
include_directories(${CMAKE_SOURCE_DIR}/common)
include_directories(${CMAKE_SOURCE_DIR}/csp/checks)
include_directories(${CMAKE_SOURCE_DIR}/csp)
target_link_libraries(mrpa_obj PRIVATE PkgConfig::XML)
target_link_libraries(mrpa PUBLIC logger)
target_link_libraries(mrpa PUBLIC boost_json)




set_target_properties(mrpa PROPERTIES POSITION_INDEPENDENT_CODE ON)
set_target_properties(mrpa_obj PROPERTIES POSITION_INDEPENDENT_CODE ON)




if(CMAKE_BUILD_TYPE STREQUAL "Debug")
     add_compile_definitions(MRPA_REMOVE_PREFIX)
     FormatDir(mrpa_pre .)
     add_dependencies(mrpa mrpa_pre)
     add_subdirectory(test)
     include (ClangTidy)
     AddClangTidy(mrpa)
     include (CppCheck)
     AddCppCheck(mrpa_cppcheck)
     add_dependencies(mrpa mrpa_cppcheck)
endif()




SET (MRPA_PUBLIC_HEADERS
     xsd1.hpp
)

 LIST (JOIN MRPA_PUBLIC_HEADERS ";" MRPA_PUBLIC_HEADERS_STR)

set_target_properties(mrpa PROPERTIES VERSION ${PROJECT_VERSION})
set_target_properties(mrpa PROPERTIES SOVERSION ${PROJECT_VERSION_MAJOR})

install(TARGETS mrpa
LIBRARY DESTINATION ${LIB_INSTALL_DIR}
PUBLIC_HEADER DESTINATION ${INCLUDE_INSTALL_DIR}/pdfcsp)