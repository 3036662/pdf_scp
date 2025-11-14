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
     grantors.cpp
     context_c.cpp
)


add_library(mrpa SHARED 
    $<TARGET_OBJECTS:mrpa_obj>  
)


find_package(PkgConfig REQUIRED)
pkg_check_modules(XML REQUIRED IMPORTED_TARGET "libxml++-3.0")

message(STATUS "XML++ include directories: ${XML_INCLUDE_DIRS}")


include_directories(${XML_INCLUDE_DIRS})
include_directories(${CMAKE_SOURCE_DIR}/c_bridge)
include_directories(${CMAKE_SOURCE_DIR}/common)
include_directories(${CMAKE_SOURCE_DIR}/csp/checks)
include_directories(${CMAKE_SOURCE_DIR}/csp)
include_directories(${CMAKE_SOURCE_DIR}/mrpa/zip)
include_directories(${CMAKE_SOURCE_DIR}/mrpa)
include_directories(${CMAKE_SOURCE_DIR}/mrpa/tree)
target_link_libraries(mrpa PUBLIC PkgConfig::XML)
target_link_libraries(mrpa PUBLIC logger)
target_link_libraries(mrpa PUBLIC boost_json)
target_link_libraries(mrpa PUBLIC zipcpp)
target_link_libraries(mrpa PUBLIC tree)
target_link_libraries(mrpa PUBLIC common_utils)
target_link_libraries(mrpa PUBLIC csp_c_bridge)



set_target_properties(mrpa PROPERTIES POSITION_INDEPENDENT_CODE ON)
set_target_properties(mrpa_obj PROPERTIES POSITION_INDEPENDENT_CODE ON)


if (DEFINED ENABLE_ADDRESS_SANITIZER)
add_compile_options(  -fsanitize=thread)
add_link_options( -fsanitize=thread )
endif()

if (DEFINED ENABLE_THREAD_SANITIZER)
     add_compile_options(-fsanitize=thread)
     add_link_options(-fsanitize=thread)
endif()

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
     zip/zip_cpp.hpp
     zip/file_stat.hpp     
     doc_archive_public.hpp
     context_c.h
     mrpa_typedefs.hpp
)

 LIST (JOIN MRPA_PUBLIC_HEADERS ";" MRPA_PUBLIC_HEADERS_STR)

set_target_properties(mrpa PROPERTIES VERSION ${PROJECT_VERSION})
set_target_properties(mrpa PROPERTIES SOVERSION ${PROJECT_VERSION_MAJOR})
set_target_properties(mrpa PROPERTIES PUBLIC_HEADER "${MRPA_PUBLIC_HEADERS_STR}")

install(TARGETS mrpa
LIBRARY DESTINATION ${LIB_INSTALL_DIR}
PUBLIC_HEADER DESTINATION ${INCLUDE_INSTALL_DIR}/pdfcsp)

add_subdirectory(zip)
add_subdirectory(tree)