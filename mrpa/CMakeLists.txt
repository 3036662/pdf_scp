include(Format)

# MRPA for "Machine-Readable Power of Attorney." 

#add_library(mrpa OBJECT )

#set_target_properties(mrpa PROPERTIES POSITION_INDEPENDENT_CODE ON)

find_package(PkgConfig REQUIRED)
pkg_check_modules(XML REQUIRED IMPORTED_TARGET "libxml++-3.0")

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
     FormatDir(mrpa_pre .)
#     add_dependencies(mrpa mrpa_pre)
     add_subdirectory(test)
     include (ClangTidy)
#     AddClangTidy(mrpa)
     include (CppCheck)
#     AddCppCheck(mrpa_cppcheck)
#     add_dependencies(mrpa mrpa_cppcheck)
endif()

# add_library(mrpa SHARED 
#     $<TARGET_OBJECTS:pdf>  
# )


# SET (MRPA_PUBLIC_HEADERS

# )

# LIST (JOIN MRPA_PUBLIC_HEADERS ";" MRPA_PUBLIC_HEADERS_STR)

# set_target_properties(mrpa PROPERTIES VERSION ${PROJECT_VERSION})
# set_target_properties(mrpa PROPERTIES SOVERSION ${PROJECT_VERSION_MAJOR})

#LIBRARY DESTINATION ${LIB_INSTALL_DIR}
#PUBLIC_HEADER DESTINATION ${INCLUDE_INSTALL_DIR}/pdfcsp)