include(Format)

include_directories(${CMAKE_SOURCE_DIR}/csp)
include_directories(${CMAKE_SOURCE_DIR}/common)
include_directories(${CMAKE_SOURCE_DIR}/csp/asn1)
include_directories(${CMAKE_SOURCE_DIR}/csp/checks)
include_directories(${CMAKE_SOURCE_DIR}/c_bridge)




add_library(pdf OBJECT 
    pdf.cpp
    pdf_utils.cpp
    image_obj.cpp
    form_x_object.cpp
    sig_field.cpp
    sig_val.cpp
    acro_form.cpp
    pdf_structs.cpp
    pdf_csp_c.cpp
)

set_target_properties(pdf PROPERTIES POSITION_INDEPENDENT_CODE ON)
#target_compile_options(pdf PRIVATE  -fvisibility=hidden )

find_package(PkgConfig REQUIRED)
pkg_check_modules(QPDF IMPORTED_TARGET libqpdf)
target_link_libraries(pdf PkgConfig::QPDF)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
 FormatDir(pdf_pre .)
 add_dependencies(pdf pdf_pre)
 add_subdirectory(test)
 include (ClangTidy)
 AddClangTidy(pdf)
 include (CppCheck)
 AddCppCheck(pdf_cppcheck)
 add_dependencies(pdf pdf_cppcheck)
endif()


add_library(csppdf SHARED 
    $<TARGET_OBJECTS:pdf>  
)
target_link_libraries(csppdf PkgConfig::QPDF)
target_link_libraries(csppdf csp_c_bridge)

set_target_properties(csppdf PROPERTIES PUBLIC_HEADER csppdf.hpp)

set_target_properties(csppdf PROPERTIES VERSION ${PROJECT_VERSION})
set_target_properties(csppdf PROPERTIES SOVERSION ${PROJECT_VERSION_MAJOR})
#target_compile_options(sigpdf PRIVATE  -fvisibility=hidden )

install(TARGETS csppdf
LIBRARY DESTINATION ${LIB_INSTALL_DIR}
PUBLIC_HEADER DESTINATION ${INCLUDE_INSTALL_DIR}/pdfcsp)