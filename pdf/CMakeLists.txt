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
    cross_ref_stream.cpp
)

set_target_properties(pdf PROPERTIES POSITION_INDEPENDENT_CODE ON)
#target_compile_options(pdf PRIVATE  -fvisibility=hidden )

find_package(PkgConfig REQUIRED)
pkg_check_modules(QPDF IMPORTED_TARGET libqpdf)
find_package(SignatureImageCWrapper REQUIRED)


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
target_link_libraries(csppdf signimage_c_wrapper)

SET (PDF_PUBLIC_HEADERS
    csppdf.hpp
    pdf_pod_structs.hpp
    pdf_structs.hpp
    pdf_defs.hpp
    pdf_csp_c.hpp
    pdf_update_object_kit.hpp
    acro_form.hpp
    form_x_object.hpp
    image_obj.hpp
    sig_field.hpp
    sig_val.hpp 
)


LIST (JOIN PDF_PUBLIC_HEADERS ";" PDF_PUBLIC_HEADERS_STR)
set_target_properties(csppdf PROPERTIES PUBLIC_HEADER "${PDF_PUBLIC_HEADERS_STR}")

set_target_properties(csppdf PROPERTIES VERSION ${PROJECT_VERSION})
set_target_properties(csppdf PROPERTIES SOVERSION ${PROJECT_VERSION_MAJOR})

install(TARGETS csppdf
LIBRARY DESTINATION ${LIB_INSTALL_DIR}
PUBLIC_HEADER DESTINATION ${INCLUDE_INSTALL_DIR}/pdfcsp)