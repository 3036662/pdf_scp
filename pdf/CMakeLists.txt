include_directories(/opt/cprocsp/include/pki /opt/cprocsp/include/cpcsp/ /opt/cprocsp/include/)
include(Format)

include_directories(${CMAKE_SOURCE_DIR}/common)

add_library(pdf OBJECT 
    pdf.cpp
    utils.cpp
)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
 FormatDir(pdf_pre .)
 add_dependencies(pdf pdf_pre)
endif()