include_directories( /opt/cprocsp/include/pki /opt/cprocsp/include/cpcsp/ /opt/cprocsp/include/)
include_directories(${CMAKE_SOURCE_DIR}/common)
include_directories(${CMAKE_SOURCE_DIR}/csp/asn1)
include_directories(${CMAKE_SOURCE_DIR}/csp/checks)
include_directories(${CMAKE_SOURCE_DIR}/csp)
include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_SOURCE_DIR})

include(Format)



#add_library(for_poppler OBJECT 
#    c_interface.cpp
#)

add_library(cspforpoppl SHARED
    c_interface.cpp
)



target_link_libraries(cspforpoppl altcsp)
target_compile_options(cspforpoppl PRIVATE  -fvisibility=hidden -fvisibility-inlines-hidden)
set_target_properties(cspforpoppl PROPERTIES VERSION ${PROJECT_VERSION})
set_target_properties(cspforpoppl PROPERTIES SOVERSION ${PROJECT_VERSION_MAJOR})

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
 FormatDir(for_poppler_pre .)
 add_dependencies(cspforpoppl for_poppler_pre)
 add_subdirectory(test)
 include(ClangTidy)
 AddClangTidy(cspforpoppl)
 include (CppCheck)
 AddCppCheck(cspforpoppl_cppcheck)
 add_dependencies(cspforpoppl cspforpoppl_cppcheck)
endif()