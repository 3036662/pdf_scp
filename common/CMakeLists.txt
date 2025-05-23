add_library(boost_json OBJECT boost_json.cpp)

add_library(logger OBJECT logger_utils.cpp)

set_target_properties(logger PROPERTIES POSITION_INDEPENDENT_CODE ON)

set_target_properties(boost_json PROPERTIES POSITION_INDEPENDENT_CODE ON)

target_link_libraries(logger PUBLIC spdlog)
target_link_libraries(logger PUBLIC fmt)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
 FormatDir(common_pre .)
 add_dependencies(logger common_pre)
 include(ClangTidy)
 AddClangTidy(common_pre)
 include (CppCheck)
 AddCppCheck(logger_cppcheck)
 add_dependencies(logger logger_cppcheck)
endif()

set_target_properties(logger PROPERTIES PUBLIC_HEADER "logger_utils.hpp")

install(TARGETS logger
PUBLIC_HEADER DESTINATION ${INCLUDE_INSTALL_DIR}/pdfcsp)