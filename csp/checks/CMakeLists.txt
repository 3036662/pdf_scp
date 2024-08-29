include_directories(${CMAKE_SOURCE_DIR}/csp)
message(${CMAKE_SOURCE_DIR}/csp)
include_directories(/opt/cprocsp/include/pki /opt/cprocsp/include/cpcsp/ /opt/cprocsp/include/)
include_directories(${CMAKE_SOURCE_DIR}/common)

add_library(checking_strategies OBJECT
    bes_checks.cpp
    t_checks.cpp
    x_checks.cpp
    pks_checks.cpp
    check_result.cpp
)

target_include_directories(checking_strategies SYSTEM PUBLIC ${CMAKE_SOURCE_DIR}/thirdparty)

set_target_properties(checking_strategies PROPERTIES POSITION_INDEPENDENT_CODE ON)
#target_compile_options(checking_strategies PRIVATE  -fvisibility=hidden )

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
 FormatDir(checking_strategies_pre .)
 add_dependencies(checking_strategies checking_strategies_pre)
 include(ClangTidy)
 AddClangTidy(checking_strategies)
 include (CppCheck)
 AddCppCheck(checking_strategies_cppcheck)
 add_dependencies(checking_strategies checking_strategies_cppcheck)
endif()