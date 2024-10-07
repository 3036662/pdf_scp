include_directories(${CMAKE_SOURCE_DIR}/c_bridge)
include_directories(${CMAKE_SOURCE_DIR}/for_poppler)
include_directories(${CMAKE_SOURCE_DIR}/pdf)
include_directories(${CMAKE_SOURCE_DIR})


add_executable(popl_test1
test_poppler_lib.cpp
)

target_link_libraries(popl_test1 csp_c_bridge)
target_link_libraries(popl_test1 pdf)
target_link_libraries(popl_test1 cspforpoppl)




set(TEST_FILES_DIR "${CMAKE_SOURCE_DIR}/test_files/")
message("Test files will be created here:${TEST_DIR}/test_files")
add_definitions(-DTEST_FILES_DIR="${TEST_FILES_DIR}")
add_definitions(-DTEST=1)
add_definitions(-DSIZEOF_VOID=8)