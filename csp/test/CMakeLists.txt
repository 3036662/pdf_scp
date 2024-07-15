add_executable(csp_test1
    test_common.cpp
)

target_link_libraries(csp_test1 csp)
target_link_libraries(csp_test1 pdf)
include_directories("../")
include_directories(${CMAKE_SOURCE_DIR}/pdf)

set(TEST_FILES_DIR "${CMAKE_SOURCE_DIR}/test_files/")
message("Test files will be created here:${TEST_DIR}/test_files")
add_definitions(-DTEST_FILES_DIR="${TEST_FILES_DIR}")