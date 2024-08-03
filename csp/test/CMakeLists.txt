add_executable(csp_test1
    test_common.cpp
)

add_executable(test_valid_files
    test_valid_bunch.cpp
)
target_link_libraries(test_valid_files csp)
target_link_libraries(test_valid_files pdf)
target_link_libraries(test_valid_files asn)

target_link_libraries(csp_test1 csp)
target_link_libraries(csp_test1 asn)
target_link_libraries(csp_test1 pdf)
include_directories("../")
include_directories(${CMAKE_SOURCE_DIR}/pdf)
include_directories(${CMAKE_SOURCE_DIR}/csp)

# target_compile_options(csp_test1 PRIVATE -fsanitize=address)
# target_compile_options(csp_test1 PRIVATE -fsanitize=undefined)
# target_link_libraries(csp_test1  -fsanitize=address)
# target_link_libraries(csp_test1 -fsanitize=undefined)

set(TEST_FILES_DIR "${CMAKE_SOURCE_DIR}/test_files/")
message("Test files will be created here:${TEST_DIR}/test_files")
add_definitions(-DTEST_FILES_DIR="${TEST_FILES_DIR}")
add_definitions(-DTEST=1)
add_definitions(-DSIZEOF_VOID=8)