add_executable(test1
    test_common.cpp
)

add_executable(test_sign
    test_sign.cpp
)

file(MAKE_DIRECTORY "${CMAKE_BINARY_DIR}/testfiles/")
set(TEST_DIR "${CMAKE_BINARY_DIR}/testfiles/")
set(TEST_FILES_DIR "${CMAKE_SOURCE_DIR}/test_files/")
message("Test files will be created here:${TEST_DIR}/test_files")
add_definitions(-DTEST_DIR="${TEST_DIR}")
add_definitions(-DTEST_FILES_DIR="${TEST_FILES_DIR}")

target_link_libraries(test1 csppdf)

target_link_libraries(test_sign csppdf)
target_link_libraries(test_sign csp_c_bridge)

include_directories("../")


