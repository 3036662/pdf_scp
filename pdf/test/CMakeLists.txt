add_executable(test1
    test_common.cpp
)

file(MAKE_DIRECTORY "${CMAKE_BINARY_DIR}/testfiles/")
set(TEST_DIR "${CMAKE_BINARY_DIR}/testfiles/")
message("Test files will be created here:${TEST_DIR}")
add_definitions(-DTEST_DIR="${TEST_DIR}")


target_link_libraries(test1 pdf)
include_directories("../")