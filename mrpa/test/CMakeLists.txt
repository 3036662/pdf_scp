add_executable(test_mrpa
    test_common.cpp
)


file(MAKE_DIRECTORY "${CMAKE_BINARY_DIR}/testfiles/")
set(TEST_DIR "${CMAKE_BINARY_DIR}/testfiles/")
set(TEST_FILES_DIR "${CMAKE_SOURCE_DIR}/test_files/")
message("Test files will be created here:${TEST_DIR}/test_files")
add_definitions(-DTEST_DIR="${TEST_DIR}")
add_definitions(-DTEST_FILES_DIR="${TEST_FILES_DIR}")


target_link_libraries(test_mrpa PRIVATE PkgConfig::XML)

include_directories("../")


if(CMAKE_BUILD_TYPE STREQUAL "Debug")
     FormatDir(test_mrpa_pre .)
     add_dependencies(test_mrpa test_mrpa_pre)
endif()
