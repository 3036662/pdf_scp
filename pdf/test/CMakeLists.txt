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

if(NOT DEFINED USER_CERT_SERIAL)
 SET(USER_CERT_SERIAL 7c0024ddfc0e2aa3e6dd25cc94000f0024ddfc)
endif()


if(NOT DEFINED USER_CERT_SUBJECT)
 SET(USER_CERT_SUBJECT "Test Certificate")
endif()

target_compile_definitions(test_sign PRIVATE USER_CERT_SERIAL="${USER_CERT_SERIAL}")

target_compile_definitions(test_sign PRIVATE USER_CERT_SUBJECT="${USER_CERT_SUBJECT}")

include_directories("../")


