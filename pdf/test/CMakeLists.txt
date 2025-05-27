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
 SET(USER_CERT_SERIAL 7c001dfc32b4a566eaf1b12c4e000d001dfc32)
endif()


if(NOT DEFINED USER_CERT_SUBJECT)
 SET(USER_CERT_SUBJECT test)
endif()

target_compile_definitions(test_sign PRIVATE USER_CERT_SERIAL="${USER_CERT_SERIAL}")

target_compile_definitions(test_sign PRIVATE USER_CERT_SUBJECT="${USER_CERT_SUBJECT}")

include_directories("../")


