add_executable(csp_test1
    test_common.cpp
)

add_executable(test_valid_files
    test_valid_bunch.cpp
)

add_executable(test_sign_helpers 
   test_sign_helpers.cpp
)




target_link_libraries(test_valid_files csp)
target_link_libraries(test_valid_files pdf)
target_link_libraries(test_valid_files asn)
target_link_libraries(test_valid_files boost_json)
target_link_libraries(test_valid_files checking_strategies)
target_link_libraries(test_valid_files csp_c_bridge)
target_link_libraries(test_valid_files signimage_c_wrapper)
target_link_libraries(test_valid_files logger)

target_link_libraries(csp_test1 csp)
target_link_libraries(csp_test1 asn)
target_link_libraries(csp_test1 pdf)
target_link_libraries(csp_test1 boost_json)
target_link_libraries(csp_test1 checking_strategies)
target_link_libraries(csp_test1 signimage_c_wrapper)
target_link_libraries(csp_test1 csp_c_bridge)
target_link_libraries(csp_test1 logger)


target_link_libraries(test_sign_helpers csp)
target_link_libraries(test_sign_helpers pdf)
target_link_libraries(test_sign_helpers asn)
target_link_libraries(test_sign_helpers boost_json)
target_link_libraries(test_sign_helpers checking_strategies)
target_link_libraries(test_sign_helpers csp_c_bridge)
target_link_libraries(test_sign_helpers checking_strategies)
target_link_libraries(test_sign_helpers signimage_c_wrapper)
target_link_libraries(test_sign_helpers logger)



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