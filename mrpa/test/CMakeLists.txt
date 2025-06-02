add_executable(test_mrpa
    test_common.cpp
)

add_compile_options(-fprofile-instr-generate -fcoverage-mapping  -O0 -g  )
add_link_options(-fprofile-instr-generate -fcoverage-mapping  -O0 -g  )

target_link_libraries(test_mrpa PUBLIC
    mrpa_obj logger boost_json common_utils 
)


include_directories(${CMAKE_SOURCE_DIR}/c_bridge)

target_link_libraries(test_mrpa PRIVATE PkgConfig::XML)
target_link_libraries(test_mrpa PUBLIC csp_c_bridge)

file(MAKE_DIRECTORY "${CMAKE_BINARY_DIR}/testfiles/")
set(TEST_DIR "${CMAKE_BINARY_DIR}/testfiles/")
set(TEST_FILES_DIR "${CMAKE_SOURCE_DIR}/test_files/")
message("Test files will be created here:${TEST_DIR}/test_files")
add_definitions(-DTEST_DIR="${TEST_DIR}")
add_definitions(-DTEST_FILES_DIR="${TEST_FILES_DIR}")

enable_testing()
add_test(NAME mrpa COMMAND test_mrpa)


include_directories("../")


FormatDir(test_mrpa_pre .)
add_dependencies(test_mrpa test_mrpa_pre)

add_custom_target(coverage ALL
COMMENT("run coverage")
  COMMAND ${CMAKE_COMMAND} -E env LLVM_PROFILE_FILE=${CMAKE_BINARY_DIR}/test_mrpa.profraw $<TARGET_FILE:test_mrpa>
  COMMAND llvm-profdata merge -sparse ${CMAKE_BINARY_DIR}/test_mrpa.profraw -o ${CMAKE_BINARY_DIR}/test_mrpa.profdata
  COMMAND llvm-cov show $<TARGET_FILE:test_mrpa> -instr-profile=${CMAKE_BINARY_DIR}/test_mrpa.profdata -format=html -output-dir=${CMAKE_BINARY_DIR}/coverage_report/mrpa  --ignore-filename-regex=test_common.cpp
  COMMAND ${CMAKE_COMMAND} -E echo "Coverage report generated in ${CMAKE_BINARY_DIR}/coverage_report/mrpa/index.html"
 DEPENDS test_mrpa
  WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
  VERBATIM
)


# llvm-profdata merge -sparse default.profraw -o default.profdata
# llvm-cov show ./test_mrpa -instr-profile=default.profdata
# llvm-cov report ./test_mrpa --instr-profile=default.profdata
# llvm-cov show ./test_mrpa -instr-profile=default.profdata -format=html -output-dir=coverage_report