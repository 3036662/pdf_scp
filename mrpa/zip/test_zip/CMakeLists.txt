add_executable(test_zip
    test_zip.cpp
)

if(CMAKE_BUILD_TYPE STREQUAL "Debug") 
     add_compile_options(-fprofile-instr-generate -fcoverage-mapping  -O0 -g )
     add_link_options(-fprofile-instr-generate -fcoverage-mapping  -O0 -g )
endif()


include_directories(test_zip ${CMAKE_SOURCE_DIR}/mrpa/zip)

set(TEST_DIR "${CMAKE_BINARY_DIR}/testfiles/")
set(TEST_FILES_DIR "${CMAKE_SOURCE_DIR}/test_files/")

add_definitions(-DTEST_DIR="${TEST_DIR}")
add_definitions(-DTEST_FILES_DIR="${TEST_FILES_DIR}")

target_link_libraries(test_zip PUBLIC logger zip zipcpp)

FormatDir(test_zip_pre .)
add_dependencies(test_zip test_zip_pre)

add_custom_target(coverage_zip  ALL
COMMENT("run coverage for zip module")
  COMMAND ${CMAKE_COMMAND} -E env LLVM_PROFILE_FILE=${CMAKE_BINARY_DIR}/test_zip.profraw $<TARGET_FILE:test_zip>
  COMMAND llvm-profdata merge -sparse ${CMAKE_BINARY_DIR}/test_zip.profraw -o ${CMAKE_BINARY_DIR}/test_zip.profdata
  COMMAND llvm-cov show $<TARGET_FILE:test_zip> -object=$<TARGET_FILE:zipcpp> 
     -instr-profile=${CMAKE_BINARY_DIR}/test_zip.profdata -format=html -output-dir=${CMAKE_BINARY_DIR}/coverage_report/zip  
     --ignore-filename-regex=test_zip.cpp
  COMMAND ${CMAKE_COMMAND} -E echo "Coverage report generated in ${CMAKE_BINARY_DIR}/coverage_report/zip/index.html"
  DEPENDS test_zip
  WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
  VERBATIM
)
