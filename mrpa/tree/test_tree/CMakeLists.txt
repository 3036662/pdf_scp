add_executable(test_tree
    test_tree.cpp
)

if(CMAKE_BUILD_TYPE STREQUAL "Debug") 
     add_compile_options(-fprofile-instr-generate -fcoverage-mapping  -O0 -g )
     add_link_options(-fprofile-instr-generate -fcoverage-mapping  -O0 -g )
endif()

include_directories(${CMAKE_SOURCE_DIR}/mrpa/tree)

set(TEST_DIR "${CMAKE_BINARY_DIR}/testfiles/")
set(TEST_FILES_DIR "${CMAKE_SOURCE_DIR}/test_files/")

if(DEFINED SKIP_SENSITIVE)
add_compile_definitions(SKIP_SENSITIVE)
endif()

add_definitions(-DTEST_DIR="${TEST_DIR}")
add_definitions(-DTEST_FILES_DIR="${TEST_FILES_DIR}")
add_compile_definitions(TEST_BUILD)

target_link_libraries(test_tree PUBLIC mrpa)


FormatDir(test_tree_pre .)
add_dependencies(test_tree test_tree_pre)

add_custom_target(coverage_tree 
COMMENT("run coverage for tree module")
  COMMAND ${CMAKE_COMMAND} -E env LLVM_PROFILE_FILE=${CMAKE_BINARY_DIR}/test_tree.profraw $<TARGET_FILE:test_tree>
  COMMAND llvm-profdata merge -sparse ${CMAKE_BINARY_DIR}/test_tree.profraw -o ${CMAKE_BINARY_DIR}/test_tree.profdata 
  COMMAND llvm-cov show $<TARGET_FILE:test_tree> -object=$<TARGET_FILE:mrpa> 
  -instr-profile=${CMAKE_BINARY_DIR}/test_tree.profdata -format=html -output-dir=${CMAKE_BINARY_DIR}/coverage_report/tree  
  -show-directory-coverage
  COMMAND ${CMAKE_COMMAND} -E echo "Coverage report generated in ${CMAKE_BINARY_DIR}/coverage_report/tree/index.html"
  DEPENDS test_tree
  WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
  VERBATIM
)
