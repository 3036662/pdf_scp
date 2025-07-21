 add_library(tree OBJECT
     tree_context.cpp
 )

include_directories(${CMAKE_SOURCE_DIR}/mrpa/zip)

if(CMAKE_BUILD_TYPE STREQUAL "Debug") 
     add_compile_options(-fprofile-instr-generate -fcoverage-mapping  -O0 -g )
     add_link_options(-fprofile-instr-generate -fcoverage-mapping  -O0 -g )
     add_compile_definitions(TEST_BUILD)
endif()



#add_subdirectory(test_tree)