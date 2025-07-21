 add_library(tree OBJECT
     tree_context.cpp
     utils_tree.cpp
 )

include_directories(${CMAKE_SOURCE_DIR}/mrpa/zip)

if(CMAKE_BUILD_TYPE STREQUAL "Debug") 
     add_compile_options(-fprofile-instr-generate -fcoverage-mapping  -O0 -g )
     add_link_options(-fprofile-instr-generate -fcoverage-mapping  -O0 -g )
     add_compile_definitions(TEST_BUILD)
     FormatDir(tree_pre .)
    add_dependencies(tree tree_pre)  
    AddClangTidy(tree)
    include (CppCheck)
    AddCppCheck(tree_cppcheck)
    add_dependencies(tree tree_cppcheck)

    add_subdirectory(test_tree)
endif()




