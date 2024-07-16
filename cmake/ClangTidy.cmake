function(AddClangTidy target)  
    find_program(CLANG-TIDY_PATH clang-tidy REQUIRED)  
    message("Top-level source directory: ${CMAKE_SOURCE_DIR}")
    set(CLANG_TIDY_COMMAND "${CLANG-TIDY_PATH}"  "--header-filter=.hpp" )
    set_target_properties(${target}    
        PROPERTIES CXX_CLANG_TIDY    
        "${CLANG_TIDY_COMMAND}")
    set_target_properties(${target}    
        PROPERTIES CMAKE_CXX_CLANG_TIDY    
        "${CLANG_TIDY_COMMAND}")
endfunction()
