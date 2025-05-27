function(Format target directory)
    if(NOT DEFINED SKIP_CLANG_FORMAT)
        find_program(CLANG-FORMAT_PATH clang-format REQUIRED)  
        set(EXPRESSION h hpp hh c cc cxx cpp)  
        list(TRANSFORM EXPRESSION PREPEND "${directory}/*.")  
        file(GLOB_RECURSE SOURCE_FILES FOLLOW_SYMLINKS 
            LIST_DIRECTORIES false ${EXPRESSION}  
        )  
        add_custom_command(TARGET ${target} PRE_BUILD COMMAND
            ${CLANG-FORMAT_PATH} -i --style=file ${SOURCE_FILES}
        )
    else()
        add_custom_target(${target} ALL COMMAND ${CMAKE_COMMAND} -E echo "skipping clang-format")    
    endif()
endfunction()   
 
    

function(FormatDir target directory)
    if(NOT DEFINED SKIP_CLANG_FORMAT)
        find_program(CLANG-FORMAT_PATH clang-format REQUIRED)  
        set(EXPRESSION h hpp hh c cc cxx cpp)  
        list(TRANSFORM EXPRESSION PREPEND "${directory}/*.")  
        file(GLOB_RECURSE SOURCE_FILES FOLLOW_SYMLINKS 
            LIST_DIRECTORIES false ${EXPRESSION}  
        )  
        add_custom_command(OUTPUT formatted COMMAND
            ${CLANG-FORMAT_PATH} -i --style=file ${SOURCE_FILES}
        )
    add_custom_target(${target} DEPENDS formatted)
    else()
     add_custom_target(${target} ALL COMMAND ${CMAKE_COMMAND} -E echo "skipping clang-format")
    endif()
endfunction()  