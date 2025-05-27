function(AddCppCheck target)
find_program(CPPCHECK_EXECUTABLE cppcheck REQUIRED)

set(CPP_CHECK_PARAMS " --enable=all  --inconclusive --force --inline-suppr --template=gcc --std=c++17 --suppressions-list=${CMAKE_SOURCE_DIR}/CppCheckSuppressions.cppcheck")

if(NOT DEFINED OLD_CPPCHECK)
  set(CPP_CHECK_PARAMS "${CPP_CHECK_PARAMS} --check-level=exhaustive")
endif()

if(CPPCHECK_EXECUTABLE)
    if(NOT DEFINED SKIP_CPP_CHECK)
        add_custom_target(${target}
            COMMAND ${CPPCHECK_EXECUTABLE} ${CPP_CHECK_PARAMS}   ${CMAKE_CURRENT_SOURCE_DIR}
            COMMENT "Running cppcheck on all files in folder ${CMAKE_CURRENT_SOURCE_DIR}"
        )
    else()
    add_custom_target(${target} ALL COMMAND ${CMAKE_COMMAND} -E echo "skipping cppCheck")
    endif()    
else()
    message(WARNING "cppcheck not found. Please install cppcheck to enable static code analysis.")
endif()

endfunction()
