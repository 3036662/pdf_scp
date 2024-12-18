find_package(Boost REQUIRED  COMPONENTS program_options REQUIRED)
include_directories(${Boost_INCLUDE_DIRS})



add_executable(signpdf 
    signpdf.cpp
    options.cpp
    )
target_link_libraries(signpdf PRIVATE ${Boost_PROGRAM_OPTIONS_LIBRARY} )

# translation

if (NOT DEFINED TRANSLATIONS_DIR)
    SET(TRANSLATIONS_DIR ${CMAKE_SOURCE_DIR}/cli/translation/)
    message("Translation path ${TRANSLATIONS_DIR}")
endif()

if (NOT DEFINED TRANSLATIONS_DIR_COMPILED)
    SET(TRANSLATIONS_DIR_COMPILED ${CMAKE_BINARY_DIR}/cli/translation/)
    message("Compiled translation path  ${TRANSLATIONS_DIR_COMPILED}")
endif()

if (NOT DEFINED TRANSLATION_DOMAIN)
    SET(TRANSLATION_DOMAIN signpdf)
    message("Translation domain ${TRANSLATION_DOMAIN}")
endif()

target_compile_definitions(signpdf PUBLIC
    TRANSLATIONS_DIR_COMPILED="${TRANSLATIONS_DIR_COMPILED}"
    TRANSLATION_DOMAIN="${TRANSLATION_DOMAIN}"
)


file(GLOB_RECURSE SOURCES "*.cpp" "*.hpp")
#message(STATUS "Source files: ${SOURCES}")

add_custom_target(update_mo ALL 
    BYPRODUCTS ${TRANSLATION_DOMAIN}.mo 
    COMMAND xgettext --c++ --from-code=utf-8 --join-existing --keyword="tr" -o ${TRANSLATIONS_DIR}messages.pot   ${SOURCES} 
    COMMAND msgmerge ${TRANSLATIONS_DIR}/ru.po ${TRANSLATIONS_DIR}messages.pot -o ${TRANSLATIONS_DIR}/ru.po
    COMMAND mkdir -p ${TRANSLATIONS_DIR_COMPILED}/ru_RU/LC_MESSAGES
    COMMAND msgfmt  ${TRANSLATIONS_DIR}/ru.po --output-file=${TRANSLATIONS_DIR_COMPILED}/ru_RU/LC_MESSAGES/${TRANSLATION_DOMAIN}.mo 
    COMMENT Update translation files ...    
    DEPENDS SOURCES
)

find_package(Intl REQUIRED)
target_link_libraries(signpdf PUBLIC ${Intl_LIBRARY})
target_include_directories(signpdf PUBLIC ${Intl_INCLUDE_DIRS})



if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    FormatDir(cli_pre .)
    add_dependencies(signpdf cli_pre)
    include(ClangTidy)
    AddClangTidy(signpdf)
    include (CppCheck)
    AddCppCheck(signpdf_cppcheck)
    add_dependencies(signpdf signpdf_cppcheck)
endif()

install(TARGETS signpdf
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

# find . -name "*.cpp" -o -name "*.hpp" | xargs xgettext --c++ --from-code=utf-8 --join-existing  -o translation/messages.pot 
# msgfmt  translation/singpdf.po --output-file=translation/ru_RU/signpdf.mo
# msgmerge translation/ru.po translation/messages.pot -o translation/ru.po