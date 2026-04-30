set(TEST_SOURCES
    unity/unity.c
    test_fixture.c
    test_main.c
    test_reader.c
    test_meta.c
    test_lookup.c
    test_dictionaries.c
)

set(TEST_INCLUDE_DIRS
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/unity
    ${CMAKE_CURRENT_SOURCE_DIR}/../src
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/crypto
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/minilzo
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/utils
    ${CMAKE_CURRENT_SOURCE_DIR}/../deps/uobject/src
)

add_executable(cmdx_tests ${TEST_SOURCES})

target_include_directories(cmdx_tests PRIVATE ${TEST_INCLUDE_DIRS})

target_link_libraries(cmdx_tests PRIVATE cmdx)

add_test(NAME cmdx_test_suite COMMAND cmdx_tests)
