
enable_testing()

list(APPEND COMMON_TEST_SOURCES
    test-cipher.c
    test-cipher.h
    test-permutation.c
)

add_executable(tinyjambu-test-static
    ${COMMON_TEST_SOURCES}
)
target_link_libraries(tinyjambu-test-static PUBLIC tinyjambu_static)

add_executable(tinyjambu-test-shared
    ${COMMON_TEST_SOURCES}
)
target_link_libraries(tinyjambu-test-shared PUBLIC tinyjambu)

add_test(NAME TinyJAMBU-static COMMAND tinyjambu-test-static)
add_test(NAME TinyJAMBU-shared COMMAND tinyjambu-test-shared)
