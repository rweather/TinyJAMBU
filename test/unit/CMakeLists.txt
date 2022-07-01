
enable_testing()

list(APPEND COMMON_TEST_SOURCES
    test-cipher.c
    test-cipher.h
)

add_executable(tinyjambu-test-static
    ${COMMON_TEST_SOURCES}
    test-permutation.c
)
target_link_libraries(tinyjambu-test-static PUBLIC tinyjambu_static)

add_executable(tinyjambu-test-shared
    ${COMMON_TEST_SOURCES}
    test-permutation.c
)
target_link_libraries(tinyjambu-test-shared PUBLIC tinyjambu)

add_executable(tinyjambu-test-pbkdf2-static
    ${COMMON_TEST_SOURCES}
    test-pbkdf2.c
)
target_link_libraries(tinyjambu-test-pbkdf2-static PUBLIC tinyjambu_static)

add_executable(tinyjambu-test-pbkdf2-shared
    ${COMMON_TEST_SOURCES}
    test-pbkdf2.c
)
target_link_libraries(tinyjambu-test-pbkdf2-shared PUBLIC tinyjambu)

add_executable(tinyjambu-test-hkdf-static
    ${COMMON_TEST_SOURCES}
    test-hkdf.c
)
target_link_libraries(tinyjambu-test-hkdf-static PUBLIC tinyjambu_static)

add_executable(tinyjambu-test-hkdf-shared
    ${COMMON_TEST_SOURCES}
    test-hkdf.c
)
target_link_libraries(tinyjambu-test-hkdf-shared PUBLIC tinyjambu)

add_test(NAME permutation-static COMMAND tinyjambu-test-static)
add_test(NAME permutation-shared COMMAND tinyjambu-test-shared)
add_test(NAME pbkdf2-static COMMAND tinyjambu-test-pbkdf2-static)
add_test(NAME pbkdf2-shared COMMAND tinyjambu-test-pbkdf2-shared)
add_test(NAME hkdf-static COMMAND tinyjambu-test-hkdf-static)
add_test(NAME hkdf-shared COMMAND tinyjambu-test-hkdf-shared)
