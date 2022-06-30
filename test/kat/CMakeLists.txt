
enable_testing()

# Program for running KAT tests.
add_executable(kat
    aead-metadata.h
    algorithms.c
    algorithms.h
    internal-blake2s.c
    internal-blake2s.h
    internal-chachapoly.c
    internal-chachapoly.h
    kat.c
    timing.c
    timing.h
)
target_link_libraries(kat PUBLIC tinyjambu_static)
target_include_directories(kat
    PUBLIC
        ${CMAKE_CURRENT_LIST_DIR}/../../src/aead
)
if(HAVE_LIBRT)
    target_link_libraries(kat PRIVATE -lrt)
endif()
if(MINGW)
    target_link_options(kat PUBLIC --static)
endif()

# Program for generating KAT tests.
add_executable(kat-gen
    aead-metadata.h
    algorithms.c
    algorithms.h
    kat-gen.c
)
target_link_libraries(kat-gen PUBLIC tinyjambu_static)
if(HAVE_LIBRT)
    target_link_libraries(kat-gen PRIVATE -lrt)
endif()
if(MINGW)
    target_link_options(kat-gen PUBLIC --static)
endif()

# Function to perform KAT tests on a specific algorithm.
function(kat_test algorithm kat_file gen_opts)
    # Add a unit test to run the KAT test.
    add_test(NAME kat-run-${algorithm} COMMAND bash -c "${CMAKE_CURRENT_BINARY_DIR}/kat ${algorithm} - <${CMAKE_CURRENT_LIST_DIR}/${kat_file}")

    # Add a unit test to generate the KAT output and cross-check.
    add_test(NAME kat-gen-${algorithm} COMMAND bash -c "${CMAKE_CURRENT_BINARY_DIR}/kat-gen ${gen_opts} ${algorithm} - | diff --strip-trailing-cr -q - ${CMAKE_CURRENT_LIST_DIR}/${kat_file}")

    # Add a custom command to run performance tests on the algorithm.
    add_custom_command(
        OUTPUT kat-perf-${algorithm}
        COMMAND bash -c "${CMAKE_CURRENT_BINARY_DIR}/kat --performance ${algorithm} - <${CMAKE_CURRENT_LIST_DIR}/${kat_file}"
    )
    list(APPEND PERF_RULES kat-perf-${algorithm})
    set(PERF_RULES ${PERF_RULES} PARENT_SCOPE)
endfunction()

# Perform all of the Known Answer Tests (KAT's).
kat_test(TinyJAMBU-128 TinyJAMBU-128.txt "")
kat_test(TinyJAMBU-192 TinyJAMBU-192.txt "")
kat_test(TinyJAMBU-256 TinyJAMBU-256.txt "")
kat_test(TinyJAMBU-128-SIV TinyJAMBU-128-SIV.txt "")
kat_test(TinyJAMBU-192-SIV TinyJAMBU-192-SIV.txt "")
kat_test(TinyJAMBU-256-SIV TinyJAMBU-256-SIV.txt "")
kat_test(TinyJAMBU-Hash TinyJAMBU-HASH.txt "")

# Add a custom 'perf' target to run all performance tests.
add_custom_target(perf DEPENDS ${PERF_RULES})
