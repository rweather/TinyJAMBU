
list(APPEND TINYJAMBU_SOURCES
    TinyJAMBU.h
    tinyjambu-128-aead.c
    tinyjambu-128-siv.c
    tinyjambu-192-aead.c
    tinyjambu-192-siv.c
    tinyjambu-256-aead.c
    tinyjambu-256-siv.c
    tinyjambu-hash.c
    tinyjambu-hmac.c
    tinyjambu-prng.c
    backend/tinyjambu-128-asm-avr5.S
    backend/tinyjambu-128-asm-armv6.S
    backend/tinyjambu-128-asm-armv6m.S
    backend/tinyjambu-128-asm-armv7m.S
    backend/tinyjambu-128-asm-riscv32e.S
    backend/tinyjambu-128-asm-riscv32i.S
    backend/tinyjambu-128-asm-riscv64i.S
    backend/tinyjambu-128-asm-xtensa.S
    backend/tinyjambu-128-c32.c
    backend/tinyjambu-192-asm-avr5.S
    backend/tinyjambu-192-asm-armv6.S
    backend/tinyjambu-192-asm-armv6m.S
    backend/tinyjambu-192-asm-armv7m.S
    backend/tinyjambu-192-asm-riscv32e.S
    backend/tinyjambu-192-asm-riscv32i.S
    backend/tinyjambu-192-asm-riscv64i.S
    backend/tinyjambu-192-asm-xtensa.S
    backend/tinyjambu-192-c32.c
    backend/tinyjambu-256-asm-avr5.S
    backend/tinyjambu-256-asm-armv6.S
    backend/tinyjambu-256-asm-armv6m.S
    backend/tinyjambu-256-asm-armv7m.S
    backend/tinyjambu-256-asm-riscv32e.S
    backend/tinyjambu-256-asm-riscv32i.S
    backend/tinyjambu-256-asm-riscv64i.S
    backend/tinyjambu-256-asm-xtensa.S
    backend/tinyjambu-256-c32.c
    backend/tinyjambu-aead-common-128.c
    backend/tinyjambu-aead-common-192.c
    backend/tinyjambu-aead-common-256.c
    backend/tinyjambu-aead-common.h
    backend/tinyjambu-backend.h
    backend/tinyjambu-backend-select.h
    backend/tinyjambu-clean.c
    backend/tinyjambu-util.c
    backend/tinyjambu-util.h
)

if(NOT MINIMAL)
add_library(tinyjambu SHARED ${TINYJAMBU_SOURCES})
set_target_properties(tinyjambu PROPERTIES
    VERSION ${TinyJAMBU_VERSION_MAJOR}.${TinyJAMBU_VERSION_MINOR}.${TinyJAMBU_VERSION_PATCH}
    SOVERSION ${TinyJAMBU_VERSION_MAJOR}
)
endif()

add_library(tinyjambu_static STATIC ${TINYJAMBU_SOURCES})

# Install the main include file and the libraries.
install(FILES TinyJAMBU.h DESTINATION include)
if(NOT MINIMAL)
    install(TARGETS tinyjambu DESTINATION lib)
endif()
install(TARGETS tinyjambu_static DESTINATION lib)
