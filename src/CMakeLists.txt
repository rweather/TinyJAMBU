
list(APPEND TINYJAMBU_SOURCES
    TinyJAMBU.h
    tinyjambu-128-aead.c
    tinyjambu-128-asm-avr5.S
    tinyjambu-128-asm-armv6.S
    tinyjambu-128-asm-armv6m.S
    tinyjambu-128-asm-armv7m.S
    tinyjambu-128-asm-riscv32e.S
    tinyjambu-128-asm-riscv32i.S
    tinyjambu-128-asm-riscv64i.S
    tinyjambu-128-asm-xtensa.S
    tinyjambu-128-c32.c
    tinyjambu-192-aead.c
    tinyjambu-192-asm-avr5.S
    tinyjambu-192-asm-armv6.S
    tinyjambu-192-asm-armv6m.S
    tinyjambu-192-asm-armv7m.S
    tinyjambu-192-asm-riscv32e.S
    tinyjambu-192-asm-riscv32i.S
    tinyjambu-192-asm-riscv64i.S
    tinyjambu-192-asm-xtensa.S
    tinyjambu-192-c32.c
    tinyjambu-256-aead.c
    tinyjambu-256-asm-avr5.S
    tinyjambu-256-asm-armv6.S
    tinyjambu-256-asm-armv6m.S
    tinyjambu-256-asm-armv7m.S
    tinyjambu-256-asm-riscv32e.S
    tinyjambu-256-asm-riscv32i.S
    tinyjambu-256-asm-riscv64i.S
    tinyjambu-256-asm-xtensa.S
    tinyjambu-256-c32.c
    tinyjambu-backend.h
    tinyjambu-backend-select.h
    tinyjambu-util.c
    tinyjambu-util.h
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
