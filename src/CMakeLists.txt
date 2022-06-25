
list(APPEND TINYJAMBU_SOURCES
    TinyJAMBU.h
    tinyjambu-128-aead.c
    tinyjambu-128-c32.c
    tinyjambu-128-c64.c
    tinyjambu-192-aead.c
    tinyjambu-192-c32.c
    tinyjambu-192-c64.c
    tinyjambu-256-aead.c
    tinyjambu-256-c32.c
    tinyjambu-256-c64.c
    tinyjambu-backend.h
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
