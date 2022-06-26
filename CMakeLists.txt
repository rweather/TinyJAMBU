cmake_minimum_required(VERSION 3.5)
include(CheckIncludeFiles)
include(CheckFunctionExists)
include(CheckLibraryExists)

# Set the project name and version number.
project(TinyJAMBU VERSION 0.1.0 LANGUAGES C ASM)

# Options to force the use of specific backends for testing.
# Use "cmake -DBACKEND_X=ON" to enable the specific backend.
option(BACKEND_C32 "Force the use of the c32 backend" OFF)

# Other options.
option(COVERAGE "Enable the use of gcov for coverage testing" OFF)

# Option to compile a minimal configuration with just the static library.
# This may be needed when cross-compiling for embedded microcontrollers.
option(MINIMAL "Build a minimal configuration only" OFF)

# Set up the type of build and the compiler flags to use.
if(NOT CMAKE_BUILD_TYPE)
    if(COVERAGE)
        set(CMAKE_BUILD_TYPE Debug)
    else()
        set(CMAKE_BUILD_TYPE Release)
    endif()
endif()
set(CMAKE_C_FLAGS "-Wall -Wextra -DHAVE_CONFIG_H ${CMAKE_C_FLAGS}")
set(CMAKE_C_FLAGS_DEBUG "-g")
set(CMAKE_C_FLAGS_RELEASE "-O3")
if(BACKEND_C32)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DTINYJAMBU_FORCE_C32")
endif()
if(COVERAGE)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fprofile-arcs -ftest-coverage")
endif()

# Require the c99 standard to compile the code.
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED True)

# Set up the assembler options.
set(ASM_OPTIONS "-x assembler-with-cpp")
set(CMAKE_ASM_FLAGS "${CMAKE_C_FLAGS} ${ASM_OPTIONS}")

# Set up the main include directory.
include_directories(src)

# Add the subdirectories.
add_subdirectory(src)
if(NOT MINIMAL)
    add_subdirectory(test)
#    add_subdirectory(examples EXCLUDE_FROM_ALL)
endif()

# Enable testing support.
enable_testing()

# Custom 'test' rule to run the unit tests in a more verbose way.
add_custom_target(test-verbose COMMAND ${CMAKE_CTEST_COMMAND}
    --force-new-ctest-process
    --verbose
    --output-on-failure
)
