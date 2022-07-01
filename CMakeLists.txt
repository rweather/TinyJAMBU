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

# Check for some system features.
check_include_files(strings.h HAVE_STRINGS_H)
check_include_files(sys/random.h HAVE_SYS_RANDOM_H)
check_include_files(sys/syscall.h HAVE_SYS_SYSCALL_H)
check_include_files(time.h HAVE_TIME_H)
check_include_files(sys/time.h HAVE_SYS_TIME_H)
check_include_files(unistd.h HAVE_UNISTD_H)
check_include_files(fcntl.h HAVE_FCNTL_H)
check_function_exists(explicit_bzero HAVE_EXPLICIT_BZERO)
check_function_exists(memset_s HAVE_MEMSET_S)
check_function_exists(getrandom HAVE_GETRANDOM)
check_function_exists(getentropy HAVE_GETENTROPY)
check_function_exists(time HAVE_TIME)
check_function_exists(gettimeofday HAVE_GETTIMEOFDAY)
check_library_exists(rt clock_gettime "" HAVE_LIBRT)
check_function_exists(clock_gettime HAVE_CLOCK_GETTIME)
configure_file(config.h.in config.h)

# Set up the main include directories.
include_directories(src ${PROJECT_BINARY_DIR})

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
