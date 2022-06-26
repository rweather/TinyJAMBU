TinyJAMBU
=========

This repository provides implementations of the TinyJAMBU Authenticated
Encryption with Associated Data (AEAD) algorithm for various platforms.

TinyJAMBU is a finalist in the [NIST lightweight cryptography competition](https://csrc.nist.gov/projects/lightweight-cryptography).  The algorithm is
extremely small and fast.

The following implementations are provided:

* `c32`: Plain C for 32-bit platforms
* `c64`: Plain C for 64-bit platforms
* `avr5`: Assembly code for AVR5 platforms; e.g. Arduino Uno and Arduino Mega.
* `armv7m`: Assembly code for ARMv7-M platforms such as ARM Cortex M3,
ARM Cortex M4, ARM Cortex M7.  Should also work on ARMv8-M platforms such as
ARM Cortex M33.

Platforms without an assembly version will use either the 32-bit or 64-bit
plain C implementation as appropriate.

Building
--------

This repository uses [cmake](https://cmake.org/) to build, so you will need to
have that installed.  Here is the simplest method to compile, test, and
install the library:

    mkdir build
    cd build
    cmake ..
    make
    make test
    sudo make install

To build with a cross-compiler, set the "CC" and "CMAKE\_C\_FLAGS"
variables when invoking cmake:

    mkdir build
    cd build
    CC="avr-gcc" cmake -DMINIMAL=ON -DCMAKE_C_FLAGS="-mmcu=atmega2560" ..
    make

Note carefully the placement of environment variables before the "cmake"
command name, and the cmake variables specified with "-D" after.

The MINIMAL option suppresses the compilation of shared libraries, examples,
and test programs, which may not compile for embedded microcontrollers due to
missing libc functions or other platform constraints.  Only the static library
libtinyjambu\_static.a is built in the minimal configuration.

If you are having problems compiling the assembly code backends, then
I will need some extra information to help diagnose the problem.
Navigate to the "test/compiler" directory and follow the instructions
in the README.md file there.

Arduino
-------

This repository can be used as an Arduino library by copying the contents
of the repository (or cloning it) into `libraries/TinyJAMBU` in your
sketchbook directory.  Then re-launch the Arduino IDE and look for the
TinyJAMBU examples under the File -> Examples submenu.

History
-------

The functionality in this library was originally prototyped in the
[LWC Finalists](https://github.com/rweather/lwc-finalists) repository.
This repository extracts and expands the TinyJAMBU-specific parts of the
original repository.

Contact
-------

For more information on this code, to report bugs, or to suggest
improvements, please contact the author Rhys Weatherley via
[email](mailto:rhys.weatherley@gmail.com).