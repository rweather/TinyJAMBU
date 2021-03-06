TinyJAMBU
=========

This repository provides implementations of the TinyJAMBU Authenticated
Encryption with Associated Data (AEAD) algorithm for various platforms.

TinyJAMBU is a finalist in the [NIST lightweight cryptography competition](https://csrc.nist.gov/projects/lightweight-cryptography).  The algorithm is
extremely small and fast.

The following implementations are provided:

* `c32`: Plain C version, using 32-bit words in the permutation.
* `avr5`: Assembly code for AVR5 platforms; e.g. Arduino Uno and Arduino Mega.
* `armv6`: Assembly code for ARMv6 platforms such as Raspberry Pi 3.
* `armv6m`: Assembly code for ARMv6-M platforms such as ARM Cortex M0 and M0+.
* `armv7m`: Assembly code for ARMv7-M platforms such as ARM Cortex M3,
ARM Cortex M4, ARM Cortex M7.  Should also work on ARMv8-M platforms such as
ARM Cortex M33.
* `riscv32e`: 32-bit RISC-V systems, RV32E base integer instruction set.
* `riscv32i`: 32-bit RISC-V systems, RV32I base integer instruction set.
* `riscv64i`: 64-bit RISC-V systems, RV64I base integer instruction set.
* `xtensa`: 32-bit Xtensa processors as used on ESP32 and ESP8266 modules.

Platforms without an assembly version will use the plain C implementation.

TinyJAMBU is inherently 32-bit in its design.  The assembly code backends
for 64-bit systems restrict themselves to 32-bit register operations,
but still provide an improvement over plain C.

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

Extensions
----------

This library provides the following extensions beyond the AEAD mode from
the TinyJAMBU submission to the NIST Lightweight Cryptography Competition:

* Hashing
* Hashed Message Authentication Code (HMAC)
* HMAC-based Key Derivation Function (HKDF)
* Synthetic Initialization Vector (SIV)
* Pseudorandom Number Generator (PRNG)
* Password-Based Key Derivation Function (PBKDF2)

The security level of these experimental modes is presently unknown.
They are not defined in the official TinyJAMBU submission to NIST.

### Hashing Mode

This library contains an experimental implementation of a hashing
algorithm with a 256-bit output built around the TinyJAMBU-256 permutation.

The hash uses the MDPH construction, similar to the Romulus-H submission
to the third round of the NIST Lightweight Cryptography Competition (LWC).
TinyJAMBU-256 is operated as a tweakable block cipher with an increased
number of rounds.

See the `README.md` file in the `tools/hashref` directory for a formal
description of the hashing mode together with reference code.

### HMAC Mode

The hash algorithm is vulnerable to length extension attacks just like SHA256.
So this library builds a HMAC mode on top of the hash in the standard manner.

### SIV Mode

It is inadvisable to reuse the same key and nonce with the AEAD mode
as the ciphertexts for different input plaintexts will be related.
Reusing nonces can be used to break an otherwise sound encryption scheme.

SIV provides a nonce misuse-resistant mode for TinyJAMBU.  It consists of
two passes over the message to authenticate and then encrypt it.  The
authentication tag from the first pass is used as part of the nonce to
perform encryption in the second pass.

If there is a single bit change in the plaintext of a message, then the
resulting ciphertext will be completely different.  In other words,
related plaintexts will not result in related ciphertexts.

If the same key and nonce is used to encrypt the same plaintext again,
then SIV mode will leak that the same message has been resent, but will
not help the attacker decrypt the message.

SIV is best used for key-wrapping.  If you need to store an asymmetric
key pair in the device, then encrypt the key pair with SIV mode with
the nonce set to the address in memory where the key pair will be stored.
Replacing the encrypted key pair later with a new value will use the same
nonce but the ciphertext will be unrelated to the original ciphertext.

SIV can also be used for encrypting memory pages or disk blocks as long as
you have enough extra space to store the 64-bit authentication tag for each
page or block.  Without the tag it is impossible to decrypt the message.

See the `README.md` file in the `tools/sivref` directory for a formal
description of the SIV mode together with reference code.

### Pseudorandom Number Generator

This library provides an API for expanding entropy from a system random
number source into an arbitrary amount of random data.  If the source
has non-uniform entropy distribution, then the PRNG will hash the
input to make the output more uniform.

The PRNG is based on Hash\_DRBG from section 10.1.1 of NIST Special
Publication 800-90A Revision 1.  The hash algorithm is TinyJAMBU-Hash.

The application must supply a function to fetch data from the system
random number source and then the PRNG API takes care of the rest.

The Arudino PRNG example demonstrates how to use the API to generate
random data at runtime.

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
