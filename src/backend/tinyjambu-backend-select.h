/*
 * Copyright (C) 2022 Southern Storm Software, Pty Ltd.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#ifndef TINYJAMBU_BACKEND_SELECT_H
#define TINYJAMBU_BACKEND_SELECT_H

/**
 * \file tinyjambu-backend-select.h
 * \brief Select the TinyJAMBU backend implementation to use.
 */

#ifdef __cplusplus
extern "C" {
#endif

/* Select the default back end to use for the TinyJAMBU permutation,
 * and any properties we can use to optimize use of the permutation. */

#if defined(TINYJAMBU_FORCE_C32)

/* Force the use of the "c32" backend for testing purposes */
#define TINYJAMBU_BACKEND_C32 1

#elif defined(__AVR__) && __AVR_ARCH__ >= 5

/* AVR5 assembly code backend */
#define TINYJAMBU_BACKEND_AVR5 1

#elif defined(__ARM_ARCH_ISA_THUMB) && __ARM_ARCH == 8 && defined(__ARM_ARCH_8M__)

/* Assembly backend for ARMv8-M systems; e.g. ARM Cortex M33 */
/* This can actually use the same backend as ARMv7-M systems */
#define TINYJAMBU_BACKEND_ARMV7M 1

#elif defined(__ARM_ARCH_ISA_THUMB) && __ARM_ARCH == 7

/* Assembly backend for ARMv7-M systems; e.g. ARM Cortex M3, M4, and M7 */
/* This backend has also been tested to work on ARMv7-A systems */
#define TINYJAMBU_BACKEND_ARMV7M 1

#elif defined(__ARM_ARCH_ISA_THUMB) && __ARM_ARCH == 6 && defined(__ARM_ARCH_6M__)

/* Assembly backend for ARMv6-M systems; e.g. ARM Cortex M0+ */
#define TINYJAMBU_BACKEND_ARMV6M 1

#elif defined(__ARM_ARCH) && __ARM_ARCH == 6

/* Assembly backend for ARMv6 systems, should work with thumb and non-thumb */
#define TINYJAMBU_BACKEND_ARMV6 1

#elif defined(__riscv) && __riscv_xlen == 64

/* Assembly backend for RISC-V systems, RV64I base integer instruction set */
#define TINYJAMBU_BACKEND_RISCV64I 1

#elif defined(__riscv) && __riscv_xlen == 32 && defined(__riscv_32e)

/* Assembly backend for RISC-V systems, RV32E base integer instruction set */
#define TINYJAMBU_BACKEND_RISCV32E 1

#elif defined(__riscv) && __riscv_xlen == 32

/* Assembly backend for RISC-V systems, RV32I base integer instruction set */
#define TINYJAMBU_BACKEND_RISCV32I 1

#elif defined(__XTENSA__)

/* Assembly backend for Xtensa-based systems */
#define TINYJAMBU_BACKEND_XTENSA 1

#else

/* Plain C backend */
#define TINYJAMBU_BACKEND_C32 1

#endif

#endif /* TINYJAMBU_BACKEND_SELECT_H */
