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
#define TINYJAMBU_BACKEND_WORD32 1

#elif defined(TINYJAMBU_FORCE_C64)

/* Force the use of the "c64" backend for testing purposes */
#define TINYJAMBU_BACKEND_C64 1
#define TINYJAMBU_BACKEND_WORD64 1

#elif defined(__AVR__) && __AVR_ARCH__ >= 5

/* AVR5 assembly code backend */
#define TINYJAMBU_BACKEND_AVR5 1
#define TINYJAMBU_BACKEND_WORD32 1

#elif defined(__x86_64) || defined(__x86_64__) || \
      defined(__aarch64__) || defined(__ARM_ARCH_ISA_A64) || \
      defined(_M_AMD64) || defined(_M_X64) || defined(_M_IA64) || \
      (defined(__riscv) && __riscv_xlen == 64)

/* C backend for 64-bit systems */
#define TINYJAMBU_BACKEND_C64 1
#define TINYJAMBU_BACKEND_WORD64 1

#else

/* C backend for 32-bit systems */
#define TINYJAMBU_BACKEND_C32 1
#define TINYJAMBU_BACKEND_WORD32 1

#endif

#endif /* TINYJAMBU_BACKEND_SELECT_H */
