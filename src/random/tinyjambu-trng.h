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

#ifndef TINYJAMBU_TRNG_H
#define TINYJAMBU_TRNG_H

/**
 * \file tinyjambu-trng.h
 * \brief Access to the system's random number source.
 *
 * This is not a public API and should only be used by the library itself.
 * Applications should use the PRNG API instead.
 *
 * The data that comes out of the system's random number source may not
 * be very good for direct application use with non-uniform entropy
 * distribution in the output.
 *
 * If the source is embedded in a chip then the user may have reason to
 * distrust the chip vendor.
 *
 * The PRNG will destroy any watermarks from the chip vendor and spread
 * out the entropy in the source before passing the data to the application.
 */

#include "tinyjambu-trng-select.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Number of bytes to request from the system TRNG to seed a PRNG.
 */
#define TINYJAMBU_SYSTEM_SEED_SIZE 32

/**
 * \brief Generates a buffer of bytes from the system TRNG source.
 *
 * \param out Output buffer to be filled with random bytes.  Must be at
 * least TINYJAMBU_SYSTEM_SEED_SIZE bytes in length.
 *
 * \return Non-zero if the system random number source is working;
 * zero if there is no system random number source or it has failed.
 *
 * This function should try to generate high quality random data even
 * if it is a little slower.
 */
int tinyjambu_trng_generate(unsigned char *out);

#ifdef __cplusplus
}
#endif

#endif
