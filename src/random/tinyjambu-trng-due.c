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

#include "tinyjambu-trng.h"
#include <string.h>

#if defined(TINYJAMBU_TRNG_DUE)

#include <Arduino.h>

static int volatile due_init_done = 0;

static inline void tinyjambu_trng_init_internal(void)
{
    if (!due_init_done) {
        /* Once-only initialization of the TRNG peripheral */
        pmc_enable_periph_clk(ID_TRNG);
        REG_TRNG_CR = TRNG_CR_KEY(0x524E47) | TRNG_CR_ENABLE;
        REG_TRNG_IDR = TRNG_IDR_DATRDY;
        due_init_done = 1;
    }
}

static inline int tinyjambu_trng_generate_word(uint32_t *x)
{
    /* SAM3X8E's TRNG returns a new random word every 84 clock cycles.
     * If the TRNG is not ready after 100 iterations, assume it has failed. */
    int count = 100;
    while ((REG_TRNG_ISR & TRNG_ISR_DATRDY) == 0) {
        if ((--count) <= 0) {
            *x = 0xABADBEEF; /* This is a problem! */
            return 0;
        }
    }
    *x = REG_TRNG_ODATA;
    return 1;
}

int tinyjambu_trng_generate(unsigned char *out)
{
    unsigned outlen = TINYJAMBU_SYSTEM_SEED_SIZE;
    uint32_t x;
    int ok = 1;
    tinyjambu_trng_init_internal();
    while (outlen >= sizeof(x)) {
        if (!tinyjambu_trng_generate_word(&x))
            ok = 0;
        memcpy(out, &x, sizeof(x));
        out += sizeof(x);
        outlen -= sizeof(x);
    }
    return ok;
}

#endif /* TINYJAMBU_TRNG_DUE */
