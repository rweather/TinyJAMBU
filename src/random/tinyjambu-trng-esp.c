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

#if defined(TINYJAMBU_TRNG_ESP)

#if defined(ESP8266)
#define esp_random() (*((volatile uint32_t *)0x3FF20E44))
#else
/* It is variable from one ESP32 SDK to the next which header this
 * function is declared in, so we declare it ourselves. */
extern uint32_t esp_random(void);
#endif

int tinyjambu_trng_generate(unsigned char *out)
{
    unsigned outlen = TINYJAMBU_SYSTEM_SEED_SIZE;
    uint32_t x;
    while (outlen >= sizeof(x)) {
        x = esp_random();
        memcpy(out, &x, sizeof(x));
        out += sizeof(x);
        outlen -= sizeof(x);
    }
    return 1; /* Assume that it works */
}

#endif /* TINYJAMBU_TRNG_ESP */
