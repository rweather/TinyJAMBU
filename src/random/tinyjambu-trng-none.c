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
#include "../TinyJAMBU.h"
#include <string.h>

#if defined(TINYJAMBU_TRNG_NONE)

#if defined(HAVE_CONFIG_H)
#include <config.h>
#endif
#if defined(ARDUINO)
#include <Arduino.h>
#endif
#if defined(HAVE_TIME_H)
#include <time.h>
#endif
#if defined(HAVE_SYS_TIME_H)
#include <sys/time.h>
#endif

#warning "No system random number source found"

int tinyjambu_trng_get_bytes(unsigned char *out, size_t outlen) __attribute__((weak));
int tinyjambu_trng_get_bytes_is_good(void) __attribute__((weak));

/**
 * \brief Escape hatch that allows applications to provide their
 * own interface to the system TRNG when the library does not know
 * how to generate random bytes on its own.
 *
 * \param out Buffer to fill with random bytes.
 * \param outlen Number of bytes to provide.
 *
 * \return Non-zero if the application provided the bytes or zero
 * if the application does not know how to generate random bytes.
 */
int tinyjambu_trng_get_bytes(unsigned char *out, size_t outlen)
{
    (void)out;
    (void)outlen;
    return 0;
}

/**
 * \brief Escape hatch that declares that the application's output
 * from tinyjambu_trng_get_bytes() is good and there is no need to run a
 * global PRNG to mix up the data.
 *
 * \return Non-zero if the data from tinyjambu_trng_get_bytes() is good.
 *
 * This escape hatch should only be used if the application knows
 * that it is getting random data from a good source.
 */
int tinyjambu_trng_get_bytes_is_good(void)
{
    return 0;
}

int tinyjambu_trng_generate(unsigned char *out)
{
    tinyjambu_hash_state_t hash;
    int ok;

    /* If the application has declared tinyjambu_trng_get_bytes() to be good,
     * then use it directly rather than run a global PRNG.  We fall through
     * if tinyjambu_trng_get_bytes() subsequently fails anyway. */
    if (tinyjambu_trng_get_bytes_is_good()) {
        ok = tinyjambu_trng_get_bytes(out, TINYJAMBU_SYSTEM_SEED_SIZE);
        if (ok)
            return 1;
    }

    /* Hash as many time values as we can find into a common seed */
    tinyjambu_hash_init(&hash);
#if defined(ARDUINO)
    /* Add the current Arduino time as a seed to provide some extra jitter */
    {
        uint32_t x[2];
        x[0] = (uint32_t)millis();
        x[1] = (uint32_t)micros();
        tinyjambu_hash_update(&hash, (const unsigned char *)x, sizeof(x));
    }
#elif defined(USE_HAL_DRIVER)
    /* Mix in the STM32 millisecond tick counter for some extra jitter */
    {
        uint32_t x = HAL_GetTick();
        tinyjambu_hash_update(&hash, (const unsigned char *)&x, sizeof(x));
    }
#elif defined(HAVE_CLOCK_GETTIME)
    /* Mix in the monotonic and real times in nanoseconds */
    {
        struct timespec ts;
#if defined(CLOCK_MONOTONIC)
        clock_gettime(CLOCK_MONOTONIC, &ts);
        tinyjambu_hash_update(&hash, (const unsigned char *)&ts, sizeof(ts));
#endif
        clock_gettime(CLOCK_REALTIME, &ts);
        tinyjambu_hash_update(&hash, (const unsigned char *)&ts, sizeof(ts));
        tinyjambu_clean(&ts, sizeof(ts));
    }
#elif defined(HAVE_GETTIMEOFDAY)
    /* Mix in the current time of day in microseconds */
    {
        struct timeval tv;
        gettimeofday(&tv, 0);
        tinyjambu_hash_update(&hash, (const unsigned char *)&tv, sizeof(tv));
        tinyjambu_clean(&tv, sizeof(tv));
    }
#elif defined(HAVE_TIME)
    /* Mix in the current time of day in seconds (very little jitter) */
    {
        time_t t = time(0);
        tinyjambu_hash_update(&hash, (const unsigned char *)&t, sizeof(t));
    }
#endif
    tinyjambu_hash_finalize(&hash, out);

    /* We don't have a real random number source */
    return 0;
}

#endif /* TINYJAMBU_TRNG_NONE */
