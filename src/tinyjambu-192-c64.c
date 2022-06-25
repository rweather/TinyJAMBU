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

#include "tinyjambu-backend.h"
#include "tinyjambu-util.h"

#if defined(TINYJAMBU_BACKEND_C64)

/* Perform 64 steps of the TinyJAMBU permutation on 64-bit platforms */
#define tinyjambu_steps_64(s0, s2, kword0, kword1) \
    do { \
        t1 = (s0 >> 47) | (s2 << 17); \
        t2 = (s2 >> 6); \
        t3 = (s2 >> 21); \
        t4 = (s2 >> 27); \
        s0 ^= t1 ^ (uint32_t)((t2 & t3) ^ t4 ^ kword0); \
        t2 |= (s0 << 58); \
        t3 |= (s0 << 43); \
        t4 |= (s0 << 37); \
        s0 ^= ((t2 & t3) ^ t4 ^ kword1) & 0xFFFFFFFF00000000ULL; \
    } while (0)

void tinyjambu_permutation_192
    (tinyjambu_state_t *state, const tinyjambu_key_word_t *key,
     unsigned rounds)
{
    uint64_t t1, t2, t3, t4;

    /* Load the state into local variables */
    uint64_t s0 = state->t[0];
    uint64_t s2 = state->t[1];

    /* Perform all permutation rounds 128 at a time */
    for (; rounds > 0; --rounds) {
        /* Perform the first set of 128 steps */
        tinyjambu_steps_64(s0, s2, key[0], key[1]);
        tinyjambu_steps_64(s2, s0, key[2], key[3]);

        /* Bail out if this is the last round */
        if ((--rounds) == 0)
            break;

        /* Perform the second set of 128 steps */
        tinyjambu_steps_64(s0, s2, key[4], key[5]);
        tinyjambu_steps_64(s2, s0, key[0], key[1]);

        /* Bail out if this is the last round */
        if ((--rounds) == 0)
            break;

        /* Perform the third set of 128 steps */
        tinyjambu_steps_64(s0, s2, key[2], key[3]);
        tinyjambu_steps_64(s2, s0, key[4], key[5]);
    }

    /* Store the local variables back to the state */
    state->t[0] = s0;
    state->t[1] = s2;
}

#endif /* TINYJAMBU_BACKEND_C64 */
