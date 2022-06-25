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

#if defined(TINYJAMBU_BACKEND_C32)

/* Note: The last line should contain ~(t2 & t3) according to the
 * specification but we can avoid the NOT by inverting the words
 * of the key ahead of time. */
#define tinyjambu_steps_32(s0, s1, s2, s3, kword) \
    do { \
        t1 = (s1 >> 15) | (s2 << 17); \
        t2 = (s2 >> 6)  | (s3 << 26); \
        t3 = (s2 >> 21) | (s3 << 11); \
        t4 = (s2 >> 27) | (s3 << 5); \
        s0 ^= t1 ^ (t2 & t3) ^ t4 ^ kword; \
    } while (0)

void tinyjambu_permutation_128
    (tinyjambu_state_t *state, const tinyjambu_key_word_t *key,
     unsigned rounds)
{
    uint32_t t1, t2, t3, t4;

    /* Load the state into local variables */
    uint32_t s0 = state->s[0];
    uint32_t s1 = state->s[1];
    uint32_t s2 = state->s[2];
    uint32_t s3 = state->s[3];

    /* Perform all permutation rounds 128 at a time */
    for (; rounds > 0; --rounds) {
        /* Perform the first set of 128 steps */
        tinyjambu_steps_32(s0, s1, s2, s3, key[0]);
        tinyjambu_steps_32(s1, s2, s3, s0, key[1]);
        tinyjambu_steps_32(s2, s3, s0, s1, key[2]);
        tinyjambu_steps_32(s3, s0, s1, s2, key[3]);

        /* Bail out if this is the last round */
        if ((--rounds) == 0)
            break;

        /* Perform the second set of 128 steps */
        tinyjambu_steps_32(s0, s1, s2, s3, key[0]);
        tinyjambu_steps_32(s1, s2, s3, s0, key[1]);
        tinyjambu_steps_32(s2, s3, s0, s1, key[2]);
        tinyjambu_steps_32(s3, s0, s1, s2, key[3]);
    }

    /* Store the local variables back to the state */
    state->s[0] = s0;
    state->s[1] = s1;
    state->s[2] = s2;
    state->s[3] = s3;
}

#endif /* TINYJAMBU_BACKEND_C32 */
