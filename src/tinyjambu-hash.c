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

#include "TinyJAMBU.h"
#include "backend/tinyjambu-backend.h"
#include "backend/tinyjambu-util.h"
#include <string.h>

/**
 * \brief Number of TinyJAMBU rounds to use for hashing.
 */
#define TINYJAMBU_HASH_ROUNDS TINYJAMBU_ROUNDS(2560)

/**
 * \brief Private state information for TinyJAMBU-Hash.
 */
typedef struct
{
    /** State of the hash, stored in both the key and state words */
    tinyjambu_256_state_t state;

    /** Position within the current block */
    unsigned posn;

} tinyjambu_hash_state_p_t;

/** @cond */

/* Compile-time check that tinyjambu_hash_state_p_t can fit within the
 * bounds of tinyjambu_hash_state_t.  This line of code will fail to
 * compile if the private structure is too large for the public one. */
typedef int tinyjambu_hash_state_size_check
    [(sizeof(tinyjambu_hash_state_p_t) <=
            sizeof(tinyjambu_hash_state_t)) * 2 - 1];

/** @endcond */

void tinyjambu_hash(unsigned char *out, const unsigned char *in, size_t inlen)
{
    tinyjambu_hash_state_t state;
    tinyjambu_hash_init(&state);
    tinyjambu_hash_update(&state, in, inlen);
    tinyjambu_hash_finalize(&state, out);
}

void tinyjambu_hash_init(tinyjambu_hash_state_t *state)
{
    /* Note: The key needs to be pre-inverted for tinyjambu_permutation_256().
     * k[4..7] are inverted in the compression function, so we only need to
     * worry about pre-inverting k[0..3]. */
    tinyjambu_hash_state_p_t *pstate = (tinyjambu_hash_state_p_t *)state;
    pstate->state.s[0] = 0;
    pstate->state.s[1] = 0;
    pstate->state.s[2] = 0;
    pstate->state.s[3] = 0;
    pstate->state.k[0] = 0xFFFFFFFFU;
    pstate->state.k[1] = 0xFFFFFFFFU;
    pstate->state.k[2] = 0xFFFFFFFFU;
    pstate->state.k[3] = 0xFFFFFFFFU;
    pstate->state.k[4] = 0;
    pstate->state.k[5] = 0;
    pstate->state.k[6] = 0;
    pstate->state.k[7] = 0;
    pstate->posn = 0;
}

static void tinyjambu_hash_compress
    (tinyjambu_256_state_t *state, unsigned char domain)
{
    uint32_t L1[4];
    uint32_t L2[4];

#if !defined(LW_UTIL_LITTLE_ENDIAN)
    /* Convert the input block from little-endian to host byte order */
    state->k[4] = le_load_word32((const unsigned char *)&(state->k[4]));
    state->k[5] = le_load_word32((const unsigned char *)&(state->k[5]));
    state->k[6] = le_load_word32((const unsigned char *)&(state->k[6]));
    state->k[7] = le_load_word32((const unsigned char *)&(state->k[7]));
#endif

    /* tinyjambu_permutation_256() expects the key to be pre-inverted
     * which helps speed up the implementation of the permutation.
     * We already inverted k[0..3] in the previous init or compress. */
    state->k[4] = ~state->k[4];
    state->k[5] = ~state->k[5];
    state->k[6] = ~state->k[6];
    state->k[7] = ~state->k[7];

    /* Apply the domain separator for this block to the previous L
     * value that is stored in the permutation state words */
    state->s[0] ^= domain;
    L1[0] = state->s[0];
    L1[1] = state->s[1];
    L1[2] = state->s[2];
    L1[3] = state->s[3];

    /* L' = Encrypt(K, L) ^ L */
    tinyjambu_permutation_256(state, TINYJAMBU_HASH_ROUNDS);
    L2[0] = L1[0] ^ state->s[0];
    L2[1] = L1[1] ^ state->s[1];
    L2[2] = L1[2] ^ state->s[2];
    L2[3] = L1[3] ^ state->s[3];

    /* R' = Encrypt(K, L ^ 1) ^ L ^ 1 */
    L1[0] ^= 1;
    state->s[0] = L1[0];
    state->s[1] = L1[1];
    state->s[2] = L1[2];
    state->s[3] = L1[3];
    tinyjambu_permutation_256(state, TINYJAMBU_HASH_ROUNDS);
    state->k[0] = ~(state->s[0] ^ L1[0]);
    state->k[1] = ~(state->s[1] ^ L1[1]);
    state->k[2] = ~(state->s[2] ^ L1[2]);
    state->k[3] = ~(state->s[3] ^ L1[3]);

    /* L = L' */
    state->s[0] = L2[0];
    state->s[1] = L2[1];
    state->s[2] = L2[2];
    state->s[3] = L2[3];
}

void tinyjambu_hash_update
    (tinyjambu_hash_state_t *state, const unsigned char *in, size_t inlen)
{
    tinyjambu_hash_state_p_t *pstate = (tinyjambu_hash_state_p_t *)state;
    unsigned char *block = ((unsigned char *)(pstate->state.k)) + 16;
    unsigned temp;

    /* Deal with left-over blocks from last time */
    if (pstate->posn > 0) {
        temp = 16 - pstate->posn;
        if (temp > inlen) {
            temp = (unsigned)inlen;
            memcpy(block + pstate->posn, in, temp);
            pstate->posn += temp;
            return;
        }
        memcpy(block + pstate->posn, in, temp);
        tinyjambu_hash_compress(&(pstate->state), 0);
        in += temp;
        inlen -= temp;
        pstate->posn = 0;
    }

    /* Handle as many full blocks as possible */
    while (inlen >= 16) {
        memcpy(block, in, 16);
        tinyjambu_hash_compress(&(pstate->state), 0);
        in += 16;
        inlen -= 16;
    }

    /* Deal with the left-over data */
    if (inlen > 0) {
        temp = (unsigned)inlen;
        memcpy(block, in, temp);
        pstate->posn = temp;
    }
}

void tinyjambu_hash_finalize(tinyjambu_hash_state_t *state, unsigned char *out)
{
    tinyjambu_hash_state_p_t *pstate = (tinyjambu_hash_state_p_t *)state;
    unsigned char *block = ((unsigned char *)(pstate->state.k)) + 16;

    /* Pad and compress the final block */
    block[pstate->posn] = 0x01;
    memset(block + pstate->posn + 1, 0, 16 - (pstate->posn + 1));
    tinyjambu_hash_compress(&(pstate->state), 2);
    pstate->posn = 0;

    /* Format the output hash value */
    le_store_word32(out,      pstate->state.s[0]);
    le_store_word32(out + 4,  pstate->state.s[1]);
    le_store_word32(out + 8,  pstate->state.s[2]);
    le_store_word32(out + 12, pstate->state.s[3]);
    le_store_word32(out + 16, ~(pstate->state.k[0]));
    le_store_word32(out + 20, ~(pstate->state.k[1]));
    le_store_word32(out + 24, ~(pstate->state.k[2]));
    le_store_word32(out + 28, ~(pstate->state.k[3]));
}
