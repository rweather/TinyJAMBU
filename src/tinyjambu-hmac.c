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
#include <string.h>

/**
 * \brief Block size for TinyJAMBU-HMAC.
 */
#define TINYJAMBU_HMAC_BLOCK_SIZE 64

void tinyjambu_hmac
    (unsigned char *out,
     const unsigned char *key, size_t keylen,
     const unsigned char *in, size_t inlen)
{
    tinyjambu_hmac_state_t state;
    tinyjambu_hmac_init(&state, key, keylen);
    tinyjambu_hmac_update(&state, in, inlen);
    tinyjambu_hmac_finalize(&state, key, keylen, out);
    tinyjambu_clean(&state, sizeof(state));
}

static void tinyjambu_hmac_set_key
    (tinyjambu_hmac_state_t *state, const unsigned char *key, size_t keylen,
     unsigned char mask)
{
    unsigned char block[TINYJAMBU_HMAC_BLOCK_SIZE];
    if (keylen <= TINYJAMBU_HMAC_BLOCK_SIZE) {
        memcpy(block, key, keylen);
    } else {
        tinyjambu_hash_init(&(state->hash));
        tinyjambu_hash_update(&(state->hash), key, keylen);
        tinyjambu_hash_finalize(&(state->hash), block);
        key = block;
        keylen = TINYJAMBU_HASH_SIZE;
    }
    memset(block + keylen, mask, TINYJAMBU_HMAC_BLOCK_SIZE - keylen);
    while (keylen > 0) {
        --keylen;
        block[keylen] ^= mask;
    }
    tinyjambu_hash_init(&(state->hash));
    tinyjambu_hash_update(&(state->hash), block, sizeof(block));
    tinyjambu_clean(block, sizeof(block));
}

void tinyjambu_hmac_init
    (tinyjambu_hmac_state_t *state, const unsigned char *key, size_t keylen)
{
    tinyjambu_hmac_set_key(state, key, keylen, 0x36);
}

void tinyjambu_hmac_update
    (tinyjambu_hmac_state_t *state, const unsigned char *in, size_t inlen)
{
    tinyjambu_hash_update(&(state->hash), in, inlen);
}

void tinyjambu_hmac_finalize
    (tinyjambu_hmac_state_t *state, const unsigned char *key, size_t keylen,
     unsigned char *out)
{
    unsigned char hash[TINYJAMBU_HASH_SIZE];
    tinyjambu_hash_finalize(&(state->hash), hash);
    tinyjambu_hmac_set_key(state, key, keylen, 0x5C);
    tinyjambu_hash_update(&(state->hash), hash, sizeof(hash));
    tinyjambu_hash_finalize(&(state->hash), out);
    tinyjambu_clean(hash, sizeof(hash));
}
