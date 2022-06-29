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
#include "backend/tinyjambu-aead-common.h"

void tinyjambu_192_aead_encrypt
    (unsigned char *c, size_t *clen,
     const unsigned char *m, size_t mlen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    tinyjambu_192_state_t state;
    uint32_t data;

    /* Set the length of the returned ciphertext */
    *clen = mlen + TINYJAMBU_TAG_SIZE;

    /* Unpack the key and invert it for later */
    state.k[0] = tinyjambu_key_load_even(k);
    state.k[1] = tinyjambu_key_load_odd(k + 4);
    state.k[2] = tinyjambu_key_load_even(k + 8);
    state.k[3] = tinyjambu_key_load_odd(k + 12);
    state.k[4] = tinyjambu_key_load_even(k + 16);
    state.k[5] = tinyjambu_key_load_odd(k + 20);

    /* Set up the TinyJAMBU state with the key, nonce, and associated data */
    tinyjambu_setup_192(&state, npub, 0x10);
    tinyjambu_absorb_192(&state, ad, adlen, 0x30, TINYJAMBU_ROUNDS(640));

    /* Encrypt the plaintext to produce the ciphertext */
    while (mlen >= 4) {
        tinyjambu_add_domain(&state, 0x50); /* Domain sep for message data */
        tinyjambu_permutation_192(&state, TINYJAMBU_ROUNDS(1152));
        data = le_load_word32(m);
        tinyjambu_absorb(&state, data);
        data ^= tinyjambu_squeeze(&state);
        le_store_word32(c, data);
        c += 4;
        m += 4;
        mlen -= 4;
    }
    if (mlen == 1) {
        tinyjambu_add_domain(&state, 0x50);
        tinyjambu_permutation_192(&state, TINYJAMBU_ROUNDS(1152));
        data = m[0];
        tinyjambu_absorb(&state, data);
        tinyjambu_add_domain(&state, 0x01);
        c[0] = (uint8_t)(tinyjambu_squeeze(&state) ^ data);
    } else if (mlen == 2) {
        tinyjambu_add_domain(&state, 0x50);
        tinyjambu_permutation_192(&state, TINYJAMBU_ROUNDS(1152));
        data = le_load_word16(m);
        tinyjambu_absorb(&state, data);
        tinyjambu_add_domain(&state, 0x02);
        data ^= tinyjambu_squeeze(&state);
        c[0] = (uint8_t)data;
        c[1] = (uint8_t)(data >> 8);
    } else if (mlen == 3) {
        tinyjambu_add_domain(&state, 0x50);
        tinyjambu_permutation_192(&state, TINYJAMBU_ROUNDS(1152));
        data = le_load_word16(m) | (((uint32_t)(m[2])) << 16);
        tinyjambu_absorb(&state, data);
        tinyjambu_add_domain(&state, 0x03);
        data ^= tinyjambu_squeeze(&state);
        c[0] = (uint8_t)data;
        c[1] = (uint8_t)(data >> 8);
        c[2] = (uint8_t)(data >> 16);
    }

    /* Generate the authentication tag */
    tinyjambu_generate_tag_192(&state, c + mlen);
}

int tinyjambu_192_aead_decrypt
    (unsigned char *m, size_t *mlen,
     const unsigned char *c, size_t clen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    unsigned char *mtemp = m;
    tinyjambu_192_state_t state;
    unsigned char tag[TINYJAMBU_TAG_SIZE];
    uint32_t data;

    /* Validate the ciphertext length and set the return "mlen" value */
    if (clen < TINYJAMBU_TAG_SIZE)
        return -1;
    *mlen = clen - TINYJAMBU_TAG_SIZE;

    /* Unpack the key and invert it for later */
    state.k[0] = tinyjambu_key_load_even(k);
    state.k[1] = tinyjambu_key_load_odd(k + 4);
    state.k[2] = tinyjambu_key_load_even(k + 8);
    state.k[3] = tinyjambu_key_load_odd(k + 12);
    state.k[4] = tinyjambu_key_load_even(k + 16);
    state.k[5] = tinyjambu_key_load_odd(k + 20);

    /* Set up the TinyJAMBU state with the key, nonce, and associated data */
    tinyjambu_setup_192(&state, npub, 0x10);
    tinyjambu_absorb_192(&state, ad, adlen, 0x30, TINYJAMBU_ROUNDS(640));

    /* Decrypt the ciphertext to produce the plaintext */
    clen -= TINYJAMBU_TAG_SIZE;
    while (clen >= 4) {
        tinyjambu_add_domain(&state, 0x50); /* Domain sep for message data */
        tinyjambu_permutation_192(&state, TINYJAMBU_ROUNDS(1152));
        data = le_load_word32(c) ^ tinyjambu_squeeze(&state);
        tinyjambu_absorb(&state, data);
        le_store_word32(m, data);
        c += 4;
        m += 4;
        clen -= 4;
    }
    if (clen == 1) {
        tinyjambu_add_domain(&state, 0x50);
        tinyjambu_permutation_192(&state, TINYJAMBU_ROUNDS(1152));
        data = (c[0] ^ tinyjambu_squeeze(&state)) & 0xFFU;
        tinyjambu_absorb(&state, data);
        tinyjambu_add_domain(&state, 0x01);
        m[0] = (uint8_t)data;
        ++c;
    } else if (clen == 2) {
        tinyjambu_add_domain(&state, 0x50);
        tinyjambu_permutation_192(&state, TINYJAMBU_ROUNDS(1152));
        data = (le_load_word16(c) ^ tinyjambu_squeeze(&state)) & 0xFFFFU;
        tinyjambu_absorb(&state, data);
        tinyjambu_add_domain(&state, 0x02);
        m[0] = (uint8_t)data;
        m[1] = (uint8_t)(data >> 8);
        c += 2;
    } else if (clen == 3) {
        tinyjambu_add_domain(&state, 0x50);
        tinyjambu_permutation_192(&state, TINYJAMBU_ROUNDS(1152));
        data = le_load_word16(c) | (((uint32_t)(c[2])) << 16);
        data = (data ^ tinyjambu_squeeze(&state)) & 0xFFFFFFU;
        tinyjambu_absorb(&state, data);
        tinyjambu_add_domain(&state, 0x03);
        m[0] = (uint8_t)data;
        m[1] = (uint8_t)(data >> 8);
        m[2] = (uint8_t)(data >> 16);
        c += 3;
    }

    /* Check the authentication tag */
    tinyjambu_generate_tag_192(&state, tag);
    return tinyjambu_aead_check_tag(mtemp, *mlen, tag, c, TINYJAMBU_TAG_SIZE);
}
