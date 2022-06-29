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
#include <string.h>

void tinyjambu_256_siv_encrypt
    (unsigned char *c, size_t *clen,
     const unsigned char *m, size_t mlen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    tinyjambu_256_state_t state;
    unsigned char nonce[TINYJAMBU_NONCE_SIZE];
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
    state.k[6] = tinyjambu_key_load_even(k + 24);
    state.k[7] = tinyjambu_key_load_odd(k + 28);

    /* Set up the TinyJAMBU state with the key, nonce, and associated data */
    tinyjambu_setup_256(&state, npub, 0x90);
    tinyjambu_absorb_256(&state, ad, adlen, 0x30, TINYJAMBU_ROUNDS(640));

    /* Authenticate the plaintext but do not encrypt it */
    tinyjambu_absorb_256(&state, m, mlen, 0x50, TINYJAMBU_ROUNDS(1280));

    /* Generate the authentication tag */
    tinyjambu_generate_tag_256(&state, c + mlen);

    /* Re-initialize the state with a new nonce based on the tag */
    memcpy(nonce, npub, 4);
    memcpy(nonce + 4, c + mlen, 8);
    tinyjambu_setup_256(&state, nonce, 0xB0);

    /* Encrypt the plaintext to produce the ciphertext */
    while (mlen >= 4) {
        tinyjambu_add_domain(&state, 0xD0); /* Domain sep for message data */
        tinyjambu_permutation_256(&state, TINYJAMBU_ROUNDS(1280));
        data = le_load_word32(m);
        data ^= tinyjambu_squeeze(&state);
        le_store_word32(c, data);
        c += 4;
        m += 4;
        mlen -= 4;
    }
    if (mlen == 1) {
        tinyjambu_add_domain(&state, 0xD0);
        tinyjambu_permutation_256(&state, TINYJAMBU_ROUNDS(1280));
        data = m[0];
        c[0] = (uint8_t)(tinyjambu_squeeze(&state) ^ data);
    } else if (mlen == 2) {
        tinyjambu_add_domain(&state, 0xD0);
        tinyjambu_permutation_256(&state, TINYJAMBU_ROUNDS(1280));
        data = le_load_word16(m);
        data ^= tinyjambu_squeeze(&state);
        c[0] = (uint8_t)data;
        c[1] = (uint8_t)(data >> 8);
    } else if (mlen == 3) {
        tinyjambu_add_domain(&state, 0xD0);
        tinyjambu_permutation_256(&state, TINYJAMBU_ROUNDS(1280));
        data = le_load_word16(m) | (((uint32_t)(m[2])) << 16);
        data ^= tinyjambu_squeeze(&state);
        c[0] = (uint8_t)data;
        c[1] = (uint8_t)(data >> 8);
        c[2] = (uint8_t)(data >> 16);
    }
}

int tinyjambu_256_siv_decrypt
    (unsigned char *m, size_t *mlen,
     const unsigned char *c, size_t clen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    unsigned char *mtemp = m;
    tinyjambu_256_state_t state;
    unsigned char nonce[TINYJAMBU_NONCE_SIZE];
    size_t m2len;
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
    state.k[6] = tinyjambu_key_load_even(k + 24);
    state.k[7] = tinyjambu_key_load_odd(k + 28);

    /* Set up the TinyJAMBU state with the key, nonce, and authentication tag
     * to decrypt the ciphertext to produce the plaintext */
    m2len = *mlen;
    memcpy(nonce, npub, 4);
    memcpy(nonce + 4, c + m2len, 8);
    tinyjambu_setup_256(&state, nonce, 0xB0);

    /* Decrypt the ciphertext to produce the plaintext */
    clen = m2len;
    while (clen >= 4) {
        tinyjambu_add_domain(&state, 0xD0); /* Domain sep for message data */
        tinyjambu_permutation_256(&state, TINYJAMBU_ROUNDS(1280));
        data = le_load_word32(c) ^ tinyjambu_squeeze(&state);
        le_store_word32(m, data);
        c += 4;
        m += 4;
        clen -= 4;
    }
    if (clen == 1) {
        tinyjambu_add_domain(&state, 0xD0);
        tinyjambu_permutation_256(&state, TINYJAMBU_ROUNDS(1280));
        data = (c[0] ^ tinyjambu_squeeze(&state)) & 0xFFU;
        m[0] = (uint8_t)data;
        ++c;
    } else if (clen == 2) {
        tinyjambu_add_domain(&state, 0xD0);
        tinyjambu_permutation_256(&state, TINYJAMBU_ROUNDS(1280));
        data = (le_load_word16(c) ^ tinyjambu_squeeze(&state)) & 0xFFFFU;
        m[0] = (uint8_t)data;
        m[1] = (uint8_t)(data >> 8);
        c += 2;
    } else if (clen == 3) {
        tinyjambu_add_domain(&state, 0xD0);
        tinyjambu_permutation_256(&state, TINYJAMBU_ROUNDS(1280));
        data = le_load_word16(c) | (((uint32_t)(c[2])) << 16);
        data = (data ^ tinyjambu_squeeze(&state)) & 0xFFFFFFU;
        m[0] = (uint8_t)data;
        m[1] = (uint8_t)(data >> 8);
        m[2] = (uint8_t)(data >> 16);
        c += 3;
    }

    /* Set up the TinyJAMBU state with the key, nonce, and associated data
     * to perform the authentication pass over the plaintext */
    tinyjambu_setup_256(&state, npub, 0x90);
    tinyjambu_absorb_256(&state, ad, adlen, 0x30, TINYJAMBU_ROUNDS(640));

    /* Authenticate the plaintext */
    tinyjambu_absorb_256(&state, mtemp, m2len, 0x50, TINYJAMBU_ROUNDS(1280));

    /* Check the authentication tag */
    tinyjambu_generate_tag_256(&state, nonce);
    return tinyjambu_aead_check_tag(mtemp, m2len, nonce, c, TINYJAMBU_TAG_SIZE);
}
