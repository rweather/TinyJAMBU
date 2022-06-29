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

#include "tinyjambu-aead-common.h"

void tinyjambu_setup_256
    (tinyjambu_256_state_t *state, const unsigned char *nonce,
     unsigned char domain)
{
    /* Initialize the state with the key */
    tinyjambu_init_state(state);
    tinyjambu_permutation_256(state, TINYJAMBU_ROUNDS(1280));

    /* Absorb the three 32-bit words of the 96-bit nonce */
    tinyjambu_add_domain(state, domain); /* Domain separator for the nonce */
    tinyjambu_permutation_256(state, TINYJAMBU_ROUNDS(640));
    tinyjambu_absorb(state, le_load_word32(nonce));
    tinyjambu_add_domain(state, domain);
    tinyjambu_permutation_256(state, TINYJAMBU_ROUNDS(640));
    tinyjambu_absorb(state, le_load_word32(nonce + 4));
    tinyjambu_add_domain(state, domain);
    tinyjambu_permutation_256(state, TINYJAMBU_ROUNDS(640));
    tinyjambu_absorb(state, le_load_word32(nonce + 8));
}

void tinyjambu_absorb_256
    (tinyjambu_256_state_t *state, const unsigned char *data,
     size_t size, unsigned char domain, unsigned rounds)
{
    /* Process as many full 32-bit words of data as we can */
    while (size >= 4) {
        tinyjambu_add_domain(state, domain);
        tinyjambu_permutation_256(state, rounds);
        tinyjambu_absorb(state, le_load_word32(data));
        data += 4;
        size -= 4;
    }

    /* Handle the left-over associated data bytes, if any */
    if (size == 1) {
        tinyjambu_add_domain(state, domain);
        tinyjambu_permutation_256(state, rounds);
        tinyjambu_absorb(state, data[0]);
        tinyjambu_add_domain(state, 0x01);
    } else if (size == 2) {
        tinyjambu_add_domain(state, domain);
        tinyjambu_permutation_256(state, rounds);
        tinyjambu_absorb(state, le_load_word16(data));
        tinyjambu_add_domain(state, 0x02);
    } else if (size == 3) {
        tinyjambu_add_domain(state, domain);
        tinyjambu_permutation_256(state, rounds);
        tinyjambu_absorb
            (state, le_load_word16(data) | (((uint32_t)(data[2])) << 16));
        tinyjambu_add_domain(state, 0x03);
    }
}

void tinyjambu_generate_tag_256
    (tinyjambu_256_state_t *state, unsigned char *tag)
{
    tinyjambu_add_domain(state, 0x70); /* Domain separator for finalization */
    tinyjambu_permutation_256(state, TINYJAMBU_ROUNDS(1280));
    le_store_word32(tag, tinyjambu_squeeze(state));
    tinyjambu_add_domain(state, 0x70);
    tinyjambu_permutation_256(state, TINYJAMBU_ROUNDS(640));
    le_store_word32(tag + 4, tinyjambu_squeeze(state));
}

