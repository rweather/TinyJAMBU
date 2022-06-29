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
#include "tinyjambu-backend.h"
#include "tinyjambu-util.h"
#include <string.h>

/*
 * This PRNG uses a variation on the TinyJAMBU-256 AEAD mode to
 * expand entropy from the system random number source into an
 * aribtrary amount of random data.
 */

/**
 * \brief Private state information for a TinyJAMBU-based PRNG.
 */
typedef struct
{
    /** State of the PRNG, stored in both the key and state words */
    tinyjambu_256_state_t state;

    /** Callback for obtaining entropy from the system random number source */
    tinyjambu_prng_callback_t callback;

    /** User data pointer for the callback */
    void *user_data;

} tinyjambu_prng_state_p_t;

/** @cond */

/* Compile-time check that tinyjambu_prng_state_p_t can fit within the
 * bounds of tinyjambu_prng_state_t.  This line of code will fail to
 * compile if the private structure is too large for the public one. */
typedef int tinyjambu_prng_state_size_check
    [(sizeof(tinyjambu_prng_state_p_t) <=
            sizeof(tinyjambu_prng_state_t)) * 2 - 1];

/* Nonce to use when initializing the PRNG in tinyjambu_prng_init() */
static uint32_t const tinyjambu_prng_nonce[3] = {
    /* "TinyJAMBUrng" in little-endian byte order */
    0x796E6954, 0x424D414A, 0x676E7255
};

/** @endcond */

/**
 * \brief Sets up the PRNG state with a new key and nonce.
 *
 * \param state Points to the PRNG state, which already contains the key.
 * \param nonce Points to the three words (96 bits) of nonce data to use.
 */
static void tinyjambu_prng_setup
    (tinyjambu_256_state_t *state, const uint32_t *nonce)
{
    /* Initialize the state with the key */
    tinyjambu_init_state(state);
    tinyjambu_permutation_256(state, TINYJAMBU_ROUNDS(1280));

    /* Absorb the three 32-bit words of the 96-bit nonce */
    tinyjambu_add_domain(state, 0xA0); /* Domain separator for the nonce */
    tinyjambu_permutation_256(state, TINYJAMBU_ROUNDS(640));
    tinyjambu_absorb(state, nonce[0]);
    tinyjambu_add_domain(state, 0xA0);
    tinyjambu_permutation_256(state, TINYJAMBU_ROUNDS(640));
    tinyjambu_absorb(state, nonce[1]);
    tinyjambu_add_domain(state, 0xA0);
    tinyjambu_permutation_256(state, TINYJAMBU_ROUNDS(640));
    tinyjambu_absorb(state, nonce[2]);
}

/**
 * \brief Re-keys the PRNG.
 *
 * \param state The PRNG state to be re-keyed.
 */
static void tinyjambu_prng_rekey(tinyjambu_256_state_t *state)
{
    uint32_t data[11];
    unsigned index;

    /* Generate 11 words of output: 8 words for the new key and 3
     * words for the new nonce */
    for (index = 0; index < 11; ++index) {
        tinyjambu_add_domain(state, 0x60);
        tinyjambu_permutation_256(state, TINYJAMBU_ROUNDS(1280));
        data[index] = tinyjambu_squeeze(state);
    }

    /* Re-initialize the PRNG state */
    memcpy(state->k, data, sizeof(state->k));
    tinyjambu_prng_setup(state, data + 8);

    /* Clean up */
    tinyjambu_clean(data, sizeof(data));
}

void tinyjambu_prng_init
    (tinyjambu_prng_state_t *state, tinyjambu_prng_callback_t callback,
     void *user_data)
{
    tinyjambu_prng_state_p_t *pstate = (tinyjambu_prng_state_p_t *)state;

    /* Initialize the state */
    memset(state, 0, sizeof(tinyjambu_prng_state_t));
    pstate->callback = callback;
    pstate->user_data = user_data;

    /* Generate a random key using the system random number source */
    if (callback) {
        (*callback)(user_data, (unsigned char *)(pstate->state.k),
                    sizeof(pstate->state.k), 0);
    }

    /* Set up the TinyJAMBU state using the initial key and nonce */
    tinyjambu_prng_setup(&(pstate->state), tinyjambu_prng_nonce);

    /* Immediately re-key the PRNG */
    tinyjambu_prng_rekey(&(pstate->state));
}

void tinyjambu_prng_free(tinyjambu_prng_state_t *state)
{
    tinyjambu_clean(state, sizeof(tinyjambu_prng_state_t));
}

void tinyjambu_prng_generate
    (tinyjambu_prng_state_t *state, unsigned char *data, size_t size)
{
    tinyjambu_prng_state_p_t *pstate = (tinyjambu_prng_state_p_t *)state;
    unsigned count = 0;

    /* Generate as many 4 byte groups as we can */
    while (size >= 4) {
        tinyjambu_add_domain(&(pstate->state), 0x50);
        tinyjambu_permutation_256(&(pstate->state), TINYJAMBU_ROUNDS(1280));
        memcpy(data, &(pstate->state.s[2]), 4);
        data += 4;
        size -= 4;
        if ((++count) >= (unsigned)(1024 / 4)) {
            /* Re-key automatically every 1K of generated data */
            tinyjambu_prng_rekey(&(pstate->state));
            count = 0;
        }
    }

    /* Handle the left-over bytes */
    if (size > 0) {
        tinyjambu_add_domain(&(pstate->state), 0x50);
        tinyjambu_permutation_256(&(pstate->state), TINYJAMBU_ROUNDS(1280));
        memcpy(data, &(pstate->state.s[2]), size);
        tinyjambu_add_domain(&(pstate->state), size);
    }

    /* Re-key the PRNG */
    tinyjambu_prng_rekey(&(pstate->state));
}

void tinyjambu_prng_feed
    (tinyjambu_prng_state_t *state, const unsigned char *data, size_t size)
{
    tinyjambu_prng_state_p_t *pstate = (tinyjambu_prng_state_p_t *)state;

    /* Absorb as many 4 byte groups as we can */
    while (size >= 4) {
        tinyjambu_add_domain(&(pstate->state), 0x30);
        tinyjambu_permutation_256(&(pstate->state), TINYJAMBU_ROUNDS(1280));
        tinyjambu_absorb(state, le_load_word32(data));
        data += 4;
        size -= 4;
    }

    /* Handle the left-over bytes */
    if (size > 0) {
        uint32_t x = 0;
        memcpy(&x, data, size);
        tinyjambu_add_domain(&(pstate->state), 0x30);
        tinyjambu_permutation_256(&(pstate->state), TINYJAMBU_ROUNDS(1280));
        tinyjambu_absorb(state, x);
        tinyjambu_add_domain(&(pstate->state), size);
    }

    /* Re-key the PRNG */
    tinyjambu_prng_rekey(&(pstate->state));
}

void tinyjambu_prng_reseed(tinyjambu_prng_state_t *state)
{
    tinyjambu_prng_state_p_t *pstate = (tinyjambu_prng_state_p_t *)state;
    unsigned char data[32] = {0};

    /* Acquire new entropy using the system random number source */
    if (pstate->callback)
        (*pstate->callback)(pstate->user_data, data, sizeof(data), 1);

    /* Feed the new entropy into the PRNG */
    tinyjambu_prng_feed(state, data, sizeof(data));

    /* Clean up */
    tinyjambu_clean(data, sizeof(data));
}
