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
#include "backend/tinyjambu-util.h"
#include "random/tinyjambu-trng.h"
#include <string.h>

/*
 * This PRNG is based on Hash_DRBG from section 10.1.1 of NIST Special
 * Publication 800-90Ar1.
 *
 * Parameters:
 *      Hash algorithm: TinyJAMBU-Hash
 *      Output block length, outlen: 256 bits
 *      Seed length, seedlen: 256 bits
 */

/**
 * \brief Length of the seed values for Hash_DRBG.
 */
#define TINYJAMBU_SEED_LENGTH 32

/**
 * \brief Private state information for the TinyJAMBU-based PRNG.
 */
typedef struct
{
    /** Working value that is updated during each PRNG call */
    unsigned char V[TINYJAMBU_SEED_LENGTH];

    /** Constant that depends upon the most recent reseed */
    unsigned char C[TINYJAMBU_SEED_LENGTH];

    /** Number of times that the PRNG has been reseeded */
    uint32_t reseed_counter;

    /** Number of blocks to generate before forcing a reseed */
    uint32_t reseed_limit;

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

/** @endcond */

/* Hash_df function from section 10.3.1 of SP.800-90Ar1 */
static void tinyjambu_hash_df
    (unsigned char out[TINYJAMBU_SEED_LENGTH], unsigned char marker,
     const unsigned char V[TINYJAMBU_SEED_LENGTH],
     const unsigned char *in, size_t inlen)
{
    /* result = HASH(counter || no_of_bits_to_return || input_string),
     * where input_string = marker || V || in */
    /* Since we are only generating a single block, then the counter is 1
     * and the number of bits to return is 256 */
    unsigned char header[6] = {1, 0, 0, 1, 0, marker};
    tinyjambu_hash_state_t hash;
    tinyjambu_hash_init(&hash);
    if (marker != 0xFF)
        tinyjambu_hash_update(&hash, header, 6);
    else
        tinyjambu_hash_update(&hash, header, 5); /* No marker required */
    tinyjambu_hash_update(&hash, V, TINYJAMBU_SEED_LENGTH);
    tinyjambu_hash_update(&hash, in, inlen);
    tinyjambu_hash_finalize(&hash, out);
    tinyjambu_hash_free(&hash);
}

/* Prefixed Hash function */
static void tinyjambu_hash_prefixed
    (unsigned char out[TINYJAMBU_SEED_LENGTH], unsigned char prefix,
     const unsigned char V[TINYJAMBU_SEED_LENGTH])
{
    /* result = HASH(prefix || V) */
    tinyjambu_hash_state_t hash;
    tinyjambu_hash_init(&hash);
    tinyjambu_hash_update(&hash, &prefix, sizeof(prefix));
    tinyjambu_hash_update(&hash, V, TINYJAMBU_SEED_LENGTH);
    tinyjambu_hash_finalize(&hash, out);
    tinyjambu_hash_free(&hash);
}

/**
 * \brief Default random number source for the system.
 *
 * \param user_data User data for the callback; ignored.
 * \param buf Buffer to fill with random data.
 * \param size Size of the buffer; ignored, assumed to be 32.
 *
 * \return Number of bytes that were fetched from the system TRNG.
 */
static size_t tinyjambu_prng_system
    (void *user_data, unsigned char *buf, size_t size)
{
    (void)user_data;
    if (tinyjambu_trng_generate(buf))
        return size;
    else
        return 0;
}

int tinyjambu_prng_init
    (tinyjambu_prng_state_t *state,
     const unsigned char *custom, size_t custom_len)
{
    return tinyjambu_prng_init_user
        (state, tinyjambu_prng_system, NULL, custom, custom_len);
}

/* Hash_DRBG_Instantiate_algorithm from section 10.1.1.2 of SP.800-90Ar1 */
int tinyjambu_prng_init_user
    (tinyjambu_prng_state_t *state, tinyjambu_prng_callback_t callback,
     void *user_data, const unsigned char *custom, size_t custom_len)
{
    tinyjambu_prng_state_p_t *pstate = (tinyjambu_prng_state_p_t *)state;
    int seeded = 0;

    /* Initialize the state */
    memset(state, 0, sizeof(tinyjambu_prng_state_t));
    if (callback) {
        pstate->callback = callback;
        pstate->user_data = user_data;
    } else {
        pstate->callback = tinyjambu_prng_system;
    }

    /* Obtain entropy input from the system */
    if ((*callback)(user_data, pstate->V, sizeof(pstate->V))
            == sizeof(pstate->V)) {
        seeded = 1;
    }

    /* seed_material = entropy_input || nonce || personalization_string */
    /* In our case, custom = nonce || personalization_string */
    /* V = Hash_df(seed_material, seedlen) */
    tinyjambu_hash_df(pstate->V, 0xFF, pstate->V, custom, custom_len);

    /* C = Hash_df((0x00 || V), seedlen) */
    tinyjambu_hash_df(pstate->C, 0x00, pstate->V, 0, 0);

    /* reseed_counter = 1 */
    pstate->reseed_counter = 1;

    /* Set the initial reseed limit to 1K */
    pstate->reseed_limit = 1024 / TINYJAMBU_SEED_LENGTH;
    return seeded;
}

void tinyjambu_prng_free(tinyjambu_prng_state_t *state)
{
    tinyjambu_clean(state, sizeof(tinyjambu_prng_state_t));
}

/* Hash_DRBG_Generate from section 10.1.1.4 of SP.800-90Ar1 */
void tinyjambu_prng_generate
    (tinyjambu_prng_state_t *state, unsigned char *data, size_t size)
{
    tinyjambu_prng_state_p_t *pstate = (tinyjambu_prng_state_p_t *)state;
    size_t len;
    unsigned char H[TINYJAMBU_SEED_LENGTH];
    uint32_t carry;
    int index;

    /* Bail out if nothing to do */
    if (!size)
        return;

    /* Note: We make a small adjustment to the algorithm from SP.800-90Ar1.
     * The specification generates all requested output and then updates V.
     * We update V every block.  Most practical systems are usually requesting
     * 32 bytes or less at a time, so this shouldn't be too big of a change. */
    while (size > 0) {
        /* Reseed automatically if too much data has been generated already */
        if (pstate->reseed_counter > pstate->reseed_limit)
            tinyjambu_prng_reseed(state);

        /* How many bytes do we need this time? */
        if (size < TINYJAMBU_SEED_LENGTH)
            len = size;
        else
            len = TINYJAMBU_SEED_LENGTH;

        /* Generate the output block: output = Hash(V) */
        tinyjambu_hash(H, pstate->V, sizeof(pstate->V));
        memcpy(data, H, len);

        /*
         * Update V for the next block:
         *
         *      H = Hash(0x03 || V)
         *      V = V + H + C + reseed_counter
         *      reseed_counter = reseed_counter + 1
         */
        tinyjambu_hash_prefixed(H, 0x03, pstate->V);
        carry = pstate->reseed_counter;
        for (index = TINYJAMBU_SEED_LENGTH - 1; index >= 0; --index) {
            carry += pstate->V[index];
            carry += H[index];
            carry += pstate->C[index];
            pstate->V[index] = (unsigned char)carry;
            carry >>= 8;
        }
        ++(pstate->reseed_counter);

        /* Advance to the next block of output */
        data += len;
        size -= len;
    }

    /* Clean up */
    tinyjambu_clean(H, sizeof(H));
}

/* Hash_DRBG_Reseed from section 10.1.1.3 of SP.800-90Ar1 for the special
 * case of no entropy_input, just additional_input */
void tinyjambu_prng_feed
    (tinyjambu_prng_state_t *state, const unsigned char *data, size_t size)
{
    tinyjambu_prng_state_p_t *pstate = (tinyjambu_prng_state_p_t *)state;

    /* seed_material = 0x01 || V || entropy_input || additional_input */
    /* V = Hash_df(seed_material, seedlen) */
    tinyjambu_hash_df(pstate->V, 0x01, pstate->V, data, size);

    /* C = Hash_df((0x00 || V), seedlen) */
    tinyjambu_hash_df(pstate->C, 0x00, pstate->V, 0, 0);

    /* Note: SP.800-90Ar1 says that reseed_counter should be set back to 1
     * when reseeding, but we aren't really reseeding here.  So instead we
     * increase the "reseed needed" counter to force a real reseed later. */
    ++(pstate->reseed_counter);
}

/* Hash_DRBG_Reseed from section 10.1.1.3 of SP.800-90Ar1 for the special
 * case of entropy_input with no additional_input */
int tinyjambu_prng_reseed(tinyjambu_prng_state_t *state)
{
    tinyjambu_prng_state_p_t *pstate = (tinyjambu_prng_state_p_t *)state;
    int reseeded = 0;

    /* Get some new entropy from the system.  If there is no callback
     * then just mix things up a little using the previous V value which
     * will improve forward security even if there is no new entropy */
    memcpy(pstate->C, pstate->V, TINYJAMBU_SEED_LENGTH);
    if ((*(pstate->callback))
            (pstate->user_data, pstate->C, sizeof(pstate->C))
                == sizeof(pstate->C)) {
        reseeded = 1;
    }

    /* seed_material = 0x01 || V || entropy_input || additional_input */
    /* V = Hash_df(seed_material, seedlen) */
    tinyjambu_hash_df(pstate->V, 0x01, pstate->V, pstate->C, sizeof(pstate->C));

    /* C = Hash_df((0x00 || V), seedlen) */
    tinyjambu_hash_df(pstate->C, 0x00, pstate->V, 0, 0);

    /* reseed_counter = 1 */
    pstate->reseed_counter = 1;
    return reseeded;
}

void tinyjambu_prng_set_reseed_limit
    (tinyjambu_prng_state_t *state, size_t limit)
{
    tinyjambu_prng_state_p_t *pstate = (tinyjambu_prng_state_p_t *)state;
#if !defined(__SIZEOF_SIZE_T__) || __SIZEOF_SIZE_T__ >= 4
    /* 32-bit or better system; clamp the value to 1M */
    if (limit > 1048576U)
        limit = 1048576U;
#else
    /* 8-bit or 16-bit system; clamp the value just shy of 64K */
    if (limit > (unsigned)(65535 - TINYJAMBU_SEED_LENGTH))
        limit = 65535U - TINYJAMBU_SEED_LENGTH;
#endif
    limit = (limit + TINYJAMBU_SEED_LENGTH - 1) / TINYJAMBU_SEED_LENGTH;
    if (!limit)
        limit = 1;
    pstate->reseed_limit = limit;
}
