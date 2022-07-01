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
 * \brief Default output block size for TinyJAMBU-HKDF.  Key material is
 * generated in blocks of this size.
 */
#define TINYJAMBU_HKDF_OUTPUT_SIZE TINYJAMBU_HMAC_SIZE

/**
 * \brief Private state for incremental generation of key material
 * from TinyJAMBU-HKDF.
 */
typedef struct
{
    /** Hashed key from tinyjambu_hkdf_extract() */
    unsigned char prk[TINYJAMBU_HKDF_OUTPUT_SIZE];

    /** Last output block that was generated for tinyjambu_hkdf_expand() */
    unsigned char out[TINYJAMBU_HKDF_OUTPUT_SIZE];

    /** Counter for the next output block to generate */
    unsigned char counter;

    /** Current position in the output block */
    unsigned char posn;

} tinyjambu_hkdf_state_p_t;

/** @cond */

/* Compile-time check that tinyjambu_hkdf_state_p_t can fit within the
 * bounds of tinyjambu_hkdf_state_t.  This line of code will fail to
 * compile if the private structure is too large for the public one. */
typedef int tinyjambu_hkdf_state_size_check
    [(sizeof(tinyjambu_hkdf_state_p_t) <=
            sizeof(tinyjambu_hkdf_state_t)) * 2 - 1];

/** @endcond */

int tinyjambu_hkdf
    (unsigned char *out, size_t outlen,
     const unsigned char *key, size_t keylen,
     const unsigned char *salt, size_t saltlen,
     const unsigned char *info, size_t infolen)
{
    tinyjambu_hkdf_state_t state;
    if (outlen > (size_t)(TINYJAMBU_HMAC_SIZE * 255))
        return -1;
    tinyjambu_hkdf_extract(&state, key, keylen, salt, saltlen);
    tinyjambu_hkdf_expand(&state, info, infolen, out, outlen);
    tinyjambu_clean(&state, sizeof(state));
    return 0;
}

void tinyjambu_hkdf_extract
    (tinyjambu_hkdf_state_t *state,
     const unsigned char *key, size_t keylen,
     const unsigned char *salt, size_t saltlen)
{
    tinyjambu_hkdf_state_p_t *pstate = (tinyjambu_hkdf_state_p_t *)state;
    tinyjambu_hmac_state_t hmac;
    tinyjambu_hmac_init(&hmac, salt, saltlen);
    tinyjambu_hmac_update(&hmac, key, keylen);
    tinyjambu_hmac_finalize(&hmac, salt, saltlen, pstate->prk);
    tinyjambu_hmac_free(&hmac);
    pstate->counter = 1;
    pstate->posn = TINYJAMBU_HMAC_SIZE;
}

int tinyjambu_hkdf_expand
    (tinyjambu_hkdf_state_t *state,
     const unsigned char *info, size_t infolen,
     unsigned char *out, size_t outlen)
{
    tinyjambu_hkdf_state_p_t *pstate = (tinyjambu_hkdf_state_p_t *)state;
    tinyjambu_hmac_state_t hmac;
    size_t len;

    /* Deal with left-over data from the last output block */
    len = TINYJAMBU_HMAC_SIZE - pstate->posn;
    if (len > outlen)
        len = outlen;
    memcpy(out, pstate->out + pstate->posn, len);
    out += len;
    outlen -= len;
    pstate->posn += len;

    /* Squeeze out the data one block at a time */
    while (outlen > 0) {
        /* Have we squeezed out too many blocks already? */
        if (pstate->counter == 0) {
            memset(out, 0, outlen); /* Zero the rest of the output data */
            return -1;
        }

        /* Squeeze out the next block of data */
        tinyjambu_hmac_init(&hmac, pstate->prk, sizeof(pstate->prk));
        if (pstate->counter != 1)
            tinyjambu_hmac_update(&hmac, pstate->out, sizeof(pstate->out));
        tinyjambu_hmac_update(&hmac, info, infolen);
        tinyjambu_hmac_update(&hmac, &(pstate->counter), 1);
        tinyjambu_hmac_finalize
            (&hmac, pstate->prk, sizeof(pstate->prk), pstate->out);
        tinyjambu_hmac_free(&hmac);
        ++(pstate->counter);

        /* Copy the data to the output buffer */
        len = TINYJAMBU_HMAC_SIZE;
        if (len > outlen)
            len = outlen;
        memcpy(out, pstate->out, len);
        pstate->posn = len;
        out += len;
        outlen -= len;
    }
    return 0;
}

void tinyjambu_hkdf_free(tinyjambu_hkdf_state_t *state)
{
    tinyjambu_clean(state, sizeof(tinyjambu_hkdf_state_t));
}
