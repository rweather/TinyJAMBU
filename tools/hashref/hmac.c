
/* Implemented by Rhys Weatherley, placed into the public domain */

#include "api_auth.h"
#include "crypto_auth.h"
#include "crypto_hash.h"
#include <string.h>
#include <stdlib.h>

#define HMAC_BLOCK_SIZE 64

static void mask_key(unsigned char *block, unsigned char mask)
{
    unsigned int i;
    for (i = 0; i < HMAC_BLOCK_SIZE; ++i)
        block[i] ^= mask;
}

int crypto_auth(unsigned char *out, const unsigned char *in,
                unsigned long long inlen, const unsigned char *k)
{
    unsigned char outer[HMAC_BLOCK_SIZE + CRYPTO_BYTES];
    unsigned char *buf;

    // Format the inner data and hash it.
    buf = (unsigned char *)malloc(HMAC_BLOCK_SIZE + inlen);
    memcpy(buf, k, CRYPTO_KEYBYTES);
    memset(buf + CRYPTO_KEYBYTES, 0, HMAC_BLOCK_SIZE - CRYPTO_KEYBYTES);
    memcpy(buf + HMAC_BLOCK_SIZE, in, inlen);
    mask_key(buf, 0x36);
    crypto_hash(outer + HMAC_BLOCK_SIZE, buf, HMAC_BLOCK_SIZE + inlen);
    free(buf);

    // Format the outer data and hash it.
    memcpy(outer, k, CRYPTO_KEYBYTES);
    memset(outer + CRYPTO_KEYBYTES, 0, HMAC_BLOCK_SIZE - CRYPTO_KEYBYTES);
    mask_key(outer, 0x5C);
    crypto_hash(out, outer, HMAC_BLOCK_SIZE + CRYPTO_BYTES);

    return 0;
}

int crypto_auth_verify(const unsigned char *h, const unsigned char *in,
                       unsigned long long inlen, const unsigned char *k)
{
    unsigned char out[CRYPTO_BYTES];
    crypto_auth(out, in, inlen, k);
    if (!memcmp(out, h, CRYPTO_BYTES))
        return 0;
    return -1;
}
