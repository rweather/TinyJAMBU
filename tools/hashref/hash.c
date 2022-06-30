
/* Implemented by Rhys Weatherley, placed into the public domain */

#include "crypto_hash.h"
#include "api.h"
#include <string.h>

// NOTE: This implementation assumes that the machine is little-endian.

#define NROUNDS (128*10*2) // 2560

extern void state_update(unsigned int *state, const unsigned char *key, unsigned int number_of_steps);

// Encrypts a block of input and then XOR's the input with the output.
// Implements: L' = Encrypt(K, L ^ domain) ^ L ^ domain
static void encrypt_block_and_xor
    (unsigned char out[16], const unsigned char key[32],
     const unsigned char in[16], unsigned int domain)
{
    unsigned int state[4];
    unsigned i;

    memcpy(state, in, 16);
    state[0] ^= domain;

    state_update(state, key, NROUNDS);

    for (i = 0; i < 16; ++i) {
        out[i] = in[i] ^ ((const unsigned char *)state)[i];
    }
    out[0] ^= domain;
}

// Compression function; domain is 2 for the last block and 0 for other blocks.
static void compress
    (unsigned char L[16], unsigned char R[16], const unsigned char M[16],
     unsigned char domain)
{
    unsigned char K[32];
    unsigned char Lprime[16];

    // K = R || M
    memcpy(K, R, 16);
    memcpy(K + 16, M, 16);

    // L' = Encrypt(K, L) ^ L
    encrypt_block_and_xor(Lprime, K, L, domain);

    // R = Encrypt(K, L ^ 1) ^ L ^ 1
    encrypt_block_and_xor(R, K, L, domain ^ 1);

    // L = L'
    memcpy(L, Lprime, 16);
}

int crypto_hash(unsigned char *out, const unsigned char *in,
                unsigned long long inlen)
{
    unsigned char L[16] = {0};
    unsigned char R[16] = {0};
    unsigned char M[16];
    unsigned len;

    // Process as many full 128-bit blocks as possible.
    while (inlen >= 16) {
        compress(L, R, in, 0);
        in += 16;
        inlen -= 16;
    }

    // Pad and process the last block.
    len = (unsigned)inlen;
    memcpy(M, in, len);
    M[len] = 1;
    memset(M + len + 1, 0, 16 - (len + 1));
    compress(L, R, M, 2);

    // Construct the final hash value and return.
    memcpy(out, L, 16);
    memcpy(out + 16, R, 16);
    return 0;
}
