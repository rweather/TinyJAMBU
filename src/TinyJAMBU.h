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

#ifndef TINYJAMBU_H
#define TINYJAMBU_H

#include <stddef.h>

/**
 * \file tinyjambu.h
 * \brief TinyJAMBU authenticated encryption algorithm.
 *
 * TinyJAMBU is a family of encryption algorithms that are built around a
 * lightweight 128-bit permutation.  There are three variants of TinyJAMBU
 * with different key sizes:
 *
 * \li TinyJAMBU-128 with a 128-bit key, a 96-bit nonce, and a 64-bit tag.
 * This is the primary member of the family.
 * \li TinyJAMBU-192 with a 192-bit key, a 96-bit nonce, and a 64-bit tag.
 * \li TinyJAMBU-256 with a 256-bit key, a 96-bit nonce, and a 64-bit tag.
 *
 * TinyJAMBU has one of the smallest RAM and flash memory footprints out of
 * the algorithms in the NIST Lightweight Cryptography Competition (LWC).
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Size of the key for TinyJAMBU-128.
 */
#define TINYJAMBU_128_KEY_SIZE 16

/**
 * \brief Size of the key for TinyJAMBU-192.
 */
#define TINYJAMBU_192_KEY_SIZE 24

/**
 * \brief Size of the key for TinyJAMBU-256.
 */
#define TINYJAMBU_256_KEY_SIZE 32

/**
 * \brief Size of the authentication tag for all TinyJAMBU variants.
 */
#define TINYJAMBU_TAG_SIZE 8

/**
 * \brief Size of the nonce for all TinyJAMBU variants.
 */
#define TINYJAMBU_NONCE_SIZE 12

/**
 * \brief Encrypts and authenticates a packet with TinyJAMBU-128.
 *
 * \param c Buffer to receive the output.
 * \param clen On exit, set to the length of the output which includes
 * the ciphertext and the 8 byte authentication tag.
 * \param m Buffer that contains the plaintext message to encrypt.
 * \param mlen Length of the plaintext message in bytes.
 * \param ad Buffer that contains associated data to authenticate
 * along with the packet but which does not need to be encrypted.
 * \param adlen Length of the associated data in bytes.
 * \param npub Points to the public nonce for the packet which must
 * be 12 bytes in length.
 * \param k Points to the 16 bytes of the key to use to encrypt the packet.
 *
 * \sa tinyjambu_128_aead_decrypt()
 */
void tinyjambu_128_aead_encrypt
    (unsigned char *c, size_t *clen,
     const unsigned char *m, size_t mlen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Decrypts and authenticates a packet with TinyJAMBU-128.
 *
 * \param m Buffer to receive the plaintext message on output.
 * \param mlen Receives the length of the plaintext message on output.
 * \param c Buffer that contains the ciphertext and authentication
 * tag to decrypt.
 * \param clen Length of the input data in bytes, which includes the
 * ciphertext and the 8 byte authentication tag.
 * \param ad Buffer that contains associated data to authenticate
 * along with the packet but which does not need to be encrypted.
 * \param adlen Length of the associated data in bytes.
 * \param npub Points to the public nonce for the packet which must
 * be 12 bytes in length.
 * \param k Points to the 16 bytes of the key to use to decrypt the packet.
 *
 * \return 0 on success, -1 if the authentication tag was incorrect,
 * or some other negative number if there was an error in the parameters.
 *
 * \sa tinyjambu_128_aead_encrypt()
 */
int tinyjambu_128_aead_decrypt
    (unsigned char *m, size_t *mlen,
     const unsigned char *c, size_t clen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Encrypts and authenticates a packet with TinyJAMBU-192.
 *
 * \param c Buffer to receive the output.
 * \param clen On exit, set to the length of the output which includes
 * the ciphertext and the 8 byte authentication tag.
 * \param m Buffer that contains the plaintext message to encrypt.
 * \param mlen Length of the plaintext message in bytes.
 * \param ad Buffer that contains associated data to authenticate
 * along with the packet but which does not need to be encrypted.
 * \param adlen Length of the associated data in bytes.
 * \param npub Points to the public nonce for the packet which must
 * be 12 bytes in length.
 * \param k Points to the 24 bytes of the key to use to encrypt the packet.
 *
 * \sa tinyjambu_192_aead_decrypt()
 */
void tinyjambu_192_aead_encrypt
    (unsigned char *c, size_t *clen,
     const unsigned char *m, size_t mlen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Decrypts and authenticates a packet with TinyJAMBU-192.
 *
 * \param m Buffer to receive the plaintext message on output.
 * \param mlen Receives the length of the plaintext message on output.
 * \param c Buffer that contains the ciphertext and authentication
 * tag to decrypt.
 * \param clen Length of the input data in bytes, which includes the
 * ciphertext and the 8 byte authentication tag.
 * \param ad Buffer that contains associated data to authenticate
 * along with the packet but which does not need to be encrypted.
 * \param adlen Length of the associated data in bytes.
 * \param npub Points to the public nonce for the packet which must
 * be 12 bytes in length.
 * \param k Points to the 24 bytes of the key to use to decrypt the packet.
 *
 * \return 0 on success, -1 if the authentication tag was incorrect,
 * or some other negative number if there was an error in the parameters.
 *
 * \sa tinyjambu_192_aead_encrypt()
 */
int tinyjambu_192_aead_decrypt
    (unsigned char *m, size_t *mlen,
     const unsigned char *c, size_t clen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Encrypts and authenticates a packet with TinyJAMBU-256.
 *
 * \param c Buffer to receive the output.
 * \param clen On exit, set to the length of the output which includes
 * the ciphertext and the 8 byte authentication tag.
 * \param m Buffer that contains the plaintext message to encrypt.
 * \param mlen Length of the plaintext message in bytes.
 * \param ad Buffer that contains associated data to authenticate
 * along with the packet but which does not need to be encrypted.
 * \param adlen Length of the associated data in bytes.
 * \param npub Points to the public nonce for the packet which must
 * be 12 bytes in length.
 * \param k Points to the 32 bytes of the key to use to encrypt the packet.
 *
 * \sa tinyjambu_256_aead_decrypt()
 */
void tinyjambu_256_aead_encrypt
    (unsigned char *c, size_t *clen,
     const unsigned char *m, size_t mlen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Decrypts and authenticates a packet with TinyJAMBU-256.
 *
 * \param m Buffer to receive the plaintext message on output.
 * \param mlen Receives the length of the plaintext message on output.
 * \param c Buffer that contains the ciphertext and authentication
 * tag to decrypt.
 * \param clen Length of the input data in bytes, which includes the
 * ciphertext and the 8 byte authentication tag.
 * \param ad Buffer that contains associated data to authenticate
 * along with the packet but which does not need to be encrypted.
 * \param adlen Length of the associated data in bytes.
 * \param npub Points to the public nonce for the packet which must
 * be 12 bytes in length.
 * \param k Points to the 32 bytes of the key to use to decrypt the packet.
 *
 * \return 0 on success, -1 if the authentication tag was incorrect,
 * or some other negative number if there was an error in the parameters.
 *
 * \sa tinyjambu_256_aead_encrypt()
 */
int tinyjambu_256_aead_decrypt
    (unsigned char *m, size_t *mlen,
     const unsigned char *c, size_t clen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Encrypts and authenticates a packet with TinyJAMBU-128 in SIV mode.
 *
 * \param c Buffer to receive the output.
 * \param clen On exit, set to the length of the output which includes
 * the ciphertext and the 8 byte authentication tag.
 * \param m Buffer that contains the plaintext message to encrypt.
 * \param mlen Length of the plaintext message in bytes.
 * \param ad Buffer that contains associated data to authenticate
 * along with the packet but which does not need to be encrypted.
 * \param adlen Length of the associated data in bytes.
 * \param npub Points to the public nonce for the packet which must
 * be 12 bytes in length.
 * \param k Points to the 16 bytes of the key to use to encrypt the packet.
 *
 * \sa tinyjambu_128_siv_decrypt()
 */
void tinyjambu_128_siv_encrypt
    (unsigned char *c, size_t *clen,
     const unsigned char *m, size_t mlen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Decrypts and authenticates a packet with TinyJAMBU-128 in SIV mode.
 *
 * \param m Buffer to receive the plaintext message on output.
 * \param mlen Receives the length of the plaintext message on output.
 * \param c Buffer that contains the ciphertext and authentication
 * tag to decrypt.
 * \param clen Length of the input data in bytes, which includes the
 * ciphertext and the 8 byte authentication tag.
 * \param ad Buffer that contains associated data to authenticate
 * along with the packet but which does not need to be encrypted.
 * \param adlen Length of the associated data in bytes.
 * \param npub Points to the public nonce for the packet which must
 * be 12 bytes in length.
 * \param k Points to the 16 bytes of the key to use to decrypt the packet.
 *
 * \return 0 on success, -1 if the authentication tag was incorrect,
 * or some other negative number if there was an error in the parameters.
 *
 * \sa tinyjambu_128_siv_encrypt()
 */
int tinyjambu_128_siv_decrypt
    (unsigned char *m, size_t *mlen,
     const unsigned char *c, size_t clen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Encrypts and authenticates a packet with TinyJAMBU-192 in SIV mode.
 *
 * \param c Buffer to receive the output.
 * \param clen On exit, set to the length of the output which includes
 * the ciphertext and the 8 byte authentication tag.
 * \param m Buffer that contains the plaintext message to encrypt.
 * \param mlen Length of the plaintext message in bytes.
 * \param ad Buffer that contains associated data to authenticate
 * along with the packet but which does not need to be encrypted.
 * \param adlen Length of the associated data in bytes.
 * \param npub Points to the public nonce for the packet which must
 * be 12 bytes in length.
 * \param k Points to the 24 bytes of the key to use to encrypt the packet.
 *
 * \sa tinyjambu_192_siv_decrypt()
 */
void tinyjambu_192_siv_encrypt
    (unsigned char *c, size_t *clen,
     const unsigned char *m, size_t mlen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Decrypts and authenticates a packet with TinyJAMBU-192 in SIV mode.
 *
 * \param m Buffer to receive the plaintext message on output.
 * \param mlen Receives the length of the plaintext message on output.
 * \param c Buffer that contains the ciphertext and authentication
 * tag to decrypt.
 * \param clen Length of the input data in bytes, which includes the
 * ciphertext and the 8 byte authentication tag.
 * \param ad Buffer that contains associated data to authenticate
 * along with the packet but which does not need to be encrypted.
 * \param adlen Length of the associated data in bytes.
 * \param npub Points to the public nonce for the packet which must
 * be 12 bytes in length.
 * \param k Points to the 24 bytes of the key to use to decrypt the packet.
 *
 * \return 0 on success, -1 if the authentication tag was incorrect,
 * or some other negative number if there was an error in the parameters.
 *
 * \sa tinyjambu_192_siv_encrypt()
 */
int tinyjambu_192_siv_decrypt
    (unsigned char *m, size_t *mlen,
     const unsigned char *c, size_t clen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Encrypts and authenticates a packet with TinyJAMBU-256 in SIV mode.
 *
 * \param c Buffer to receive the output.
 * \param clen On exit, set to the length of the output which includes
 * the ciphertext and the 8 byte authentication tag.
 * \param m Buffer that contains the plaintext message to encrypt.
 * \param mlen Length of the plaintext message in bytes.
 * \param ad Buffer that contains associated data to authenticate
 * along with the packet but which does not need to be encrypted.
 * \param adlen Length of the associated data in bytes.
 * \param npub Points to the public nonce for the packet which must
 * be 12 bytes in length.
 * \param k Points to the 32 bytes of the key to use to encrypt the packet.
 *
 * \sa tinyjambu_256_siv_decrypt()
 */
void tinyjambu_256_siv_encrypt
    (unsigned char *c, size_t *clen,
     const unsigned char *m, size_t mlen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Decrypts and authenticates a packet with TinyJAMBU-256 in SIV mode.
 *
 * \param m Buffer to receive the plaintext message on output.
 * \param mlen Receives the length of the plaintext message on output.
 * \param c Buffer that contains the ciphertext and authentication
 * tag to decrypt.
 * \param clen Length of the input data in bytes, which includes the
 * ciphertext and the 8 byte authentication tag.
 * \param ad Buffer that contains associated data to authenticate
 * along with the packet but which does not need to be encrypted.
 * \param adlen Length of the associated data in bytes.
 * \param npub Points to the public nonce for the packet which must
 * be 12 bytes in length.
 * \param k Points to the 32 bytes of the key to use to decrypt the packet.
 *
 * \return 0 on success, -1 if the authentication tag was incorrect,
 * or some other negative number if there was an error in the parameters.
 *
 * \sa tinyjambu_256_siv_encrypt()
 */
int tinyjambu_256_siv_decrypt
    (unsigned char *m, size_t *mlen,
     const unsigned char *c, size_t clen,
     const unsigned char *ad, size_t adlen,
     const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief State information for a TinyJAMBU-based PRNG.
 *
 * The PRNG can be used to expand a small amount of random entropy
 * into an arbitrary amount of output.  If the entropy source is not
 * uniform, then the PRNG will also help to distribute the input
 * entropy throughout the output in a uniform manner.
 */
typedef struct
{
    /** Private state for the PRNG.  Must be treated as opaque */
    unsigned long long s[64 / sizeof(unsigned long long)];

} tinyjambu_prng_state_t;

/**
 * \brief Prototype for a callback that seeds the TinyJAMBU PRNG.
 *
 * \param user_data User-supplied data pointer from tinyjambu_prng_init().
 * \param buf Points to the buffer to fill with random data.
 * \param size Number of bytes that are requested.
 * \param reseed 1 if this is a reseed operation, 0 for the initial
 * fetch of system rsandomness.
 *
 * \return The number of bytes that were returned.
 *
 * The callback should consult the system random number source
 * to obtain \a size bytes of new entropy.  It is allowed to return
 * less than \a size bytes but the callback should try very hard to
 * retrieve all requested bytes.  Especially if \a reseed is 0.
 */
typedef size_t (*tinyjambu_prng_callback_t)
    (void *user_data, unsigned char *buf, size_t size, int reseed);

/**
 * \brief Initializes a TinyJAMBU-based PRNG.
 *
 * \param state Points to the PRNG state to be initialized.
 * \param callback Callback for obtaining entropy from the system
 * random number source.
 * \param user_data USer data pointer to supply to \a callback.
 */
void tinyjambu_prng_init
    (tinyjambu_prng_state_t *state, tinyjambu_prng_callback_t callback,
     void *user_data);

/**
 * \brief Frees a TinyJAMBU-based PRNG and destroys all sensitive material.
 *
 * \param state Points to the PRNG state to be freed.
 */
void tinyjambu_prng_free(tinyjambu_prng_state_t *state);

/**
 * \brief Generates random bytes with a TinyJAMBU-based PRNG.
 *
 * \param state Points to the PRNG state to be used.
 * \param data Points to the data buffer to fill with random bytes.
 * \param size Number of bytes to be generated.
 *
 * This function generates data based on the random entropy that has
 * already been incorporated into the PRNG state.
 *
 * If it has been some time since the last call to tinyjambu_prng_generate(),
 * then it is recommended that tinyjambu_prng_reseed() be called before this
 * function to fetch fresh entropy from the system random number source.
 *
 * The PRNG will be rekeyed after the bytes are generated, or after every
 * 1K of generated data if \a size is greater than 1K.
 */
void tinyjambu_prng_generate
    (tinyjambu_prng_state_t *state, unsigned char *data, size_t size);

/**
 * \brief Feeds additional data into a TinyJAMBU-based PRNG.
 *
 * \param state Points to the PRNG state to be used.
 * \param data Points to the additional data to feed into the state.
 * \param size Number of bytes to feed into the state.
 *
 * This function can be used to add other sources of entropy to the
 * PRNG state.  Or to feed in serial numbers or other unique values
 * that will make the data generated by this device different from the
 * data generated by other devices.
 *
 * The PRNG is rekeyed after the data is fed in to improve forward
 * security.  If \a size is zero, then this function will just rekey.
 */
void tinyjambu_prng_feed
    (tinyjambu_prng_state_t *state, const unsigned char *data, size_t size);

/**
 * \brief Reseeds a TinyJAMBU-based PRNG from the system random number source.
 *
 * \param state Points to the PRNG state to be reseeded.
 */
void tinyjambu_prng_reseed(tinyjambu_prng_state_t *state);

/**
 * \brief Cleans a buffer that contains sensitive material.
 *
 * \param buf Points to the buffer to clear.
 * \param size Size of the buffer to clear in bytes.
 */
void tinyjambu_clean(void *buf, unsigned size);

#ifdef __cplusplus
}
#endif

#endif
