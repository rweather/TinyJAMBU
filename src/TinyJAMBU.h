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
 * \brief Size of the hash output for TinyJAMBU-Hash.
 */
#define TINYJAMBU_HASH_SIZE 32

/**
 * \brief Default size of the output for TinyJAMBU-HMAC.
 */
#define TINYJAMBU_HMAC_SIZE TINYJAMBU_HASH_SIZE

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
 * \brief State information for TinyJAMBU-Hash.
 */
typedef struct
{
    /** Private state for the hash.  Must be treated as opaque */
    unsigned long long s[56 / sizeof(unsigned long long)];

} tinyjambu_hash_state_t;

/**
 * \brief Hashes a block of input data with TinyJAMBU-Hash.
 *
 * \param out Buffer to receive the hash output which must be at least
 * TINYJAMBU_HASH_SIZE bytes in length.
 * \param in Points to the input data to be hashed.
 * \param inlen Length of the input data in bytes.
 *
 * \sa tinyjambu_hash_init(), tinyjambu_hash_update(), tinyjambu_hash_finalize()
 */
void tinyjambu_hash(unsigned char *out, const unsigned char *in, size_t inlen);

/**
 * \brief Initializes the state for an TinyJAMBU-Hash hashing operation.
 *
 * \param state Hash state to be initialized.
 *
 * \sa tinyjambu_hash_update(), tinyjambu_hash_finalize(), tinyjambu_hash()
 */
void tinyjambu_hash_init(tinyjambu_hash_state_t *state);

/**
 * \brief Updates an TinyJAMBU-Hash state with more input data.
 *
 * \param state Hash state to be updated.
 * \param in Points to the input data to be incorporated into the state.
 * \param inlen Length of the input data to be incorporated into the state.
 *
 * \sa tinyjambu_hash_init(), tinyjambu_hash_finalize()
 */
void tinyjambu_hash_update
    (tinyjambu_hash_state_t *state, const unsigned char *in, size_t inlen);

/**
 * \brief Returns the final hash value from an TinyJAMBU-Hash hashing operation.
 *
 * \param state Hash state to be finalized.
 * \param out Points to the output buffer to receive the hash value.
 * Must be at least TINYJAMBU_HASH_SIZE bytes in length.
 *
 * \sa tinyjambu_hash_init(), tinyjambu_hash_update()
 */
void tinyjambu_hash_finalize(tinyjambu_hash_state_t *state, unsigned char *out);

/**
 * \brief State information for the TINYJAMBU-HMAC incremental mode.
 */
typedef struct
{
    tinyjambu_hash_state_t hash;    /**< Internal TINYJAMBU-Hash state */

} tinyjambu_hmac_state_t;

/**
 * \brief Computes a HMAC value using TINYJAMBU-HASH.
 *
 * \param out Buffer to receive the output HMAC value; must be at least
 * TINYJAMBU_HMAC_SIZE bytes in length.
 * \param key Points to the key.
 * \param keylen Number of bytes in the key.
 * \param in Points to the data to authenticate.
 * \param inlen Number of bytes of data to authenticate.
 */
void tinyjambu_hmac
    (unsigned char *out,
     const unsigned char *key, size_t keylen,
     const unsigned char *in, size_t inlen);

/**
 * \brief Initializes an incremental HMAC state using TINYJAMBU-HASH.
 *
 * \param state Points to the state to be initialized.
 * \param key Points to the key.
 * \param keylen Number of bytes in the key.
 *
 * The \a key needs to be preserved until the tinyjambu_hmac_finalize() call
 * to provide the outer HMAC hashing key.
 *
 * \sa tinyjambu_hmac_update(), tinyjambu_hmac_finalize()
 */
void tinyjambu_hmac_init
    (tinyjambu_hmac_state_t *state, const unsigned char *key, size_t keylen);

/**
 * \brief Updates an incremental TINYJAMBU-HMAC state with more input data.
 *
 * \param state HMAC state to be updated.
 * \param in Points to the input data to be incorporated into the state.
 * \param inlen Length of the input data to be incorporated into the state.
 *
 * \sa tinyjambu_hmac_init(), tinyjambu_hmac_finalize()
 */
void tinyjambu_hmac_update
    (tinyjambu_hmac_state_t *state, const unsigned char *in, size_t inlen);

/**
 * \brief Finalizes an incremental TINYJAMBU-HMAC state.
 *
 * \param state HMAC state to squeeze the output data from.
 * \param key Points to the key.
 * \param keylen Number of bytes in the key.
 * \param out Points to the output buffer to receive the HMAC value;
 * must be at least TINYJAMBU_HMAC_SIZE bytes in length.
 *
 * \sa tinyjambu_hmac_init(), tinyjambu_hmac_update()
 */
void tinyjambu_hmac_finalize
    (tinyjambu_hmac_state_t *state, const unsigned char *key, size_t keylen,
     unsigned char *out);

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
    unsigned long long s[96 / sizeof(unsigned long long)];

} tinyjambu_prng_state_t;

/**
 * \brief Prototype for a callback that seeds the TinyJAMBU PRNG.
 *
 * \param user_data User-supplied data pointer from tinyjambu_prng_init().
 * \param buf Points to the buffer to fill with random data.
 * \param size Number of bytes that are requested.
 *
 * \return The number of bytes that were returned, or zero if the
 * system random number source has failed.
 *
 * The callback should consult the system random number source
 * to obtain \a size bytes of new entropy.  It is allowed to return
 * less than \a size bytes but the callback should try very hard to
 * retrieve all requested bytes.
 */
typedef size_t (*tinyjambu_prng_callback_t)
    (void *user_data, unsigned char *buf, size_t size);

/**
 * \brief Initializes a TinyJAMBU-based PRNG and seeds it from the
 * default system random number source.
 *
 * \param state Points to the PRNG state to be initialized.
 * \param custom Points to a customization string to make this
 * instantiation of the PRNG unique.
 * \param custom_len Length of the customization string.
 *
 * \return Non-zero if enough data was obtained from the system random
 * number source to seed the PRNG; or zero otherwise.
 */
int tinyjambu_prng_init
    (tinyjambu_prng_state_t *state,
     const unsigned char *custom, size_t custom_len);

/**
 * \brief Initializes a TinyJAMBU-based PRNG with a user-supplied callback
 * to access the system random number source.
 *
 * \param state Points to the PRNG state to be initialized.
 * \param callback Callback for obtaining entropy from the system
 * random number source.
 * \param user_data User data pointer to supply to \a callback.
 * \param custom Points to a customization string to make this
 * instantiation of the PRNG unique.
 * \param custom_len Length of the customization string.
 *
 * \return Non-zero if enough data was obtained from the system random
 * number source to seed the PRNG; or zero otherwise.
 *
 * If \a callback is NULL, then a default source will be used.
 */
int tinyjambu_prng_init_user
    (tinyjambu_prng_state_t *state, tinyjambu_prng_callback_t callback,
     void *user_data, const unsigned char *custom, size_t custom_len);

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
 * This function will automatically reseed after every 1K of output.
 *
 * It is recommended that tinyjambu_prng_reseed() be called regularly by
 * the application at other times when random numbers are not needed.
 * This will ensure that fresh entropy is mixed in regularly to improve
 * forward security.
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
 *
 * \return Non-zero if it was possible to obtain all requested seed
 * material from the system random number source, or zero if the request
 * could not be accomodated.
 */
int tinyjambu_prng_reseed(tinyjambu_prng_state_t *state);

/**
 * \brief Sets the reseeding limit for a TinyJAMBU-based PRNG.
 *
 * \param state Points to the PRNG state to be updated.
 * \param limit Number of bytes to generate, after which the PRNG
 * will be automatically reseeded.  Maximum of 1M, default is 1K.
 *
 * The \a limit will be rounded up to the next block size if it is not a
 * multiple of 32.  Setting \a limit to zero will force the PRNG to be
 * reseeded every time tinyjambu_prng_generate() is called.
 */
void tinyjambu_prng_set_reseed_limit
    (tinyjambu_prng_state_t *state, size_t limit);

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
