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

#ifndef TINYJAMBU_BACKEND_H
#define TINYJAMBU_BACKEND_H

#include "tinyjambu-util.h"
#include "tinyjambu-backend-select.h"

/**
 * \file tinyjambu-backend.h
 * \brief Backend implementation of the TinyJAMBU permutation.
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief TinyJAMBU permutation state.
 */
typedef struct
{
#if defined(TINYJAMBU_BACKEND_WORD64)
    uint64_t t[2];      /**< State as 64-bit words */
#else
    uint32_t s[4];      /**< State as 32-bit words */
#endif
} tinyjambu_state_t;

/**
 * \typedef tinyjambu_key_word_t
 * \brief Size of a word in the key schedule (32 or 64 bits).
 */
#if defined(TINYJAMBU_BACKEND_WORD64)
typedef uint64_t tinyjambu_key_word_t;
#else
typedef uint32_t tinyjambu_key_word_t;
#endif

/**
 * \def tinyjambu_key_load_even(ptr)
 * \brief Loads an even key word for TinyJAMBU.
 *
 * \param ptr Points to the 4 bytes of the key word in little-endian order.
 * \return The key word.
 */
/**
 * \def tinyjambu_key_load_odd(ptr)
 * \brief Loads an odd key word for TinyJAMBU.
 *
 * \param ptr Points to the 4 bytes of the key word in little-endian order.
 * \return The key word.
 */
#if defined(TINYJAMBU_BACKEND_WORD64)
#define tinyjambu_key_load_even(ptr) \
    ((tinyjambu_key_word_t)(~(le_load_word32((ptr)))))
#define tinyjambu_key_load_odd(ptr) \
    (((tinyjambu_key_word_t)(~(le_load_word32((ptr))))) << 32)
#else
#define tinyjambu_key_load_even(ptr) \
    ((tinyjambu_key_word_t)(~(le_load_word32((ptr)))))
#define tinyjambu_key_load_odd(ptr) \
    ((tinyjambu_key_word_t)(~(le_load_word32((ptr)))))
#endif

/**
 * \def tinyjambu_init_state(state)
 * \brief Initializes a TinyJAMBU state to zero.
 *
 * \param state TinyJAMBU state to be initialized.
 */
/**
 * \def tinyjambu_add_domain(state, domain)
 * \brief Adds a domain separation value to the TinyJAMBU state.
 *
 * \param state TinyJAMBU state to be updated.
 * \param domain Domain separation value to add.
 */
/**
 * \def tinyjambu_absorb(state, word)
 * \brief Absorbs a 32-bit word into the TinyJAMBU state.
 *
 * \param state TinyJAMBU state to be updated.
 * \param word Word value to absorb.
 */
/**
 * \def tinyjambu_squeeze(state)
 * \brief Squeezes a 32-bit word from the TinyJAMBU state.
 *
 * \param state TinyJAMBU state to squeeze from.
 * \return Word value that was squeezed out.
 */
#if defined(TINYJAMBU_BACKEND_WORD64)
#define tinyjambu_init_state(state) \
    ((state)->t[0] = (state)->t[1] = 0)
#define tinyjambu_add_domain(state, domain) \
    ((state)->t[0] ^= ((uint64_t)(domain)) << 32)
#define tinyjambu_absorb(state, word) \
    ((state)->t[1] ^= ((uint64_t)(word)) << 32)
#define tinyjambu_squeeze(state) ((uint32_t)((state)->t[1]))
#else
#define tinyjambu_init_state(state) \
    ((state)->s[0] = (state)->s[1] = (state)->s[2] = (state)->s[3] = 0)
#define tinyjambu_add_domain(state, domain) \
    ((state)->s[1] ^= (domain))
#define tinyjambu_absorb(state, word) \
    ((state)->s[3] ^= (word))
#define tinyjambu_squeeze(state) ((state)->s[2])
#endif

/**
 * \brief Converts a number of steps into a number of rounds, where each
 * round consists of 128 steps.
 *
 * \param steps The number of steps to perform; 384, 1024, 1152, or 1280.
 *
 * \return The number of rounds corresponding to \a steps.
 */
#define TINYJAMBU_ROUNDS(steps) ((steps) / 128)

/**
 * \brief Perform the TinyJAMBU-128 permutation.
 *
 * \param state TinyJAMBU-128 state to be permuted.
 * \param key Points to the 4 key words.
 * \param rounds The number of rounds to perform.
 *
 * \note The words of the \a key must be the inverted version of the
 * actual key so that we can replace NAND with AND operations when
 * evaluating the permutation.
 */
void tinyjambu_permutation_128
    (tinyjambu_state_t *state, const tinyjambu_key_word_t *key,
     unsigned rounds);

/**
 * \brief Perform the TinyJAMBU-192 permutation.
 *
 * \param state TinyJAMBU-192 state to be permuted.
 * \param key Points to the 6 key words.
 * \param rounds The number of rounds to perform.
 *
 * \note The words of the \a key must be the inverted version of the
 * actual key so that we can replace NAND with AND operations when
 * evaluating the permutation.
 */
void tinyjambu_permutation_192
    (tinyjambu_state_t *state, const tinyjambu_key_word_t *key,
     unsigned rounds);

/**
 * \brief Perform the TinyJAMBU-256 permutation.
 *
 * \param state TinyJAMBU-256 state to be permuted.
 * \param key Points to the 8 key words.
 * \param rounds The number of rounds to perform.
 *
 * \note The words of the \a key must be the inverted version of the
 * actual key so that we can replace NAND with AND operations when
 * evaluating the permutation.
 */
void tinyjambu_permutation_256
    (tinyjambu_state_t *state, const tinyjambu_key_word_t *key,
     unsigned rounds);

/* Note: The last line should contain ~(t2 & t3) according to the
 * specification but we can avoid the NOT by inverting the words
 * of the key ahead of time. */
#define tinyjambu_steps_32(s0, s1, s2, s3, kword) \
    do { \
        t1 = (s1 >> 15) | (s2 << 17); \
        t2 = (s2 >> 6)  | (s3 << 26); \
        t3 = (s2 >> 21) | (s3 << 11); \
        t4 = (s2 >> 27) | (s3 << 5); \
        s0 ^= t1 ^ (t2 & t3) ^ t4 ^ kword; \
    } while (0)

/* Perform 64 steps of the TinyJAMBU permutation on 64-bit platforms */
#define tinyjambu_steps_64(s0, s2, kword0, kword1) \
    do { \
        t1 = (s0 >> 47) | (s2 << 17); \
        t2 = (s2 >> 6); \
        t3 = (s2 >> 21); \
        t4 = (s2 >> 27); \
        s0 ^= t1 ^ (uint32_t)((t2 & t3) ^ t4 ^ kword0); \
        t2 |= (s0 << 58); \
        t3 |= (s0 << 43); \
        t4 |= (s0 << 37); \
        s0 ^= ((t2 & t3) ^ t4 ^ kword1) & 0xFFFFFFFF00000000ULL; \
    } while (0)

#ifdef __cplusplus
}
#endif

#endif
