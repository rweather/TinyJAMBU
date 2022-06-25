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

/**
 * \file tinyjambu-backend.h
 * \brief Backend implementation of the TinyJAMBU permutation.
 */

#ifdef __cplusplus
extern "C" {
#endif

/* Select the default back end to use for the TinyJAMBU permutation,
 * and any properties we can use to optimize use of the permutation. */

#if defined(TINYJAMBU_FORCE_C32)

/* Force the use of the "c32" backend for testing purposes */
#define TINYJAMBU_BACKEND_C32 1
#define TINYJAMBU_BACKEND_WORD32 1

#elif defined(TINYJAMBU_FORCE_C64)

/* Force the use of the "c64" backend for testing purposes */
#define TINYJAMBU_BACKEND_C64 1
#define TINYJAMBU_BACKEND_WORD64 1

#elif defined(LW_UTIL_CPU_IS_64BIT)

/* C backend for 64-bit systems */
#define TINYJAMBU_BACKEND_C64 1
#define TINYJAMBU_BACKEND_WORD64 1

#else

/* C backend for 32-bit systems */
#define TINYJAMBU_BACKEND_C32 1
#define TINYJAMBU_BACKEND_WORD32 1

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

#ifdef __cplusplus
}
#endif

#endif
