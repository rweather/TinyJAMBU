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

#ifndef TINYJAMBU_AEAD_COMMON_H
#define TINYJAMBU_AEAD_COMMON_H

#include "tinyjambu-backend.h"
#include "tinyjambu-util.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Set up the TinyJAMBU-128 state with the key and the nonce.
 *
 * \param state TinyJAMBU state to be permuted.
 * \param nonce Points to the 96-bit nonce.
 * \param domain Domain separator value for the nonce.
 */
void tinyjambu_setup_128
    (tinyjambu_128_state_t *state, const unsigned char *nonce,
     unsigned char domain);

/**
 * \brief Absorbs data into the TinyJAMBU-128 state.
 *
 * \param state TinyJAMBU state to be permuted.
 * \param data Points to data to be absorbed.
 * \param size Length of the data to be absorbed in bytes.
 * \param domain Domain separator value for the absorb operation.
 * \param round Number of TinyJAMBU rounds to perform.
 */
void tinyjambu_absorb_128
    (tinyjambu_128_state_t *state, const unsigned char *data,
     size_t size, unsigned char domain, unsigned rounds);

/**
 * \brief Generates the final authentication tag for TinyJAMBU-128.
 *
 * \param state TinyJAMBU state to be permuted.
 * \param tag Buffer to receive the tag.
 */
void tinyjambu_generate_tag_128
    (tinyjambu_128_state_t *state, unsigned char *tag);

/**
 * \brief Set up the TinyJAMBU-192 state with the key and the nonce.
 *
 * \param state TinyJAMBU state to be permuted.
 * \param nonce Points to the 96-bit nonce.
 * \param domain Domain separator value for the nonce.
 */
void tinyjambu_setup_192
    (tinyjambu_192_state_t *state, const unsigned char *nonce,
     unsigned char domain);

/**
 * \brief Absorbs data into the TinyJAMBU-192 state.
 *
 * \param state TinyJAMBU state to be permuted.
 * \param data Points to data to be absorbed.
 * \param size Length of the data to be absorbed in bytes.
 * \param domain Domain separator value for the absorb operation.
 * \param round Number of TinyJAMBU rounds to perform.
 */
void tinyjambu_absorb_192
    (tinyjambu_192_state_t *state, const unsigned char *data,
     size_t size, unsigned char domain, unsigned rounds);

/**
 * \brief Generates the final authentication tag for TinyJAMBU-192.
 *
 * \param state TinyJAMBU state to be permuted.
 * \param tag Buffer to receive the tag.
 */
void tinyjambu_generate_tag_192
    (tinyjambu_192_state_t *state, unsigned char *tag);

/**
 * \brief Set up the TinyJAMBU-256 state with the key and the nonce.
 *
 * \param state TinyJAMBU state to be permuted.
 * \param nonce Points to the 96-bit nonce.
 * \param domain Domain separator value for the nonce.
 */
void tinyjambu_setup_256
    (tinyjambu_256_state_t *state, const unsigned char *nonce,
     unsigned char domain);

/**
 * \brief Absorbs data into the TinyJAMBU-256 state.
 *
 * \param state TinyJAMBU state to be permuted.
 * \param data Points to data to be absorbed.
 * \param size Length of the data to be absorbed in bytes.
 * \param domain Domain separator value for the absorb operation.
 * \param round Number of TinyJAMBU rounds to perform.
 */
void tinyjambu_absorb_256
    (tinyjambu_256_state_t *state, const unsigned char *data,
     size_t size, unsigned char domain, unsigned rounds);

/**
 * \brief Generates the final authentication tag for TinyJAMBU-256.
 *
 * \param state TinyJAMBU state to be permuted.
 * \param tag Buffer to receive the tag.
 */
void tinyjambu_generate_tag_256
    (tinyjambu_256_state_t *state, unsigned char *tag);

#ifdef __cplusplus
}
#endif

#endif
