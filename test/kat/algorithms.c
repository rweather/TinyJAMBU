/*
 * Copyright (C) 2021 Southern Storm Software, Pty Ltd.
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

#include "algorithms.h"
#include "TinyJAMBU.h"
#include <string.h>
#include <stdio.h>

aead_cipher_t const tinyjambu128_cipher = {
    "TinyJAMBU-128",
    TINYJAMBU_128_KEY_SIZE,
    TINYJAMBU_NONCE_SIZE,
    TINYJAMBU_TAG_SIZE,
    AEAD_FLAG_LITTLE_ENDIAN,
    tinyjambu_128_aead_encrypt,
    tinyjambu_128_aead_decrypt,
    0, 0, 0, 0, 0, 0, 0, 0, 0
};

aead_cipher_t const tinyjambu192_cipher = {
    "TinyJAMBU-192",
    TINYJAMBU_192_KEY_SIZE,
    TINYJAMBU_NONCE_SIZE,
    TINYJAMBU_TAG_SIZE,
    AEAD_FLAG_LITTLE_ENDIAN,
    tinyjambu_192_aead_encrypt,
    tinyjambu_192_aead_decrypt,
    0, 0, 0, 0, 0, 0, 0, 0, 0
};

aead_cipher_t const tinyjambu256_cipher = {
    "TinyJAMBU-256",
    TINYJAMBU_256_KEY_SIZE,
    TINYJAMBU_NONCE_SIZE,
    TINYJAMBU_TAG_SIZE,
    AEAD_FLAG_LITTLE_ENDIAN,
    tinyjambu_256_aead_encrypt,
    tinyjambu_256_aead_decrypt,
    0, 0, 0, 0, 0, 0, 0, 0, 0
};

/* List of all AEAD ciphers that we can run KAT tests for */
static const aead_cipher_t *const ciphers[] = {
    &tinyjambu128_cipher,
    &tinyjambu192_cipher,
    &tinyjambu256_cipher,
    0
};

/* List of all hash algorithms that we can run KAT tests for */
static const aead_hash_algorithm_t *const hashes[] = {
    0
};

/* List of all authentication algorithms that we can run KAT tests for */
static const aead_auth_algorithm_t *const auths[] = {
    0
};

const aead_cipher_t *find_cipher(const char *name)
{
    int index;
    for (index = 0; ciphers[index] != 0; ++index) {
        if (!strcmp(ciphers[index]->name, name))
            return ciphers[index];
    }
    return 0;
}

const aead_hash_algorithm_t *find_hash_algorithm(const char *name)
{
    int index;
    for (index = 0; hashes[index] != 0; ++index) {
        if (!strcmp(hashes[index]->name, name))
            return hashes[index];
    }
    return 0;
}

const aead_auth_algorithm_t *find_auth_algorithm(const char *name)
{
    int index;
    for (index = 0; auths[index] != 0; ++index) {
        if (!strcmp(auths[index]->name, name))
            return auths[index];
    }
    return 0;
}

static void print_cipher_details(const aead_cipher_t *cipher)
{
    printf("%-30s %8u   %8u   %8u\n",
           cipher->name,
           cipher->key_len * 8,
           cipher->nonce_len * 8,
           cipher->tag_len * 8);
}

static void print_hash_details(const aead_hash_algorithm_t *hash)
{
    printf("%-30s %8u\n", hash->name, hash->hash_len * 8);
}

static void print_auth_details(const aead_auth_algorithm_t *auth)
{
    printf("%-30s %8u   %8u\n",
           auth->name, auth->key_len * 8, auth->tag_len * 8);
}

void print_algorithm_names(void)
{
    int index;
    printf("\nCipher                           Key Bits");
    printf("  Nonce Bits  Tag Bits\n");
    for (index = 0; ciphers[index] != 0; ++index)
        print_cipher_details(ciphers[index]);
    printf("\nHash Algorithm                   Hash Bits\n");
    for (index = 0; hashes[index] != 0; ++index)
        print_hash_details(hashes[index]);
    printf("\nAuthentication Algorithm         Key Bits");
    printf("   Tag Bits\n");
    for (index = 0; auths[index] != 0; ++index)
        print_auth_details(auths[index]);
}
