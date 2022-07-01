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

#include "test-cipher.h"
#include "TinyJAMBU.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int test_exit_result = 0;

static void test_print_hex
    (const char *tag, const unsigned char *data, unsigned long long len)
{
    printf("%s =", tag);
    while (len > 0) {
        printf(" %02x", data[0]);
        ++data;
        --len;
    }
    printf("\n");
}

int test_memcmp
    (const unsigned char *actual, const unsigned char *expected,
     unsigned long long len)
{
    int cmp = memcmp(actual, expected, (size_t)len);
    if (cmp == 0)
        return 0;
    printf("\n");
    test_print_hex("actual  ", actual, len);
    test_print_hex("expected", expected, len);
    return cmp;
}

/*
 * The HKDF and PBKDF2 tests use TinyJAMBU-Hash to cross-check the actual
 * code against simplified versions.
 *
 * The problem is that if the hash is broken the tests will appear to
 * succeed because it is checking the broken hash against itself.
 *
 * This sanity check is used to make sure TinyJAMBU-Hash is basically
 * working before falsely reporting that the modes work.
 */
int hash_sanity_check(void)
{
    static unsigned char const hash_expected[TINYJAMBU_HASH_SIZE] = {
        0xcb, 0x58, 0x56, 0xd9, 0x57, 0x99, 0x8c, 0xae,
        0x7f, 0xcb, 0xed, 0x7d, 0x0d, 0xf3, 0xd6, 0x37,
        0xbb, 0x83, 0x13, 0xd7, 0xbd, 0xd7, 0xf3, 0x59,
        0xb1, 0x5a, 0x96, 0x77, 0xf6, 0xf2, 0xe5, 0x84
    };
    unsigned char hash[TINYJAMBU_HASH_SIZE];
    int ok = 1;
    printf("Hash Sanity Check ...");
    fflush(stdout);
    tinyjambu_hash(hash, (const unsigned char *)"abc", 3);
    if (test_memcmp(hash, hash_expected, sizeof(hash)) != 0)
        ok = 0;
    if (!ok)
        printf("failed\n");
    else
        printf("ok\n");
    return ok;
}
