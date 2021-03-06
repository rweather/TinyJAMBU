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
#include "backend/tinyjambu-backend.h"
#include "test-cipher.h"
#include <stdio.h>
#include <string.h>

/* Test vectors for TinyJAMBU generated with the reference code */
static uint32_t const tinyjambu_input[] = {
    0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c
};
static uint32_t const tinyjambu_key_1[] = {
    0x33221100, 0x77665544, 0xbbaa9988, 0xffeeddcc
};
static uint32_t const tinyjambu_output_1[] = {
    0xd9025b75, 0xdea7c711, 0xc42bfe5c, 0x361e5016
};
static uint32_t const tinyjambu_key_2[] = {
    0x33221100, 0x77665544, 0xbbaa9988, 0xffeeddcc,
    0x9687b4a5, 0xd2c3f0e1, 0x1e0f3c2d, 0x5a4b7869
};
static uint32_t const tinyjambu_output_2[] = {
    0xf066f253, 0xa8cf13ed, 0xd46f2eb9, 0xbd4c5e4a
};
static uint32_t const tinyjambu_key_3[] = {
    0x33221100, 0x77665544, 0xbbaa9988, 0xffeeddcc,
    0x9687b4a5, 0xd2c3f0e1
};
static uint32_t const tinyjambu_output_3[] = {
    0xeb03d4da, 0x14894342, 0xb0d7ba4d, 0x025b53a6
};

static void input_to_state(uint32_t *state, const uint32_t *input)
{
#if defined(TINYJAMBU_BACKEND_WORD64)
    uint64_t *t = (uint64_t *)state;
    t[0] = input[0] | (((uint64_t)(input[1])) << 32);
    t[1] = input[2] | (((uint64_t)(input[3])) << 32);
#else
    state[0] = input[0];
    state[1] = input[1];
    state[2] = input[2];
    state[3] = input[3];
#endif
}

static void state_to_output(uint32_t *state)
{
#if defined(TINYJAMBU_BACKEND_WORD64)
    uint64_t *t = (uint64_t *)state;
    uint32_t s0 = (uint32_t)(t[0]);
    uint32_t s1 = (uint32_t)(t[0] >> 32);
    uint32_t s2 = (uint32_t)(t[1]);
    uint32_t s3 = (uint32_t)(t[1] >> 32);
    state[0] = s0;
    state[1] = s1;
    state[2] = s2;
    state[3] = s3;
#else
    (void)state;
#endif
}

static void invert_key(uint32_t *out, const uint32_t *in, unsigned count)
{
    while (count > 0) {
        *out++ = ~(*in++);
        --count;
    }
}

void test_tinyjambu_permutation(void)
{
    tinyjambu_128_state_t state128;
    tinyjambu_192_state_t state192;
    tinyjambu_256_state_t state256;

    printf("TinyJAMBU:\n");

    printf("    Test Vector 1 ... ");
    fflush(stdout);
    input_to_state(state128.s, tinyjambu_input);
    invert_key(state128.k, tinyjambu_key_1, 4);
    tinyjambu_permutation_128(&state128, TINYJAMBU_ROUNDS(1024));
    state_to_output(state128.s);
    if (!test_memcmp((const unsigned char *)&state128,
                     (const unsigned char *)tinyjambu_output_1,
                     sizeof(tinyjambu_output_1))) {
        printf("ok\n");
    } else {
        printf("failed\n");
        test_exit_result = 1;
    }

    printf("    Test Vector 2 ... ");
    fflush(stdout);
    input_to_state(state256.s, tinyjambu_input);
    invert_key(state256.k, tinyjambu_key_2, 8);
    tinyjambu_permutation_256(&state256, TINYJAMBU_ROUNDS(1280));
    state_to_output(state256.s);
    if (!test_memcmp((const unsigned char *)&state256,
                     (const unsigned char *)tinyjambu_output_2,
                     sizeof(tinyjambu_output_2))) {
        printf("ok\n");
    } else {
        printf("failed\n");
        test_exit_result = 1;
    }

    printf("    Test Vector 3 ... ");
    fflush(stdout);
    input_to_state(state192.s, tinyjambu_input);
    invert_key(state192.k, tinyjambu_key_3, 6);
    tinyjambu_permutation_192(&state192, TINYJAMBU_ROUNDS(1152));
    state_to_output(state192.s);
    if (!test_memcmp((const unsigned char *)&state192,
                     (const unsigned char *)tinyjambu_output_3,
                     sizeof(tinyjambu_output_3))) {
        printf("ok\n");
    } else {
        printf("failed\n");
        test_exit_result = 1;
    }

    printf("\n");
}

int main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;

    test_tinyjambu_permutation();

    return test_exit_result;
}
