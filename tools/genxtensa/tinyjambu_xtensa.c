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

/*
 * This program is used to generate the assembly code version of the
 * TinyJAMBU permutation for Xtensa microprocessors.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "copyright.h"

static void function_header(const char *name)
{
    /* The default linker scripts for Arduino ESP8266 platforms seem to put
     * assembly code .text sections into iram1 by default instead irom0.
     * This can cause a linker error due to insufficient RAM.  Move the
     * text segment back to irom0 where it belongs. */
    printf("#ifdef ESP8266\n");
    printf("\t.section .irom0.text,\"ax\",@progbits\n");
    printf("#else\n");
    printf("\t.section .text.%s,\"ax\",@progbits\n", name);
    printf("#endif\n");
    printf("\t.align\t4\n");
    printf("\t.literal_position\n");
    printf("\t.global\t%s\n", name);
    printf("\t.type\t%s, @function\n", name);
    printf("%s:\n", name);
}

static void function_footer(const char *name)
{
    printf("\t.size\t%s, .-%s\n", name, name);
}

/* List of all registers that we can work with */
typedef struct
{
    const char *s0;
    const char *s1;
    const char *s2;
    const char *s3;
    const char *k[8];
    const char *t0;
    const char *t1;

} reg_names;

/* Perform 32 steps of the TinyJAMBU permutation */
static void tinyjambu_steps_32
    (const reg_names *regs, const char *s0, const char *s1,
     const char *s2, const char *s3, const char *kreg, int offset)
{
    /*
     * t1 = (s1 >> 15) | (s2 << 17);
     * t2 = (s2 >> 6)  | (s3 << 26);
     * t3 = (s2 >> 21) | (s3 << 11);
     * t4 = (s2 >> 27) | (s3 << 5);
     * s0 ^= t1 ^ (~(t2 & t3)) ^ t4 ^ kreg;
     */

    /* We can use Xtensa's "shift right combined" (SRC) instruction
     * to compute the values of t1, t2, t3, and t4 */

    /* t1 = (s1 >> 15) | (s2 << 17); */
    printf("\tssai\t15\n");
    printf("\tsrc\t%s, %s, %s\n", regs->t0, s2, s1);

    /* t4 = (s2 >> 27) | (s3 << 5); */
    printf("\tssai\t27\n");
    printf("\tsrc\t%s, %s, %s\n", regs->t1, s3, s2);

    /* s0 ^= t1 */
    printf("\txor\t%s, %s, %s\n", s0, s0, regs->t0);

    /* s0 ^= t4 */
    printf("\txor\t%s, %s, %s\n", s0, s0, regs->t1);

    /* t2 = (s2 >> 6) | (s3 << 26); */
    printf("\tssai\t6\n");
    printf("\tsrc\t%s, %s, %s\n", regs->t0, s3, s2);

    /* t3 = (s2 >> 21) | (s3 << 11); */
    printf("\tssai\t21\n");
    printf("\tsrc\t%s, %s, %s\n", regs->t1, s3, s2);

    /* s0 ^= ~(t2 & t3); */
    /* Note: We assume that the key is inverted so we can avoid the NOT */
    printf("\tand\t%s, %s, %s\n", regs->t0, regs->t0, regs->t1);
    printf("\txor\t%s, %s, %s\n", s0, s0, regs->t0);

    /* s0 ^= kreg */
    if (kreg) {
        printf("\txor\t%s, %s, %s\n", s0, s0, kreg);
    } else {
        printf("\tl32i.n\t%s, a2, %d\n", regs->t1, 16 + offset);
        printf("\txor\t%s, %s, %s\n", s0, s0, regs->t1);
    }
}

/* Generate the body of the TinyJAMBU permutation function */
static void gen_permute(int variant)
{
    /*
     * a0 holds the return address pointer (link register).
     * a1 holds the stack pointer.
     * a2 holds the pointer to the TinyJAMBU state on entry and exit.
     * a3 holds the number of rounds to perform.
     *
     * a2-a15 can be used freely as scratch registers without saving if the
     * Xtensa has the Windowed Register Option configured.
     *
     * a2-a11 can be used freely as scratch registers without saving if the
     * Xtensa does not have the Windowed Register Option configured.
     * a12-a15 must be callee-saved in this case.
     */
    reg_names regs;
    int inner, inner_rounds, key_words;
    regs.s0 = "a4";
    regs.s1 = "a5";
    regs.s2 = "a6";
    regs.s3 = "a7";
    regs.k[0] = "a8";
    regs.k[1] = "a9";
    regs.k[2] = "a10";
    regs.k[3] = "a11";
    if (variant == 128) {
        regs.k[4] = 0;
        regs.k[5] = 0;
        regs.t0 = "a12";
        regs.t1 = "a13";
    } else if (variant == 192) {
        regs.k[4] = "a12";
        regs.k[5] = "a13";
        regs.t0 = "a14";
        regs.t1 = "a15";
    } else {
        regs.k[4] = "a12";
        regs.k[5] = "a13";
        regs.t0 = "a14";
        regs.t1 = "a15";
    }
    regs.k[6] = 0;
    regs.k[7] = 0;

    /* Establish the stack frame.  Note: The instruction set reference
     * indicates that the stack pointer must be aligned on a 16-byte
     * boundary, but ESP32 seems to require multiples of 32 instead,
     * so that's what we do. */
    printf("#ifdef __XTENSA_WINDOWED_ABI__\n");
    printf("\tentry\tsp, 32\n");
    printf("#else\n");
    printf("\taddi\tsp, sp, -32\n");
    printf("\ts32i.n\ta12, sp, 0\n");
    printf("\ts32i.n\ta13, sp, 4\n");
    if (variant != 128) {
        printf("\ts32i.n\ta14, sp, 8\n");
        printf("\ts32i.n\ta15, sp, 12\n");
    }
    printf("#endif\n");

    /* Load all words of the state and some words of the key into registers */
    printf("\tl32i.n\t%s, a2, %d\n", regs.s0, 0);
    printf("\tl32i.n\t%s, a2, %d\n", regs.s1, 4);
    printf("\tl32i.n\t%s, a2, %d\n", regs.s2, 8);
    printf("\tl32i.n\t%s, a2, %d\n", regs.s3, 12);
    printf("\tl32i.n\t%s, a2, %d\n", regs.k[0], 16);
    printf("\tl32i.n\t%s, a2, %d\n", regs.k[1], 20);
    printf("\tl32i.n\t%s, a2, %d\n", regs.k[2], 24);
    printf("\tl32i.n\t%s, a2, %d\n", regs.k[3], 28);
    if (variant != 128) {
        printf("\tl32i.n\t%s, a2, %d\n", regs.k[4], 32);
        printf("\tl32i.n\t%s, a2, %d\n", regs.k[5], 36);
    }

    /* Top of the main loop */
    printf(".L%d0:\n", variant);

    /* Unroll the rounds 4, 12, or 8 at a time */
    if (variant == 128) {
        inner_rounds = 1;
        key_words = 4;
    } else if (variant == 192) {
        inner_rounds = 3;
        key_words = 6;
    } else {
        inner_rounds = 2;
        key_words = 8;
    }
    for (inner = 0; inner < inner_rounds; ++inner) {
        /* Perform the 128 steps of this inner round, 32 at a time */
        int koffset = inner * 4;
        tinyjambu_steps_32(&regs, regs.s0, regs.s1, regs.s2, regs.s3,
                           regs.k[koffset % key_words],
                           (koffset % key_words) * 4);
        tinyjambu_steps_32(&regs, regs.s1, regs.s2, regs.s3, regs.s0,
                           regs.k[(koffset + 1) % key_words],
                           ((koffset + 1) % key_words) * 4);
        tinyjambu_steps_32(&regs, regs.s2, regs.s3, regs.s0, regs.s1,
                           regs.k[(koffset + 2) % key_words],
                           ((koffset + 2) % key_words) * 4);
        tinyjambu_steps_32(&regs, regs.s3, regs.s0, regs.s1, regs.s2,
                           regs.k[(koffset + 3) % key_words],
                           ((koffset + 3) % key_words) * 4);

        /* Check for early bail-out between the inner rounds */
        if (inner < (inner_rounds - 1)) {
            printf("\taddi\ta3, a3, -1\n");
            printf("\tbeqi\ta3, 0, .L%d1\n", variant);
        }
    }

    /* Bottom of the main loop */
    printf("\taddi\ta3, a3, -1\n");
    printf("\tbnei\ta3, 0, .L%d0\n", variant);
    printf(".L%d1:\n", variant);

    /* Store the words back to the state */
    printf("\ts32i.n\t%s, a2, %d\n", regs.s0, 0);
    printf("\ts32i.n\t%s, a2, %d\n", regs.s1, 4);
    printf("\ts32i.n\t%s, a2, %d\n", regs.s2, 8);
    printf("\ts32i.n\t%s, a2, %d\n", regs.s3, 12);

    /* Pop the stack frame, which is a NOP when register windows are in use */
    printf("#ifdef __XTENSA_WINDOWED_ABI__\n");
    printf("\tretw.n\n");
    printf("#else\n");
    printf("\tl32i.n\ta12, sp, 0\n");
    printf("\tl32i.n\ta13, sp, 4\n");
    if (variant != 128) {
        printf("\tl32i.n\ta14, sp, 8\n");
        printf("\tl32i.n\ta15, sp, 12\n");
    }
    printf("\taddi\tsp, sp, 32\n");
    printf("\tret.n\n");
    printf("#endif\n");
}

int main(int argc, char *argv[])
{
    int variant = 128;

    if (argc > 1)
        variant = atoi(argv[1]);

    /* Output the file header */
    printf("#include \"tinyjambu-backend-select.h\"\n");
    printf("#if defined(TINYJAMBU_BACKEND_XTENSA)\n");
    fputs(copyright_message, stdout);

    /* Output the permutation function */
    if (variant == 128) {
        function_header("tinyjambu_permutation_128");
        gen_permute(128);
        function_footer("tinyjambu_permutation_128");
    } else if (variant == 192) {
        function_header("tinyjambu_permutation_192");
        gen_permute(192);
        function_footer("tinyjambu_permutation_192");
    } else {
        function_header("tinyjambu_permutation_256");
        gen_permute(256);
        function_footer("tinyjambu_permutation_256");
    }
    printf("\n");

    /* Output the file footer */
    printf("#endif\n");
    return 0;
}
