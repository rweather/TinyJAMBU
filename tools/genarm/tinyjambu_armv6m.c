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
 * TinyJAMBU permutation for ARM v6m microprocessors.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "copyright.h"

static void function_header(const char *name)
{
    printf("\n\t.align\t2\n");
    printf("\t.global\t%s\n", name);
    printf("\t.thumb\n");
    printf("\t.thumb_func\n");
    printf("\t.type\t%s, %%function\n", name);
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
    const char *t0;
    const char *t1;
    const char *t2;

} reg_names;

static int is_low_reg(const char *reg)
{
    return reg[0] == 'r' && atoi(reg + 1) < 8;
}

/* Generates a binary operator, preferring thumb instructions if possible */
static void binop(const char *name, const char *reg1, const char *reg2)
{
    if (is_low_reg(reg1) && is_low_reg(reg2))
        printf("\t%ss\t%s, %s\n", name, reg1, reg2);
    else
        printf("\t%s\t%s, %s\n", name, reg1, reg2);
}

/* Shift a value right */
static void right(const char *dest, const char *src, int shift)
{
    printf("\tlsrs\t%s, %s, #%d\n", dest, src, shift);
}

/* Shift a value left */
static void left(const char *dest, const char *src, int shift)
{
    printf("\tlsls\t%s, %s, #%d\n", dest, src, shift);
}

/* Save r1 so that it can be used as an extra temporary */
static void save_r1(void)
{
    printf("\tmov\tip, r1\n");
}

/* Restore the value of r1 */
static void restore_r1(void)
{
    printf("\tmov\tr1, ip\n");
}

/* Perform 32 steps of the TinyJAMBU permutation */
static void tinyjambu_steps_32
    (const reg_names *regs, const char *s0, const char *s1,
     const char *s2, const char *s3, int offset)
{
    /*
     * t1 = (s1 >> 15) | (s2 << 17);
     * t2 = (s2 >> 6)  | (s3 << 26);
     * t3 = (s2 >> 21) | (s3 << 11);
     * t4 = (s2 >> 27) | (s3 << 5);
     * s0 ^= t1 ^ (~(t2 & t3)) ^ t4 ^ kreg;
     */

    /* s0 ^= (s1 >> 15) | (s2 << 17); */
    right(regs->t0, s1, 15);
    left(regs->t1, s2, 17);
    binop("eor", s0, regs->t0);
    binop("eor", s0, regs->t1);

    /* s0 ^= (s2 >> 27) | (s3 << 5); */
    right(regs->t0, s2, 27);
    left(regs->t1, s3, 5);
    binop("eor", s0, regs->t0);
    binop("eor", s0, regs->t1);

    /* t2 = (s2 >> 6) | (s3 << 26); */
    right(regs->t0, s2, 6);
    left(regs->t1, s3, 26);
    binop("eor", regs->t0, regs->t1);

    /* t3 = (s2 >> 21) | (s3 << 11); */
    right(regs->t1, s2, 21);
    left(regs->t2, s3, 11);
    binop("eor", regs->t1, regs->t2);

    /* s0 ^= ~(t2 & t3); */
    /* Note: We assume that the key is inverted so we can avoid the NOT */
    binop("and", regs->t0, regs->t1);
    binop("eor", s0, regs->t0);

    /* s0 ^= k[offset]; */
    printf("\tldr\t%s, [r0, #%d]\n", regs->t0, 16 + offset);
    binop("eor", s0, regs->t0);
}

/*
 * r0 holds the pointer to the TinyJAMBU state on entry and exit.
 * r1 is the number of rounds to perform (* 128 for the number of steps).
 *
 * r0, r1, r2, r3, and ip can be used as scratch registers without saving,
 * but the value of ip may not survive across a branch instruction.
 *
 * r4, r5, r6, r7, r8, r9, r10, and fp must be callee-saved.
 *
 * lr can be used as a temporary as long as it is saved on the stack.
 */

/* Generate the body of the TinyJAMBU-128 permutation function */
static void gen_tinyjambu_128(void)
{
    reg_names regs;
    regs.s0 = "r2";
    regs.s1 = "r3";
    regs.s2 = "r4";
    regs.s3 = "r5";
    regs.t0 = "r6";
    regs.t1 = "r7";
    regs.t2 = "r1";
    printf("\tpush\t{r4, r5, r6, r7, lr}\n");

    /* Load all words of the state and the key into registers */
    printf("\tldr\t%s, [r0, #%d]\n", regs.s0, 0);
    printf("\tldr\t%s, [r0, #%d]\n", regs.s1, 4);
    printf("\tldr\t%s, [r0, #%d]\n", regs.s2, 8);
    printf("\tldr\t%s, [r0, #%d]\n", regs.s3, 12);

    /* Top of the round loop */
    printf(".L128:\n");

    /* Perform 128 steps for this round */
    save_r1();
    tinyjambu_steps_32(&regs, regs.s0, regs.s1, regs.s2, regs.s3, 0);
    tinyjambu_steps_32(&regs, regs.s1, regs.s2, regs.s3, regs.s0, 4);
    tinyjambu_steps_32(&regs, regs.s2, regs.s3, regs.s0, regs.s1, 8);
    tinyjambu_steps_32(&regs, regs.s3, regs.s0, regs.s1, regs.s2, 12);
    restore_r1();

    /* Bottom of the round loop */
    printf("\tsubs\tr1, r1, #1\n");
    printf("\tbne\t.L128\n");

    /* Store the words back to the state and exit */
    printf("\tstr\t%s, [r0, #%d]\n", regs.s0, 0);
    printf("\tstr\t%s, [r0, #%d]\n", regs.s1, 4);
    printf("\tstr\t%s, [r0, #%d]\n", regs.s2, 8);
    printf("\tstr\t%s, [r0, #%d]\n", regs.s3, 12);
    printf("\tpop\t{r4, r5, r6, r7, pc}\n");
}

/* Generate the body of the TinyJAMBU-192 permutation function */
static void gen_tinyjambu_192(void)
{
    reg_names regs;
    regs.s0 = "r2";
    regs.s1 = "r3";
    regs.s2 = "r4";
    regs.s3 = "r5";
    regs.t0 = "r6";
    regs.t1 = "r7";
    regs.t2 = "r1";
    printf("\tpush\t{r4, r5, r6, r7, lr}\n");

    /* Load all words of the state and the key into registers */
    printf("\tldr\t%s, [r0, #%d]\n", regs.s0, 0);
    printf("\tldr\t%s, [r0, #%d]\n", regs.s1, 4);
    printf("\tldr\t%s, [r0, #%d]\n", regs.s2, 8);
    printf("\tldr\t%s, [r0, #%d]\n", regs.s3, 12);

    /* Top of the round loop */
    printf(".L1921:\n");

    /* Unroll the loop 3 times to help with key word alignment */
    save_r1();
    tinyjambu_steps_32(&regs, regs.s0, regs.s1, regs.s2, regs.s3, 0);
    tinyjambu_steps_32(&regs, regs.s1, regs.s2, regs.s3, regs.s0, 4);
    tinyjambu_steps_32(&regs, regs.s2, regs.s3, regs.s0, regs.s1, 8);
    tinyjambu_steps_32(&regs, regs.s3, regs.s0, regs.s1, regs.s2, 12);
    restore_r1();
    printf("\tsubs\tr1, r1, #1\n");
    printf("\tbeq\t.L1922\n");  /* Early exit if the rounds are done */
    save_r1();
    tinyjambu_steps_32(&regs, regs.s0, regs.s1, regs.s2, regs.s3, 16);
    tinyjambu_steps_32(&regs, regs.s1, regs.s2, regs.s3, regs.s0, 20);
    tinyjambu_steps_32(&regs, regs.s2, regs.s3, regs.s0, regs.s1, 0);
    tinyjambu_steps_32(&regs, regs.s3, regs.s0, regs.s1, regs.s2, 4);
    restore_r1();
    printf("\tsubs\tr1, r1, #1\n");
    printf("\tbeq\t.L1922\n");  /* Early exit if the rounds are done */
    save_r1();
    tinyjambu_steps_32(&regs, regs.s0, regs.s1, regs.s2, regs.s3, 8);
    tinyjambu_steps_32(&regs, regs.s1, regs.s2, regs.s3, regs.s0, 12);
    tinyjambu_steps_32(&regs, regs.s2, regs.s3, regs.s0, regs.s1, 16);
    tinyjambu_steps_32(&regs, regs.s3, regs.s0, regs.s1, regs.s2, 20);
    restore_r1();

    /* Bottom of the round loop */
    printf("\tsubs\tr1, r1, #1\n");
    printf("\tbne\t.L1921\n");

    /* Store the words back to the state and exit */
    printf(".L1922:\n");
    printf("\tstr\t%s, [r0, #%d]\n", regs.s0, 0);
    printf("\tstr\t%s, [r0, #%d]\n", regs.s1, 4);
    printf("\tstr\t%s, [r0, #%d]\n", regs.s2, 8);
    printf("\tstr\t%s, [r0, #%d]\n", regs.s3, 12);
    printf("\tpop\t{r4, r5, r6, r7, pc}\n");
}

/* Generate the body of the TinyJAMBU-256 permutation function */
static void gen_tinyjambu_256(void)
{
    reg_names regs;
    regs.s0 = "r2";
    regs.s1 = "r3";
    regs.s2 = "r4";
    regs.s3 = "r5";
    regs.t0 = "r6";
    regs.t1 = "r7";
    regs.t2 = "r1";
    printf("\tpush\t{r4, r5, r6, r7, lr}\n");

    /* Load all words of the state and most of the key into registers.
     * The last 3 key words need to be loaded on demand. */
    printf("\tldr\t%s, [r0, #%d]\n", regs.s0, 0);
    printf("\tldr\t%s, [r0, #%d]\n", regs.s1, 4);
    printf("\tldr\t%s, [r0, #%d]\n", regs.s2, 8);
    printf("\tldr\t%s, [r0, #%d]\n", regs.s3, 12);

    /* Top of the round loop */
    printf(".L2561:\n");

    /* Unroll the loop 2 times to help with key word alignment */
    save_r1();
    tinyjambu_steps_32(&regs, regs.s0, regs.s1, regs.s2, regs.s3, 0);
    tinyjambu_steps_32(&regs, regs.s1, regs.s2, regs.s3, regs.s0, 4);
    tinyjambu_steps_32(&regs, regs.s2, regs.s3, regs.s0, regs.s1, 8);
    tinyjambu_steps_32(&regs, regs.s3, regs.s0, regs.s1, regs.s2, 12);
    restore_r1();
    printf("\tsubs\tr1, r1, #1\n");
    printf("\tbeq\t.L2562\n");  /* Early exit if the rounds are done */
    save_r1();
    tinyjambu_steps_32(&regs, regs.s0, regs.s1, regs.s2, regs.s3, 16);
    tinyjambu_steps_32(&regs, regs.s1, regs.s2, regs.s3, regs.s0, 20);
    tinyjambu_steps_32(&regs, regs.s2, regs.s3, regs.s0, regs.s1, 24);
    tinyjambu_steps_32(&regs, regs.s3, regs.s0, regs.s1, regs.s2, 28);
    restore_r1();

    /* Bottom of the round loop */
    printf("\tsubs\tr1, r1, #1\n");
    printf("\tbne\t.L2561\n");

    /* Store the words back to the state and exit */
    printf(".L2562:\n");
    printf("\tstr\t%s, [r0, #%d]\n", regs.s0, 0);
    printf("\tstr\t%s, [r0, #%d]\n", regs.s1, 4);
    printf("\tstr\t%s, [r0, #%d]\n", regs.s2, 8);
    printf("\tstr\t%s, [r0, #%d]\n", regs.s3, 12);
    printf("\tpop\t{r4, r5, r6, r7, pc}\n");
}

int main(int argc, char *argv[])
{
    int variant = 128;

    if (argc > 1)
        variant = atoi(argv[1]);

    /* Output the file header */
    printf("#include \"tinyjambu-backend-select.h\"\n");
    printf("#if defined(TINYJAMBU_BACKEND_ARMV6M)\n");
    fputs(copyright_message, stdout);
    printf("\t.syntax unified\n");
    printf("\t.thumb\n");
    printf("\t.text\n");

    /* Output the TinyJAMBU-128 permutation function */
    if (variant == 128) {
        function_header("tinyjambu_permutation_128");
        gen_tinyjambu_128();
        function_footer("tinyjambu_permutation_128");
    }

    /* Output the TinyJAMBU-192 permutation function */
    if (variant == 192) {
        function_header("tinyjambu_permutation_192");
        gen_tinyjambu_192();
        function_footer("tinyjambu_permutation_192");
    }

    /* Output the TinyJAMBU-256 permutation function */
    if (variant == 256) {
        function_header("tinyjambu_permutation_256");
        gen_tinyjambu_256();
        function_footer("tinyjambu_permutation_256");
    }

    /* Output the file footer */
    printf("\n");
    printf("#endif\n");
    return 0;
}
