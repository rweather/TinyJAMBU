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
 * TinyJAMBU permutation for 32-bit RISC-V microprocessors.
 *
 * This can also be used to generate a version for 64-bit RISC-V
 * microprocessors but the basic operations are still on 32-bit words.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "copyright.h"

/* Name of an instruction, optionally modified for hosting on RV64I */
#if defined(RV64I_PLATFORM)
#define INSN(name)  "\t" #name "\t"
#define INSNW(name) "\t" #name "w\t"
#else
#define INSN(name)  "\t" #name "\t"
#define INSNW(name) "\t" #name "\t"
#endif

static void function_header(const char *name, int variant)
{
    printf("\n\t.align\t1\n");
    printf("\t.globl\t%s_%d\n", name, variant);
    printf("\t.type\t%s_%d, @function\n", name, variant);
    printf("%s_%d:\n", name, variant);
}

static void function_footer(const char *name, int variant)
{
    printf("\tret\n");
    printf("\t.size\t%s_%d, .-%s_%d\n", name, variant, name, variant);
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
    const char *t2;
    const char *t3;

} reg_names;

/* Generates a binary operator */
static void binop(const char *name, const char *reg1, const char *reg2)
{
    printf("%s%s, %s, %s\n", name, reg1, reg1, reg2);
}

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

    /* t1 = (s1 >> 15) | (s2 << 17); */
    /* t4 = (s2 >> 27) | (s3 << 5); */
    /* s0 ^= t1 ^ t4 */
    printf(INSNW(srli) "%s, %s, 15\n", regs->t0, s1);
    printf(INSNW(srli) "%s, %s, 27\n", regs->t1, s2);
    printf(INSNW(slli) "%s, %s, 17\n", regs->t2, s2);
    printf(INSNW(slli) "%s, %s, 5\n", regs->t3, s3);
    binop(INSN(xor), s0, regs->t0);
    binop(INSN(xor), s0, regs->t1);
    binop(INSN(xor), s0, regs->t2);
    binop(INSN(xor), s0, regs->t3);

    /* t2 = (s2 >> 6)  | (s3 << 26); */
    /* t3 = (s2 >> 21) | (s3 << 11); */
    printf(INSNW(srli) "%s, %s, 6\n", regs->t2, s2);
    printf(INSNW(srli) "%s, %s, 21\n", regs->t3, s2);
    printf(INSNW(slli) "%s, %s, 26\n", regs->t0, s3);
    printf(INSNW(slli) "%s, %s, 11\n", regs->t1, s3);
    binop(INSN(xor), regs->t2, regs->t0);
    binop(INSN(xor), regs->t3, regs->t1);

    /* s0 ^= (~(t2 & t3)) ^ kreg; */
    /* Note: We assume that the key is inverted so we can avoid the NOT */
    binop(INSN(and), regs->t2, regs->t3);
    if (kreg) {
        binop(INSN(xor), s0, kreg);
        binop(INSN(xor), s0, regs->t2);
    } else {
        printf("\tlw\t%s, %d(a0)\n", regs->t0, 16 + offset);
        binop(INSN(xor), s0, regs->t2);
        binop(INSN(xor), s0, regs->t0);
    }
}

/* Generate the body of the TiknyJAMBU permutation function */
static void gen_permute(int variant)
{
    /*
     * x0/zero is hard-wired to zero.
     *
     * a0-a7 contain arguments and can be used as scratch registers.
     * t0-t6 can be used as scratch registers.
     *
     * s0/fp is the frame pointer.
     * ra is the link register.
     * t0 can be used as an alternative link register.
     * s1-s11 are callee-saved.
     */
    reg_names regs = { .s0 = 0 };
    int need_stack_frame = 0;
    int index;
#if defined(RV32E)
    regs.s0 = "a2";
    regs.s1 = "a3";
    regs.s2 = "a4";
    regs.s3 = "a5";
    regs.t0 = "t0";
    regs.t1 = "t1";
    regs.t2 = "t2";
    regs.t3 = "s0";
    need_stack_frame = 1;
#else
    regs.s0 = "a2";
    regs.s1 = "a3";
    regs.s2 = "a4";
    regs.s3 = "a5";
    regs.k[0] = "a6";
    regs.k[1] = "a7";
    regs.k[2] = "t4";
    regs.k[3] = "t5";
    if (variant >= 192) {
        regs.k[4] = "t6";
        regs.k[5] = "s0";
        need_stack_frame = 1;
    }
    if (variant >= 256) {
        regs.k[6] = "s1";
        regs.k[7] = "s2";
        need_stack_frame = 1;
    }
    regs.t0 = "t0";
    regs.t1 = "t1";
    regs.t2 = "t2";
    regs.t3 = "t3";
#endif

    /* Create the stack frame and save the callee-saved registers */
    /* ABI documentation suggests to align the stack on a 16 byte boundary */
#if defined(RV64I_PLATFORM)
    if (need_stack_frame)
        printf("\taddi\tsp, sp, -32\n");
#if defined(RV32E)
    printf("\tsd\ts0, (sp)\n");
#else
    if (variant >= 192) {
        printf("\tsd\ts0, (sp)\n");
    }
    if (variant >= 256) {
        printf("\tsd\ts1, 8(sp)\n");
        printf("\tsd\ts2, 16(sp)\n");
    }
#endif
#else
    if (need_stack_frame)
        printf("\taddi\tsp, sp, -16\n");
#if defined(RV32E)
    printf("\tsw\ts0, (sp)\n");
#else
    if (variant >= 192) {
        printf("\tsw\ts0, (sp)\n");
    }
    if (variant >= 256) {
        printf("\tsw\ts1, 4(sp)\n");
        printf("\tsw\ts2, 8(sp)\n");
    }
#endif
#endif

    /* Load the state and as much of the key as possible into registers */
    printf("\tlw\t%s, (a0)\n", regs.s0);
    printf("\tlw\t%s, 4(a0)\n", regs.s1);
    printf("\tlw\t%s, 8(a0)\n", regs.s2);
    printf("\tlw\t%s, 12(a0)\n", regs.s3);
    for (index = 0; index < 8; ++index) {
        if (regs.k[index])
            printf("\tlw\t%s, %d(a0)\n", regs.k[index], 16 + index * 4);
    }

    /* Top of the round loop */
    printf(".L%d1:\n", variant);

    /* Unroll the inner part of the loop based on the variant */
    if (variant == 128) {
        tinyjambu_steps_32
            (&regs, regs.s0, regs.s1, regs.s2, regs.s3, regs.k[0], 0);
        tinyjambu_steps_32
            (&regs, regs.s1, regs.s2, regs.s3, regs.s0, regs.k[1], 4);
        tinyjambu_steps_32
            (&regs, regs.s2, regs.s3, regs.s0, regs.s1, regs.k[2], 8);
        tinyjambu_steps_32
            (&regs, regs.s3, regs.s0, regs.s1, regs.s2, regs.k[3], 12);
    } else if (variant == 192) {
        tinyjambu_steps_32
            (&regs, regs.s0, regs.s1, regs.s2, regs.s3, regs.k[0], 0);
        tinyjambu_steps_32
            (&regs, regs.s1, regs.s2, regs.s3, regs.s0, regs.k[1], 4);
        tinyjambu_steps_32
            (&regs, regs.s2, regs.s3, regs.s0, regs.s1, regs.k[2], 8);
        tinyjambu_steps_32
            (&regs, regs.s3, regs.s0, regs.s1, regs.s2, regs.k[3], 12);
        printf("\taddi\ta1, a1, -1\n");
        printf("\tbeq\ta1, zero, .L%d2\n", variant);
        tinyjambu_steps_32
            (&regs, regs.s0, regs.s1, regs.s2, regs.s3, regs.k[4], 16);
        tinyjambu_steps_32
            (&regs, regs.s1, regs.s2, regs.s3, regs.s0, regs.k[5], 20);
        tinyjambu_steps_32
            (&regs, regs.s2, regs.s3, regs.s0, regs.s1, regs.k[0], 0);
        tinyjambu_steps_32
            (&regs, regs.s3, regs.s0, regs.s1, regs.s2, regs.k[1], 4);
        printf("\taddi\ta1, a1, -1\n");
        printf("\tbeq\ta1, zero, .L%d2\n", variant);
        tinyjambu_steps_32
            (&regs, regs.s0, regs.s1, regs.s2, regs.s3, regs.k[2], 8);
        tinyjambu_steps_32
            (&regs, regs.s1, regs.s2, regs.s3, regs.s0, regs.k[3], 12);
        tinyjambu_steps_32
            (&regs, regs.s2, regs.s3, regs.s0, regs.s1, regs.k[4], 16);
        tinyjambu_steps_32
            (&regs, regs.s3, regs.s0, regs.s1, regs.s2, regs.k[5], 20);
    } else {
        tinyjambu_steps_32
            (&regs, regs.s0, regs.s1, regs.s2, regs.s3, regs.k[0], 0);
        tinyjambu_steps_32
            (&regs, regs.s1, regs.s2, regs.s3, regs.s0, regs.k[1], 4);
        tinyjambu_steps_32
            (&regs, regs.s2, regs.s3, regs.s0, regs.s1, regs.k[2], 8);
        tinyjambu_steps_32
            (&regs, regs.s3, regs.s0, regs.s1, regs.s2, regs.k[3], 12);
        printf("\taddi\ta1, a1, -1\n");
        printf("\tbeq\ta1, zero, .L%d2\n", variant);
        tinyjambu_steps_32
            (&regs, regs.s0, regs.s1, regs.s2, regs.s3, regs.k[4], 16);
        tinyjambu_steps_32
            (&regs, regs.s1, regs.s2, regs.s3, regs.s0, regs.k[5], 20);
        tinyjambu_steps_32
            (&regs, regs.s2, regs.s3, regs.s0, regs.s1, regs.k[6], 24);
        tinyjambu_steps_32
            (&regs, regs.s3, regs.s0, regs.s1, regs.s2, regs.k[7], 28);
    }

    /* Bottom of the round loop */
    printf("\taddi\ta1, a1, -1\n");
    printf("\tbne\ta1, zero, .L%d1\n", variant);
    printf(".L%d2:\n", variant);

    /* Write the state back */
    printf("\tsw\t%s, (a0)\n", regs.s0);
    printf("\tsw\t%s, 4(a0)\n", regs.s1);
    printf("\tsw\t%s, 8(a0)\n", regs.s2);
    printf("\tsw\t%s, 12(a0)\n", regs.s3);

    /* Pop the stack frame */
#if defined(RV64I_PLATFORM)
#if defined(RV32E)
    printf("\tld\ts0, (sp)\n");
#else
    if (variant >= 192) {
        printf("\tld\ts0, (sp)\n");
    }
    if (variant >= 256) {
        printf("\tld\ts1, 8(sp)\n");
        printf("\tld\ts2, 16(sp)\n");
    }
#endif
    if (need_stack_frame)
        printf("\taddi\tsp, sp, 32\n");
#else
#if defined(RV32E)
    printf("\tlw\ts0, (sp)\n");
#else
    if (variant >= 192) {
        printf("\tlw\ts0, (sp)\n");
    }
    if (variant >= 256) {
        printf("\tlw\ts1, 4(sp)\n");
        printf("\tlw\ts2, 8(sp)\n");
    }
#endif
    if (need_stack_frame)
        printf("\taddi\tsp, sp, 16\n");
#endif
}

int main(int argc, char *argv[])
{
    int variant = 128;

    if (argc > 1)
        variant = atoi(argv[1]);

    /* Output the file header */
    printf("#include \"tinyjambu-backend-select.h\"\n");
#if defined(RV64I_PLATFORM)
    printf("#if defined(TINYJAMBU_BACKEND_RISCV64I)\n");
#elif defined(RV32E)
    printf("#if defined(TINYJAMBU_BACKEND_RISCV32E)\n");
#else
    printf("#if defined(TINYJAMBU_BACKEND_RISCV32I)\n");
#endif
    fputs(copyright_message, stdout);
    printf("#ifdef __riscv_cmodel_pic\n");
    printf("\t.option\tpic\n");
    printf("#else\n");
    printf("\t.option\tnopic\n");
    printf("#endif\n");
    printf("\t.text\n");

    /* Output the permutation function */
    function_header("tinyjambu_permutation", variant);
    gen_permute(variant);
    function_footer("tinyjambu_permutation", variant);

    /* Output the file footer */
    printf("\n");
    printf("#endif\n");
    return 0;
}
