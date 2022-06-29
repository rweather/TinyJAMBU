#include "tinyjambu-backend-select.h"
#if defined(TINYJAMBU_BACKEND_XTENSA)
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

#ifdef ESP8266
	.section .irom0.text,"ax",@progbits
#else
	.section .text.tinyjambu_permutation_128,"ax",@progbits
#endif
	.align	4
	.literal_position
	.global	tinyjambu_permutation_128
	.type	tinyjambu_permutation_128, @function
tinyjambu_permutation_128:
#ifdef __XTENSA_WINDOWED_ABI__
	entry	sp, 32
#else
	addi	sp, sp, -32
	s32i.n	a12, sp, 0
	s32i.n	a13, sp, 4
#endif
	l32i.n	a4, a2, 0
	l32i.n	a5, a2, 4
	l32i.n	a6, a2, 8
	l32i.n	a7, a2, 12
	l32i.n	a8, a2, 16
	l32i.n	a9, a2, 20
	l32i.n	a10, a2, 24
	l32i.n	a11, a2, 28
.L1280:
	ssai	15
	src	a12, a6, a5
	ssai	27
	src	a13, a7, a6
	xor	a4, a4, a12
	xor	a4, a4, a13
	ssai	6
	src	a12, a7, a6
	ssai	21
	src	a13, a7, a6
	and	a12, a12, a13
	xor	a4, a4, a12
	xor	a4, a4, a8
	ssai	15
	src	a12, a7, a6
	ssai	27
	src	a13, a4, a7
	xor	a5, a5, a12
	xor	a5, a5, a13
	ssai	6
	src	a12, a4, a7
	ssai	21
	src	a13, a4, a7
	and	a12, a12, a13
	xor	a5, a5, a12
	xor	a5, a5, a9
	ssai	15
	src	a12, a4, a7
	ssai	27
	src	a13, a5, a4
	xor	a6, a6, a12
	xor	a6, a6, a13
	ssai	6
	src	a12, a5, a4
	ssai	21
	src	a13, a5, a4
	and	a12, a12, a13
	xor	a6, a6, a12
	xor	a6, a6, a10
	ssai	15
	src	a12, a5, a4
	ssai	27
	src	a13, a6, a5
	xor	a7, a7, a12
	xor	a7, a7, a13
	ssai	6
	src	a12, a6, a5
	ssai	21
	src	a13, a6, a5
	and	a12, a12, a13
	xor	a7, a7, a12
	xor	a7, a7, a11
	addi	a3, a3, -1
	bnei	a3, 0, .L1280
.L1281:
	s32i.n	a4, a2, 0
	s32i.n	a5, a2, 4
	s32i.n	a6, a2, 8
	s32i.n	a7, a2, 12
#ifdef __XTENSA_WINDOWED_ABI__
	retw.n
#else
	l32i.n	a12, sp, 0
	l32i.n	a13, sp, 4
	addi	sp, sp, 32
	ret.n
#endif
	.size	tinyjambu_permutation_128, .-tinyjambu_permutation_128

#endif
