#include "tinyjambu-backend-select.h"
#if defined(TINYJAMBU_BACKEND_ARMV7M)
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

	.syntax unified
	.thumb
	.text

	.align	2
	.global	tinyjambu_permutation_128
	.thumb
	.thumb_func
	.type	tinyjambu_permutation_128, %function
tinyjambu_permutation_128:
	push	{r4, r5, r6, r7, r8, r9, r10}
	ldr	r3, [r0, #0]
	ldr	r4, [r0, #4]
	ldr	r5, [r0, #8]
	ldr	r6, [r0, #12]
	ldr	r7, [r1, #0]
	ldr	r8, [r1, #4]
	ldr	r9, [r1, #8]
	ldr	r10, [r1, #12]
.L128:
	eor	r3, r3, r4, lsr #15
	eor	r3, r3, r5, lsl #17
	eor	r3, r3, r5, lsr #27
	eor	r3, r3, r6, lsl #5
	lsr	r1, r5, #6
	lsr	ip, r5, #21
	eor	r1, r1, r6, lsl #26
	eor	ip, ip, r6, lsl #11
	and	r1, ip
	eors	r3, r1
	eors	r3, r7
	eor	r4, r4, r5, lsr #15
	eor	r4, r4, r6, lsl #17
	eor	r4, r4, r6, lsr #27
	eor	r4, r4, r3, lsl #5
	lsr	r1, r6, #6
	lsr	ip, r6, #21
	eor	r1, r1, r3, lsl #26
	eor	ip, ip, r3, lsl #11
	and	r1, ip
	eors	r4, r1
	eor	r4, r8
	eor	r5, r5, r6, lsr #15
	eor	r5, r5, r3, lsl #17
	eor	r5, r5, r3, lsr #27
	eor	r5, r5, r4, lsl #5
	lsr	r1, r3, #6
	lsr	ip, r3, #21
	eor	r1, r1, r4, lsl #26
	eor	ip, ip, r4, lsl #11
	and	r1, ip
	eors	r5, r1
	eor	r5, r9
	eor	r6, r6, r3, lsr #15
	eor	r6, r6, r4, lsl #17
	eor	r6, r6, r4, lsr #27
	eor	r6, r6, r5, lsl #5
	lsr	r1, r4, #6
	lsr	ip, r4, #21
	eor	r1, r1, r5, lsl #26
	eor	ip, ip, r5, lsl #11
	and	r1, ip
	eors	r6, r1
	eor	r6, r10
	subs	r2, r2, #1
	bne	.L128
	str	r3, [r0, #0]
	str	r4, [r0, #4]
	str	r5, [r0, #8]
	str	r6, [r0, #12]
	pop	{r4, r5, r6, r7, r8, r9, r10}
	bx	lr
	.size	tinyjambu_permutation_128, .-tinyjambu_permutation_128

#endif
