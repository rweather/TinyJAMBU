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
	.global	tinyjambu_permutation_256
	.thumb
	.thumb_func
	.type	tinyjambu_permutation_256, %function
tinyjambu_permutation_256:
	push	{r4, r5, r6, r7, r8, r9, r10, fp, lr}
	ldr	r3, [r0, #0]
	ldr	r4, [r0, #4]
	ldr	r5, [r0, #8]
	ldr	r6, [r0, #12]
	ldr	r8, [r1, #0]
	ldr	r9, [r1, #4]
	ldr	r10, [r1, #8]
	ldr	fp, [r1, #12]
	ldr	lr, [r1, #16]
.L2561:
	eor	r3, r3, r4, lsr #15
	eor	r3, r3, r5, lsl #17
	eor	r3, r3, r5, lsr #27
	eor	r3, r3, r6, lsl #5
	lsr	r7, r5, #6
	lsr	ip, r5, #21
	eor	r7, r7, r6, lsl #26
	eor	ip, ip, r6, lsl #11
	and	r7, ip
	eors	r3, r7
	eor	r3, r8
	eor	r4, r4, r5, lsr #15
	eor	r4, r4, r6, lsl #17
	eor	r4, r4, r6, lsr #27
	eor	r4, r4, r3, lsl #5
	lsr	r7, r6, #6
	lsr	ip, r6, #21
	eor	r7, r7, r3, lsl #26
	eor	ip, ip, r3, lsl #11
	and	r7, ip
	eors	r4, r7
	eor	r4, r9
	eor	r5, r5, r6, lsr #15
	eor	r5, r5, r3, lsl #17
	eor	r5, r5, r3, lsr #27
	eor	r5, r5, r4, lsl #5
	lsr	r7, r3, #6
	lsr	ip, r3, #21
	eor	r7, r7, r4, lsl #26
	eor	ip, ip, r4, lsl #11
	and	r7, ip
	eors	r5, r7
	eor	r5, r10
	eor	r6, r6, r3, lsr #15
	eor	r6, r6, r4, lsl #17
	eor	r6, r6, r4, lsr #27
	eor	r6, r6, r5, lsl #5
	lsr	r7, r4, #6
	lsr	ip, r4, #21
	eor	r7, r7, r5, lsl #26
	eor	ip, ip, r5, lsl #11
	and	r7, ip
	eors	r6, r7
	eor	r6, fp
	subs	r2, r2, #1
	beq	.L2562
	eor	r3, r3, r4, lsr #15
	eor	r3, r3, r5, lsl #17
	eor	r3, r3, r5, lsr #27
	eor	r3, r3, r6, lsl #5
	lsr	r7, r5, #6
	lsr	ip, r5, #21
	eor	r7, r7, r6, lsl #26
	eor	ip, ip, r6, lsl #11
	and	r7, ip
	eors	r3, r7
	eor	r3, lr
	eor	r4, r4, r5, lsr #15
	eor	r4, r4, r6, lsl #17
	eor	r4, r4, r6, lsr #27
	eor	r4, r4, r3, lsl #5
	lsr	r7, r6, #6
	lsr	ip, r6, #21
	eor	r7, r7, r3, lsl #26
	eor	ip, ip, r3, lsl #11
	and	r7, ip
	eors	r4, r7
	ldr	r7, [r1, #20]
	eors	r4, r7
	eor	r5, r5, r6, lsr #15
	eor	r5, r5, r3, lsl #17
	eor	r5, r5, r3, lsr #27
	eor	r5, r5, r4, lsl #5
	lsr	r7, r3, #6
	lsr	ip, r3, #21
	eor	r7, r7, r4, lsl #26
	eor	ip, ip, r4, lsl #11
	and	r7, ip
	eors	r5, r7
	ldr	r7, [r1, #24]
	eors	r5, r7
	eor	r6, r6, r3, lsr #15
	eor	r6, r6, r4, lsl #17
	eor	r6, r6, r4, lsr #27
	eor	r6, r6, r5, lsl #5
	lsr	r7, r4, #6
	lsr	ip, r4, #21
	eor	r7, r7, r5, lsl #26
	eor	ip, ip, r5, lsl #11
	and	r7, ip
	eors	r6, r7
	ldr	r7, [r1, #28]
	eors	r6, r7
	subs	r2, r2, #1
	bne	.L2561
.L2562:
	str	r3, [r0, #0]
	str	r4, [r0, #4]
	str	r5, [r0, #8]
	str	r6, [r0, #12]
	pop	{r4, r5, r6, r7, r8, r9, r10, fp, pc}
	.size	tinyjambu_permutation_256, .-tinyjambu_permutation_256

#endif
