#include "tinyjambu-backend-select.h"
#if defined(TINYJAMBU_BACKEND_ARMV6M)
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
	push	{r4, r5, r6, r7, lr}
	ldr	r2, [r0, #0]
	ldr	r3, [r0, #4]
	ldr	r4, [r0, #8]
	ldr	r5, [r0, #12]
.L2561:
	mov	ip, r1
	lsrs	r6, r3, #15
	lsls	r7, r4, #17
	eors	r2, r6
	eors	r2, r7
	lsrs	r6, r4, #27
	lsls	r7, r5, #5
	eors	r2, r6
	eors	r2, r7
	lsrs	r6, r4, #6
	lsls	r7, r5, #26
	eors	r6, r7
	lsrs	r7, r4, #21
	lsls	r1, r5, #11
	eors	r7, r1
	ands	r6, r7
	eors	r2, r6
	ldr	r6, [r0, #16]
	eors	r2, r6
	lsrs	r6, r4, #15
	lsls	r7, r5, #17
	eors	r3, r6
	eors	r3, r7
	lsrs	r6, r5, #27
	lsls	r7, r2, #5
	eors	r3, r6
	eors	r3, r7
	lsrs	r6, r5, #6
	lsls	r7, r2, #26
	eors	r6, r7
	lsrs	r7, r5, #21
	lsls	r1, r2, #11
	eors	r7, r1
	ands	r6, r7
	eors	r3, r6
	ldr	r6, [r0, #20]
	eors	r3, r6
	lsrs	r6, r5, #15
	lsls	r7, r2, #17
	eors	r4, r6
	eors	r4, r7
	lsrs	r6, r2, #27
	lsls	r7, r3, #5
	eors	r4, r6
	eors	r4, r7
	lsrs	r6, r2, #6
	lsls	r7, r3, #26
	eors	r6, r7
	lsrs	r7, r2, #21
	lsls	r1, r3, #11
	eors	r7, r1
	ands	r6, r7
	eors	r4, r6
	ldr	r6, [r0, #24]
	eors	r4, r6
	lsrs	r6, r2, #15
	lsls	r7, r3, #17
	eors	r5, r6
	eors	r5, r7
	lsrs	r6, r3, #27
	lsls	r7, r4, #5
	eors	r5, r6
	eors	r5, r7
	lsrs	r6, r3, #6
	lsls	r7, r4, #26
	eors	r6, r7
	lsrs	r7, r3, #21
	lsls	r1, r4, #11
	eors	r7, r1
	ands	r6, r7
	eors	r5, r6
	ldr	r6, [r0, #28]
	eors	r5, r6
	mov	r1, ip
	subs	r1, r1, #1
	beq	.L2562
	mov	ip, r1
	lsrs	r6, r3, #15
	lsls	r7, r4, #17
	eors	r2, r6
	eors	r2, r7
	lsrs	r6, r4, #27
	lsls	r7, r5, #5
	eors	r2, r6
	eors	r2, r7
	lsrs	r6, r4, #6
	lsls	r7, r5, #26
	eors	r6, r7
	lsrs	r7, r4, #21
	lsls	r1, r5, #11
	eors	r7, r1
	ands	r6, r7
	eors	r2, r6
	ldr	r6, [r0, #32]
	eors	r2, r6
	lsrs	r6, r4, #15
	lsls	r7, r5, #17
	eors	r3, r6
	eors	r3, r7
	lsrs	r6, r5, #27
	lsls	r7, r2, #5
	eors	r3, r6
	eors	r3, r7
	lsrs	r6, r5, #6
	lsls	r7, r2, #26
	eors	r6, r7
	lsrs	r7, r5, #21
	lsls	r1, r2, #11
	eors	r7, r1
	ands	r6, r7
	eors	r3, r6
	ldr	r6, [r0, #36]
	eors	r3, r6
	lsrs	r6, r5, #15
	lsls	r7, r2, #17
	eors	r4, r6
	eors	r4, r7
	lsrs	r6, r2, #27
	lsls	r7, r3, #5
	eors	r4, r6
	eors	r4, r7
	lsrs	r6, r2, #6
	lsls	r7, r3, #26
	eors	r6, r7
	lsrs	r7, r2, #21
	lsls	r1, r3, #11
	eors	r7, r1
	ands	r6, r7
	eors	r4, r6
	ldr	r6, [r0, #40]
	eors	r4, r6
	lsrs	r6, r2, #15
	lsls	r7, r3, #17
	eors	r5, r6
	eors	r5, r7
	lsrs	r6, r3, #27
	lsls	r7, r4, #5
	eors	r5, r6
	eors	r5, r7
	lsrs	r6, r3, #6
	lsls	r7, r4, #26
	eors	r6, r7
	lsrs	r7, r3, #21
	lsls	r1, r4, #11
	eors	r7, r1
	ands	r6, r7
	eors	r5, r6
	ldr	r6, [r0, #44]
	eors	r5, r6
	mov	r1, ip
	subs	r1, r1, #1
	beq	.L2562
	b	.L2561
.L2562:
	str	r2, [r0, #0]
	str	r3, [r0, #4]
	str	r4, [r0, #8]
	str	r5, [r0, #12]
	pop	{r4, r5, r6, r7, pc}
	.size	tinyjambu_permutation_256, .-tinyjambu_permutation_256

#endif
