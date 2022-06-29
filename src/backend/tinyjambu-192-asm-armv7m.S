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
	.global	tinyjambu_permutation_192
	.thumb
	.thumb_func
	.type	tinyjambu_permutation_192, %function
tinyjambu_permutation_192:
	push	{r4, r5, r6, r7, r8, r9, r10, fp, lr}
	ldr	r2, [r0, #0]
	ldr	r3, [r0, #4]
	ldr	r4, [r0, #8]
	ldr	r5, [r0, #12]
	ldr	r6, [r0, #16]
	ldr	r7, [r0, #20]
	ldr	r8, [r0, #24]
	ldr	r9, [r0, #28]
	ldr	r10, [r0, #32]
	ldr	fp, [r0, #36]
.L1921:
	eor	r2, r2, r3, lsr #15
	eor	r2, r2, r4, lsl #17
	eor	r2, r2, r4, lsr #27
	eor	r2, r2, r5, lsl #5
	lsr	lr, r4, #6
	lsr	ip, r4, #21
	eor	lr, lr, r5, lsl #26
	eor	ip, ip, r5, lsl #11
	and	lr, ip
	eor	r2, lr
	eors	r2, r6
	eor	r3, r3, r4, lsr #15
	eor	r3, r3, r5, lsl #17
	eor	r3, r3, r5, lsr #27
	eor	r3, r3, r2, lsl #5
	lsr	lr, r5, #6
	lsr	ip, r5, #21
	eor	lr, lr, r2, lsl #26
	eor	ip, ip, r2, lsl #11
	and	lr, ip
	eor	r3, lr
	eors	r3, r7
	eor	r4, r4, r5, lsr #15
	eor	r4, r4, r2, lsl #17
	eor	r4, r4, r2, lsr #27
	eor	r4, r4, r3, lsl #5
	lsr	lr, r2, #6
	lsr	ip, r2, #21
	eor	lr, lr, r3, lsl #26
	eor	ip, ip, r3, lsl #11
	and	lr, ip
	eor	r4, lr
	eor	r4, r8
	eor	r5, r5, r2, lsr #15
	eor	r5, r5, r3, lsl #17
	eor	r5, r5, r3, lsr #27
	eor	r5, r5, r4, lsl #5
	lsr	lr, r3, #6
	lsr	ip, r3, #21
	eor	lr, lr, r4, lsl #26
	eor	ip, ip, r4, lsl #11
	and	lr, ip
	eor	r5, lr
	eor	r5, r9
	subs	r1, r1, #1
	beq	.L1922
	eor	r2, r2, r3, lsr #15
	eor	r2, r2, r4, lsl #17
	eor	r2, r2, r4, lsr #27
	eor	r2, r2, r5, lsl #5
	lsr	lr, r4, #6
	lsr	ip, r4, #21
	eor	lr, lr, r5, lsl #26
	eor	ip, ip, r5, lsl #11
	and	lr, ip
	eor	r2, lr
	eor	r2, r10
	eor	r3, r3, r4, lsr #15
	eor	r3, r3, r5, lsl #17
	eor	r3, r3, r5, lsr #27
	eor	r3, r3, r2, lsl #5
	lsr	lr, r5, #6
	lsr	ip, r5, #21
	eor	lr, lr, r2, lsl #26
	eor	ip, ip, r2, lsl #11
	and	lr, ip
	eor	r3, lr
	eor	r3, fp
	eor	r4, r4, r5, lsr #15
	eor	r4, r4, r2, lsl #17
	eor	r4, r4, r2, lsr #27
	eor	r4, r4, r3, lsl #5
	lsr	lr, r2, #6
	lsr	ip, r2, #21
	eor	lr, lr, r3, lsl #26
	eor	ip, ip, r3, lsl #11
	and	lr, ip
	eor	r4, lr
	eors	r4, r6
	eor	r5, r5, r2, lsr #15
	eor	r5, r5, r3, lsl #17
	eor	r5, r5, r3, lsr #27
	eor	r5, r5, r4, lsl #5
	lsr	lr, r3, #6
	lsr	ip, r3, #21
	eor	lr, lr, r4, lsl #26
	eor	ip, ip, r4, lsl #11
	and	lr, ip
	eor	r5, lr
	eors	r5, r7
	subs	r1, r1, #1
	beq	.L1922
	eor	r2, r2, r3, lsr #15
	eor	r2, r2, r4, lsl #17
	eor	r2, r2, r4, lsr #27
	eor	r2, r2, r5, lsl #5
	lsr	lr, r4, #6
	lsr	ip, r4, #21
	eor	lr, lr, r5, lsl #26
	eor	ip, ip, r5, lsl #11
	and	lr, ip
	eor	r2, lr
	eor	r2, r8
	eor	r3, r3, r4, lsr #15
	eor	r3, r3, r5, lsl #17
	eor	r3, r3, r5, lsr #27
	eor	r3, r3, r2, lsl #5
	lsr	lr, r5, #6
	lsr	ip, r5, #21
	eor	lr, lr, r2, lsl #26
	eor	ip, ip, r2, lsl #11
	and	lr, ip
	eor	r3, lr
	eor	r3, r9
	eor	r4, r4, r5, lsr #15
	eor	r4, r4, r2, lsl #17
	eor	r4, r4, r2, lsr #27
	eor	r4, r4, r3, lsl #5
	lsr	lr, r2, #6
	lsr	ip, r2, #21
	eor	lr, lr, r3, lsl #26
	eor	ip, ip, r3, lsl #11
	and	lr, ip
	eor	r4, lr
	eor	r4, r10
	eor	r5, r5, r2, lsr #15
	eor	r5, r5, r3, lsl #17
	eor	r5, r5, r3, lsr #27
	eor	r5, r5, r4, lsl #5
	lsr	lr, r3, #6
	lsr	ip, r3, #21
	eor	lr, lr, r4, lsl #26
	eor	ip, ip, r4, lsl #11
	and	lr, ip
	eor	r5, lr
	eor	r5, fp
	subs	r1, r1, #1
	bne	.L1921
.L1922:
	str	r2, [r0, #0]
	str	r3, [r0, #4]
	str	r4, [r0, #8]
	str	r5, [r0, #12]
	pop	{r4, r5, r6, r7, r8, r9, r10, fp, pc}
	.size	tinyjambu_permutation_192, .-tinyjambu_permutation_192

#endif
