#include "tinyjambu-backend-select.h"
#if defined(TINYJAMBU_BACKEND_RISCV32I)
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

#ifdef __riscv_cmodel_pic
	.option	pic
#else
	.option	nopic
#endif
	.text

	.align	1
	.globl	tinyjambu_permutation_128
	.type	tinyjambu_permutation_128, @function
tinyjambu_permutation_128:
	lw	a2, (a0)
	lw	a3, 4(a0)
	lw	a4, 8(a0)
	lw	a5, 12(a0)
	lw	a6, 16(a0)
	lw	a7, 20(a0)
	lw	t4, 24(a0)
	lw	t5, 28(a0)
.L1281:
	srli	t0, a3, 15
	srli	t1, a4, 27
	slli	t2, a4, 17
	slli	t3, a5, 5
	xor	a2, a2, t0
	xor	a2, a2, t1
	xor	a2, a2, t2
	xor	a2, a2, t3
	srli	t2, a4, 6
	srli	t3, a4, 21
	slli	t0, a5, 26
	slli	t1, a5, 11
	xor	t2, t2, t0
	xor	t3, t3, t1
	and	t2, t2, t3
	xor	a2, a2, a6
	xor	a2, a2, t2
	srli	t0, a4, 15
	srli	t1, a5, 27
	slli	t2, a5, 17
	slli	t3, a2, 5
	xor	a3, a3, t0
	xor	a3, a3, t1
	xor	a3, a3, t2
	xor	a3, a3, t3
	srli	t2, a5, 6
	srli	t3, a5, 21
	slli	t0, a2, 26
	slli	t1, a2, 11
	xor	t2, t2, t0
	xor	t3, t3, t1
	and	t2, t2, t3
	xor	a3, a3, a7
	xor	a3, a3, t2
	srli	t0, a5, 15
	srli	t1, a2, 27
	slli	t2, a2, 17
	slli	t3, a3, 5
	xor	a4, a4, t0
	xor	a4, a4, t1
	xor	a4, a4, t2
	xor	a4, a4, t3
	srli	t2, a2, 6
	srli	t3, a2, 21
	slli	t0, a3, 26
	slli	t1, a3, 11
	xor	t2, t2, t0
	xor	t3, t3, t1
	and	t2, t2, t3
	xor	a4, a4, t4
	xor	a4, a4, t2
	srli	t0, a2, 15
	srli	t1, a3, 27
	slli	t2, a3, 17
	slli	t3, a4, 5
	xor	a5, a5, t0
	xor	a5, a5, t1
	xor	a5, a5, t2
	xor	a5, a5, t3
	srli	t2, a3, 6
	srli	t3, a3, 21
	slli	t0, a4, 26
	slli	t1, a4, 11
	xor	t2, t2, t0
	xor	t3, t3, t1
	and	t2, t2, t3
	xor	a5, a5, t5
	xor	a5, a5, t2
	addi	a1, a1, -1
	bne	a1, zero, .L1281
.L1282:
	sw	a2, (a0)
	sw	a3, 4(a0)
	sw	a4, 8(a0)
	sw	a5, 12(a0)
	ret
	.size	tinyjambu_permutation_128, .-tinyjambu_permutation_128

#endif
