/*
 * src/common/x25519.c - X25519 (RFC 7748): the Montgomery ladder over GF(2^255 - 19).
 *
 * A field element is ten unsigned 32-bit limbs of alternately 26 and 25 bits; limb i holds the
 * bits from ceil(25.5 i). Limbs are unsigned so that every shift and carry is defined behaviour,
 * and a subtraction adds 2p first so that it never goes below zero. With the bounds below, every
 * limb fits in 32 bits and a column of a product (ten 32 x 32-bit products, each scaled by at
 * most 38) stays under 2^63: portable C with 64-bit products and no 128-bit type.
 *
 * Nothing here branches on, or indexes memory by, a secret: the only branches are on loop
 * counters and on the bits of the public exponent p - 2.
 */
#include "holywisp/ecc.h"
#include "holywisp/sys.h"

#include <stddef.h>
#include <string.h>

#define FE_LIMBS 10
#define MASK26   0x3ffffffu
#define MASK25   0x1ffffffu

typedef uint32_t fe[FE_LIMBS];

// The bit at which each limb starts: ceil(25.5 i).
static const unsigned FE_OFF[FE_LIMBS] = {0, 26, 51, 77, 102, 128, 153, 179, 204, 230};

// 2p in limb form, added before a subtraction. Each limb of it is at least the matching limb of
// a carried element (fe_carry's bounds), so f + 2p - g never wraps.
static const uint32_t FE_2P[FE_LIMBS] = {
    2 * (MASK26 - 18), 2 * MASK25, 2 * MASK26, 2 * MASK25, 2 * MASK26,
    2 * MASK25,        2 * MASK26, 2 * MASK25, 2 * MASK26, 2 * MASK25,
};

static uint32_t limb_mask(unsigned i) {
	return (i & 1) ? MASK25 : MASK26;
}

static uint32_t load32_le(const uint8_t *p) {
	return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

// The 255 low bits of s; bit 255 is ignored, as RFC 7748 section 5 says for u. Every limb lies
// within four bytes of s (its start bit modulo 8 plus its width is at most 32).
static void fe_load(fe h, const uint8_t s[32]) {
	for (unsigned i = 0; i < FE_LIMBS; i++) h[i] = (load32_le(s + FE_OFF[i] / 8) >> (FE_OFF[i] % 8)) & limb_mask(i);
}

// h = t with every limb brought back to its width (limb 1 may exceed it by at most 2^17). The
// limbs of t must be under 2^63.
static void fe_carry(fe h, uint64_t t[FE_LIMBS]) {
	uint64_t c;
	for (unsigned i = 0; i < FE_LIMBS - 1; i++) {
		c = t[i] >> (26 - (i & 1));
		t[i] &= limb_mask(i);
		t[i + 1] += c;
	}
	c = t[9] >> 25;
	t[9] &= MASK25;
	t[0] += 19 * c;
	c = t[0] >> 26;
	t[0] &= MASK26;
	t[1] += c;
	for (unsigned i = 0; i < FE_LIMBS; i++) h[i] = (uint32_t)t[i];
}

static void fe_copy(fe h, const fe f) {
	memcpy(h, f, sizeof(fe));
}

static void fe_set(fe h, uint32_t v) {
	memset(h, 0, sizeof(fe));
	h[0] = v;
}

// f + g, not carried. Operands are carried elements, so each limb of the sum is under 2^27.1.
static void fe_add(fe h, const fe f, const fe g) {
	for (unsigned i = 0; i < FE_LIMBS; i++) h[i] = f[i] + g[i];
}

// f - g, not carried. g must be carried; each limb of the result is under 3 * 2^26.
static void fe_sub(fe h, const fe f, const fe g) {
	for (unsigned i = 0; i < FE_LIMBS; i++) h[i] = f[i] + FE_2P[i] - g[i];
}

// f * g, carried. Operands are sums or differences of carried elements (limbs under 3 * 2^26 for
// an even limb, 3 * 2^25 for an odd one). The product of limbs i and j lands at limb i + j, times
// 19 when it passes limb 9 (2^255 = 19 mod p) and times 2 when i and j are both odd (their start
// bits add up to one more than limb i + j's). So limb k is the sum over i of f_i * gx[k - i],
// where gx extends g below 0 by 19 g, and f_i is doubled for odd i exactly when k is even. The
// worst column sums to under 2^62.4.
static void fe_mul(fe h, const fe f, const fe g) {
	// gr[9 - k + i] = gx[9 + k - i], gx[9 + m] = g[m] for m >= 0, 19 g[m + 10] for m < 0, so that
	// limb k is a dot product of f (or f2) with ten consecutive entries of gr.
	uint32_t gr[2 * FE_LIMBS - 1];
	uint32_t f2[FE_LIMBS];
	for (unsigned j = 0; j < FE_LIMBS; j++) {
		gr[FE_LIMBS - 1 - j] = g[j];
		if (j) gr[2 * FE_LIMBS - 1 - j] = 19 * g[j];
		f2[j] = f[j] << (j & 1);
	}
	uint64_t t[FE_LIMBS];
	for (unsigned k = 0; k < FE_LIMBS; k++) {
		const uint32_t *ff = (k & 1) ? f : f2;
		const uint32_t *gk = gr + FE_LIMBS - 1 - k;
		uint64_t sum = 0;
		for (unsigned i = 0; i < FE_LIMBS; i++) sum += (uint64_t)ff[i] * gk[i];
		t[k] = sum;
	}
	fe_carry(h, t);
}

// f * f, carried: fe_mul's columns, with each product of two different limbs made once and
// doubled, 55 multiplies where fe_mul makes 100. The operand bounds are fe_mul's, and so is every
// column's sum (the worst, limb 0, is under 2^62.2). An even limb is under 3 * 2^26 and an odd
// one under 3 * 2^25, so 19 times an even limb and 38 times an odd one still fit in 32 bits.
static void fe_sq(fe h, const fe f) {
	const uint64_t f0 = f[0], f1 = f[1], f2 = f[2], f3 = f[3], f4 = f[4];
	const uint64_t f5 = f[5], f6 = f[6], f7 = f[7], f8 = f[8], f9 = f[9];
	const uint64_t f0_2 = 2 * f0, f1_2 = 2 * f1, f2_2 = 2 * f2, f3_2 = 2 * f3, f4_2 = 2 * f4;
	const uint64_t f5_2 = 2 * f5, f6_2 = 2 * f6, f7_2 = 2 * f7;
	const uint64_t f5_38 = 38 * f5, f6_19 = 19 * f6, f7_38 = 38 * f7, f8_19 = 19 * f8, f9_38 = 38 * f9;
	uint64_t t[FE_LIMBS];
	t[0] = f0 * f0 + f1_2 * f9_38 + f2_2 * f8_19 + f3_2 * f7_38 + f4_2 * f6_19 + f5 * f5_38;
	t[1] = f0_2 * f1 + f2 * f9_38 + f3_2 * f8_19 + f4 * f7_38 + f5_2 * f6_19;
	t[2] = f0_2 * f2 + f1_2 * f1 + f3_2 * f9_38 + f4_2 * f8_19 + f5_2 * f7_38 + f6 * f6_19;
	t[3] = f0_2 * f3 + f1_2 * f2 + f4 * f9_38 + f5_2 * f8_19 + f6 * f7_38;
	t[4] = f0_2 * f4 + f1_2 * f3_2 + f2 * f2 + f5_2 * f9_38 + f6_2 * f8_19 + f7 * f7_38;
	t[5] = f0_2 * f5 + f1_2 * f4 + f2_2 * f3 + f6 * f9_38 + f7_2 * f8_19;
	t[6] = f0_2 * f6 + f1_2 * f5_2 + f2_2 * f4 + f3_2 * f3 + f7_2 * f9_38 + f8 * f8_19;
	t[7] = f0_2 * f7 + f1_2 * f6 + f2_2 * f5 + f3_2 * f4 + f8 * f9_38;
	t[8] = f0_2 * f8 + f1_2 * f7_2 + f2_2 * f6 + f3_2 * f5_2 + f4 * f4 + f9 * f9_38;
	t[9] = f0_2 * f9 + f1_2 * f8 + f2_2 * f7 + f3_2 * f6 + f4_2 * f5;
	fe_carry(h, t);
}

// h = f^(2^n).
static void fe_sq_n(fe h, const fe f, int n) {
	fe_sq(h, f);
	while (--n > 0) fe_sq(h, h);
}

// f * c for a small constant c (under 2^17), carried.
static void fe_mul_small(fe h, const fe f, uint32_t c) {
	uint64_t t[FE_LIMBS];
	for (unsigned i = 0; i < FE_LIMBS; i++) t[i] = (uint64_t)f[i] * c;
	fe_carry(h, t);
}

// z^(p - 2) = 1/z (0 for 0), p - 2 = 2^255 - 21, by the chain through z^(2^k - 1) for k = 5, 10,
// 20, 40, 50, 100, 200 and 250: 254 squarings and 11 multiplications whatever z is.
static void fe_invert(fe out, const fe z) {
	fe z2, z9, z11, a, b, c;
	fe_sq(z2, z);        // 2
	fe_sq_n(a, z2, 2);   // 8
	fe_mul(z9, a, z);    // 9
	fe_mul(z11, z9, z2); // 11
	fe_sq(a, z11);       // 22
	fe_mul(a, a, z9);    // 2^5 - 1
	fe_sq_n(b, a, 5);
	fe_mul(b, b, a); // 2^10 - 1
	fe_sq_n(c, b, 10);
	fe_mul(c, c, b); // 2^20 - 1
	fe_sq_n(a, c, 20);
	fe_mul(a, a, c); // 2^40 - 1
	fe_sq_n(a, a, 10);
	fe_mul(a, a, b); // 2^50 - 1
	fe_sq_n(b, a, 50);
	fe_mul(b, b, a); // 2^100 - 1
	fe_sq_n(c, b, 100);
	fe_mul(c, c, b); // 2^200 - 1
	fe_sq_n(c, c, 50);
	fe_mul(c, c, a);     // 2^250 - 1
	fe_sq_n(c, c, 5);    // 2^255 - 32
	fe_mul(out, c, z11); // 2^255 - 21
}

// The canonical encoding of a carried element h (value below 2^255 + 2^43, so below 2p): q is
// floor((h + 19) / 2^255), 1 exactly when h >= p, and h + 19q with bit 255 dropped is h - qp.
static void fe_store(uint8_t s[32], const fe f) {
	fe h;
	fe_copy(h, f);
	uint32_t q = (h[0] + 19) >> 26;
	for (unsigned i = 1; i < FE_LIMBS; i++) q = (h[i] + q) >> (26 - (i & 1));
	h[0] += 19 * q;
	for (unsigned i = 0; i < FE_LIMBS - 1; i++) {
		h[i + 1] += h[i] >> (26 - (i & 1));
		h[i] &= limb_mask(i);
	}
	h[9] &= MASK25;
	uint64_t acc = 0;
	unsigned bits = 0, o = 0;
	for (unsigned i = 0; i < FE_LIMBS; i++) {
		acc |= (uint64_t)h[i] << bits;
		bits += 26 - (i & 1);
		while (bits >= 8) {
			s[o++] = (uint8_t)acc;
			acc >>= 8;
			bits -= 8;
		}
	}
	s[o] = (uint8_t)acc; // the last 7 bits; bits == 7 here, o == 31
}

// Swaps f and g when swap is 1, leaves them when it is 0, with the same instructions either way.
static void fe_cswap(fe f, fe g, uint32_t swap) {
	uint32_t mask = 0u - swap;
	for (unsigned i = 0; i < FE_LIMBS; i++) {
		uint32_t x = mask & (f[i] ^ g[i]);
		f[i] ^= x;
		g[i] ^= x;
	}
}

static void wipe(void *p, size_t n) {
	volatile uint8_t *v = p;
	while (n--) *v++ = 0;
}

int hw_x25519(uint8_t out[HW_X25519_LEN], const uint8_t scalar[HW_X25519_LEN], const uint8_t point[HW_X25519_LEN]) {
	uint8_t k[32];
	memcpy(k, scalar, 32);
	k[0] &= 248;
	k[31] &= 127;
	k[31] |= 64;

	struct {
		fe x1, x2, z2, x3, z3, a, aa, b, bb, e, c, d, da, cb, t;
	} l;
	fe_load(l.x1, point);
	fe_set(l.x2, 1);
	fe_set(l.z2, 0);
	fe_copy(l.x3, l.x1);
	fe_set(l.z3, 1);
	uint32_t swap = 0;
	for (int i = 254; i >= 0; i--) {
		uint32_t bit = (uint32_t)(k[i >> 3] >> (i & 7)) & 1;
		swap ^= bit;
		fe_cswap(l.x2, l.x3, swap);
		fe_cswap(l.z2, l.z3, swap);
		swap = bit;
		fe_add(l.a, l.x2, l.z2);
		fe_sq(l.aa, l.a);
		fe_sub(l.b, l.x2, l.z2);
		fe_sq(l.bb, l.b);
		fe_sub(l.e, l.aa, l.bb);
		fe_add(l.c, l.x3, l.z3);
		fe_sub(l.d, l.x3, l.z3);
		fe_mul(l.da, l.d, l.a);
		fe_mul(l.cb, l.c, l.b);
		fe_add(l.t, l.da, l.cb);
		fe_sq(l.x3, l.t);
		fe_sub(l.t, l.da, l.cb);
		fe_sq(l.t, l.t);
		fe_mul(l.z3, l.x1, l.t);
		fe_mul(l.x2, l.aa, l.bb);
		fe_mul_small(l.t, l.e, 121665); // a24 = (486662 - 2) / 4
		fe_add(l.t, l.aa, l.t);
		fe_mul(l.z2, l.e, l.t);
	}
	fe_cswap(l.x2, l.x3, swap);
	fe_cswap(l.z2, l.z3, swap);
	fe_invert(l.z2, l.z2);
	fe_mul(l.x2, l.x2, l.z2);
	fe_store(out, l.x2);

	wipe(k, sizeof(k));
	wipe(&l, sizeof(l));
	uint8_t acc = 0;
	for (unsigned i = 0; i < HW_X25519_LEN; i++) acc |= out[i];
	return acc ? 0 : -1;
}

int hw_x25519_keygen(uint8_t priv[HW_X25519_LEN], uint8_t pub[HW_X25519_LEN]) {
	static const uint8_t base[HW_X25519_LEN] = {9};
	if (hw_sys_random(priv, HW_X25519_LEN) != 0) return -1;
	return hw_x25519(pub, priv, base);
}
