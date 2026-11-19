/*
 * holywisp/aead.h implementation: AES-128 (FIPS 197) bitsliced, GCM (SP 800-38D) over a
 * constant-time carry-less multiply, ChaCha20 and Poly1305 (RFC 8439).
 *
 * Nothing here indexes memory or branches on a secret. AES has no tables: four blocks at a time
 * are spread over eight 64-bit words, one bit of every byte per word, and the S-box is a circuit
 * of 113 gates (Boyar and Peralta's) over those words. GHASH multiplies with integer multiplies
 * whose operands have holes between their bits, so that carries never reach a bit that is kept.
 * ChaCha20 runs four or eight blocks at once in the compiler's generic vectors, one block per
 * lane, and Poly1305 four blocks at once over 26-bit limbs, so that every product is a 32x32->64
 * multiply on any target. On x86-64 both kernels are also built for AVX2 and picked at run time,
 * and AES-128-GCM for AES-NI and PCLMULQDQ: the same blocks and the same GHASH, on the CPU's
 * instructions, which are constant-time too.
 */
#include "holywisp/aead.h"

#include "holywisp/hw.h"

#include "aead_internal.h"

#include <string.h>

// The vector kernels load and store keystream words with memcpy: every target is little-endian.
_Static_assert(__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__, "aead.c assumes a little-endian target");

static uint32_t le32(const uint8_t *p) {
	return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static void put_le32(uint8_t *p, uint32_t v) {
	p[0] = (uint8_t)v;
	p[1] = (uint8_t)(v >> 8);
	p[2] = (uint8_t)(v >> 16);
	p[3] = (uint8_t)(v >> 24);
}

static uint64_t le64(const uint8_t *p) {
	return (uint64_t)le32(p) | (uint64_t)le32(p + 4) << 32;
}

static void put_le64(uint8_t *p, uint64_t v) {
	put_le32(p, (uint32_t)v);
	put_le32(p + 4, (uint32_t)(v >> 32));
}

static uint32_t be32(const uint8_t *p) {
	return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | (uint32_t)p[3];
}

static void put_be32(uint8_t *p, uint32_t v) {
	p[0] = (uint8_t)(v >> 24);
	p[1] = (uint8_t)(v >> 16);
	p[2] = (uint8_t)(v >> 8);
	p[3] = (uint8_t)v;
}

static uint64_t be64(const uint8_t *p) {
	return (uint64_t)be32(p) << 32 | be32(p + 4);
}

static void put_be64(uint8_t *p, uint64_t v) {
	put_be32(p, (uint32_t)(v >> 32));
	put_be32(p + 4, (uint32_t)v);
}

int hw_ct_equal(const void *a, const void *b, size_t n) {
	const uint8_t *x = a, *y = b;
	uint32_t acc = 0;
	for (size_t i = 0; i < n; i++) acc |= (uint32_t)(x[i] ^ y[i]);
	return (int)(1 & ((acc - 1) >> 8)); // acc is at most 0xff: only 0 - 1 sets bit 8
}

// memset through a volatile pointer: the compiler cannot know what it calls, so it cannot drop a
// wipe of a buffer that is about to go out of scope (both GCC and clang removed the plain memsets
// of the one-time Poly1305 key and keystream below). It runs at memset's speed.
static void *(*const volatile WIPE_FN)(void *, int, size_t) = memset;
static void wipe(void *p, size_t n) {
	WIPE_FN(p, 0, n);
}

// AES-128 and GCM on the CPU's instructions where it has them (x86-64's AES-NI and PCLMULQDQ),
// defined with the vector kernels below. aes_hw_cpu: the CPU has them; aes_hw: they are to be
// used (not when a test forces the base kernels). gcm_hw_init fills the table's hardware part,
// which the CPU decides alone, so that a table made while the base kernels were forced still
// works once they are not.
static int aes_hw_cpu(void);
static int aes_hw(void);
static void aes_hw_encrypt(const hw_aes128 *k, const uint8_t in[16], uint8_t out[16]);
static void gcm_hw_init(hw_aes128gcm *g);
static void gcm_hw_seal(const hw_aes128gcm *g, const uint8_t nonce[HW_AEAD_NONCE], const uint8_t *aad, size_t aad_len,
                        const uint8_t *in, size_t len, uint8_t *out);
static int gcm_hw_open(const hw_aes128gcm *g, const uint8_t nonce[HW_AEAD_NONCE], const uint8_t *aad, size_t aad_len,
                       const uint8_t *in, size_t len, uint8_t *out);

// ---- AES-128, bitsliced -------------------------------------------------------------------
// Up to four blocks in q[0..7]: bit i of byte p of block b is bit 16 * b + p of q[i]. A byte's
// position p is 4 * column + row, the order of FIPS 197's input array, so a column is a nibble.

// The S-box on every byte position at once: Boyar and Peralta's circuit (2009), a linear layer
// into the GF(2^4) inversion, its 32 AND gates, and a linear layer out. u0 is the top bit.
static void aes_sbox(uint64_t q[8]) {
	uint64_t u0 = q[7], u1 = q[6], u2 = q[5], u3 = q[4], u4 = q[3], u5 = q[2], u6 = q[1], u7 = q[0];

	uint64_t t1 = u0 ^ u3, t2 = u0 ^ u5, t3 = u0 ^ u6, t4 = u3 ^ u5, t5 = u4 ^ u6;
	uint64_t t6 = t1 ^ t5, t7 = u1 ^ u2, t8 = u7 ^ t6, t9 = u7 ^ t7, t10 = t6 ^ t7;
	uint64_t t11 = u1 ^ u5, t12 = u2 ^ u5, t13 = t3 ^ t4, t14 = t6 ^ t11, t15 = t5 ^ t11;
	uint64_t t16 = t5 ^ t12, t17 = t9 ^ t16, t18 = u3 ^ u7, t19 = t7 ^ t18, t20 = t1 ^ t19;
	uint64_t t21 = u6 ^ u7, t22 = t7 ^ t21, t23 = t2 ^ t22, t24 = t2 ^ t10, t25 = t20 ^ t17;
	uint64_t t26 = t3 ^ t16, t27 = t1 ^ t12;

	uint64_t m1 = t13 & t6, m2 = t23 & t8, m3 = t14 ^ m1, m4 = t19 & u7, m5 = m4 ^ m1;
	uint64_t m6 = t3 & t16, m7 = t22 & t9, m8 = t26 ^ m6, m9 = t20 & t17, m10 = m9 ^ m6;
	uint64_t m11 = t1 & t15, m12 = t4 & t27, m13 = m12 ^ m11, m14 = t2 & t10, m15 = m14 ^ m11;
	uint64_t m16 = m3 ^ m2, m17 = m5 ^ t24, m18 = m8 ^ m7, m19 = m10 ^ m15, m20 = m16 ^ m13;
	uint64_t m21 = m17 ^ m15, m22 = m18 ^ m13, m23 = m19 ^ t25, m24 = m22 ^ m23, m25 = m22 & m20;
	uint64_t m26 = m21 ^ m25, m27 = m20 ^ m21, m28 = m23 ^ m25, m29 = m28 & m27, m30 = m26 & m24;
	uint64_t m31 = m20 & m23, m32 = m27 & m31, m33 = m27 ^ m25, m34 = m21 & m22, m35 = m24 & m34;
	uint64_t m36 = m24 ^ m25, m37 = m21 ^ m29, m38 = m32 ^ m33, m39 = m23 ^ m30, m40 = m35 ^ m36;
	uint64_t m41 = m38 ^ m40, m42 = m37 ^ m39, m43 = m37 ^ m38, m44 = m39 ^ m40, m45 = m42 ^ m41;
	uint64_t m46 = m44 & t6, m47 = m40 & t8, m48 = m39 & u7, m49 = m43 & t16, m50 = m38 & t9;
	uint64_t m51 = m37 & t17, m52 = m42 & t15, m53 = m45 & t27, m54 = m41 & t10, m55 = m44 & t13;
	uint64_t m56 = m40 & t23, m57 = m39 & t19, m58 = m43 & t3, m59 = m38 & t22, m60 = m37 & t20;
	uint64_t m61 = m42 & t1, m62 = m45 & t4, m63 = m41 & t2;

	uint64_t l0 = m61 ^ m62, l1 = m50 ^ m56, l2 = m46 ^ m48, l3 = m47 ^ m55, l4 = m54 ^ m58;
	uint64_t l5 = m49 ^ m61, l6 = m62 ^ l5, l7 = m46 ^ l3, l8 = m51 ^ m59, l9 = m52 ^ m53;
	uint64_t l10 = m53 ^ l4, l11 = m60 ^ l2, l12 = m48 ^ m51, l13 = m50 ^ l0, l14 = m52 ^ m61;
	uint64_t l15 = m55 ^ l1, l16 = m56 ^ l0, l17 = m57 ^ l1, l18 = m58 ^ l8, l19 = m63 ^ l4;
	uint64_t l20 = l0 ^ l1, l21 = l1 ^ l7, l22 = l3 ^ l12, l23 = l18 ^ l2, l24 = l15 ^ l9;
	uint64_t l25 = l6 ^ l10, l26 = l7 ^ l9, l27 = l8 ^ l10, l28 = l11 ^ l14, l29 = l11 ^ l17;

	q[7] = l6 ^ l24;
	q[6] = ~(l16 ^ l26);
	q[5] = ~(l19 ^ l28);
	q[4] = l6 ^ l21;
	q[3] = l20 ^ l22;
	q[2] = l25 ^ l29;
	q[1] = ~(l13 ^ l27);
	q[0] = ~(l6 ^ l23);
}

// Row r of every column moves r columns left: within a 16-bit state, the bits of row r (one per
// nibble) rotate down by 4 * r.
static void aes_shift_rows(uint64_t q[8]) {
	for (int i = 0; i < 8; i++) {
		uint64_t x = q[i];
		q[i] = (x & 0x1111111111111111) | ((x >> 4) & 0x0222022202220222) | ((x << 12) & 0x2000200020002000) |
		       ((x >> 8) & 0x0044004400440044) | ((x << 8) & 0x4400440044004400) | ((x >> 12) & 0x0008000800080008) |
		       ((x << 4) & 0x8880888088808880);
	}
}

// Row r + 1 (r + 2) of the same column, in row r's place: a rotation within each nibble.
static uint64_t aes_rot1(uint64_t x) {
	return ((x >> 1) & 0x7777777777777777) | ((x << 3) & 0x8888888888888888);
}

static uint64_t aes_rot2(uint64_t x) {
	return ((x >> 2) & 0x3333333333333333) | ((x << 2) & 0xcccccccccccccccc);
}

// out[r] = 2 a[r] + 3 a[r + 1] + a[r + 2] + a[r + 3] = 2 (a[r] + a[r + 1]) + a[r + 1] + a[r + 2] + a[r + 3].
static void aes_mix_columns(uint64_t q[8]) {
	uint64_t t[8], s[8];
	for (int i = 0; i < 8; i++) {
		uint64_t r1 = aes_rot1(q[i]);
		t[i] = q[i] ^ r1;
		s[i] = r1 ^ aes_rot2(t[i]);
	}
	// Doubling in GF(2^8): every bit moves up one plane, and the top one comes back as 0x1b.
	q[0] = s[0] ^ t[7];
	q[1] = s[1] ^ t[0] ^ t[7];
	q[2] = s[2] ^ t[1];
	q[3] = s[3] ^ t[2] ^ t[7];
	q[4] = s[4] ^ t[3] ^ t[7];
	q[5] = s[5] ^ t[4];
	q[6] = s[6] ^ t[5];
	q[7] = s[7] ^ t[6];
}

// An 8x8 bit transpose: bit 8 * r + c moves to bit 8 * c + r.
static uint64_t transpose8(uint64_t x) {
	uint64_t t = (x ^ (x >> 7)) & 0x00aa00aa00aa00aa;
	x ^= t ^ (t << 7);
	t = (x ^ (x >> 14)) & 0x0000cccc0000cccc;
	x ^= t ^ (t << 14);
	t = (x ^ (x >> 28)) & 0x00000000f0f0f0f0;
	return x ^ t ^ (t << 28);
}

// ORs block `in` into state b of q (which the caller zeroed).
static void aes_load(uint64_t q[8], const uint8_t in[16], int b) {
	uint64_t lo = transpose8(le64(in)), hi = transpose8(le64(in + 8));
	for (int i = 0; i < 8; i++) {
		uint64_t unit = ((lo >> (8 * i)) & 0xff) | ((hi >> (8 * i)) & 0xff) << 8;
		q[i] |= unit << (16 * b);
	}
}

static void aes_store(const uint64_t q[8], uint8_t out[16], int b) {
	uint64_t lo = 0, hi = 0;
	for (int i = 0; i < 8; i++) {
		uint64_t unit = (q[i] >> (16 * b)) & 0xffff;
		lo |= (unit & 0xff) << (8 * i);
		hi |= (unit >> 8) << (8 * i);
	}
	put_le64(out, transpose8(lo));
	put_le64(out + 8, transpose8(hi));
}

// The round keys in the bitsliced layout, each repeated in all four states.
typedef struct {
	uint64_t k[11][8];
} aes_bs_keys;

static void aes_bs_expand(const hw_aes128 *k, aes_bs_keys *bk) {
	for (int r = 0; r < 11; r++) {
		uint8_t b[16];
		for (int j = 0; j < 4; j++) put_be32(b + 4 * j, k->rk[4 * r + j]);
		uint64_t q[8] = {0};
		aes_load(q, b, 0);
		for (int i = 0; i < 8; i++) bk->k[r][i] = q[i] * 0x0001000100010001;
	}
}

static void aes_add_round_key(uint64_t q[8], const uint64_t k[8]) {
	for (int i = 0; i < 8; i++) q[i] ^= k[i];
}

static void aes_bs_encrypt(const aes_bs_keys *bk, uint64_t q[8]) {
	aes_add_round_key(q, bk->k[0]);
	for (int r = 1; r < 10; r++) {
		aes_sbox(q);
		aes_shift_rows(q);
		aes_mix_columns(q);
		aes_add_round_key(q, bk->k[r]);
	}
	aes_sbox(q);
	aes_shift_rows(q);
	aes_add_round_key(q, bk->k[10]);
}

// SubWord of the key schedule, through the same circuit: byte j of w in bit j of each plane.
static uint32_t aes_sub_word(uint32_t w) {
	uint64_t q[8];
	for (int i = 0; i < 8; i++) {
		q[i] = 0;
		for (int j = 0; j < 4; j++) q[i] |= (uint64_t)((w >> (8 * j + i)) & 1) << j;
	}
	aes_sbox(q);
	uint32_t r = 0;
	for (int i = 0; i < 8; i++) {
		for (int j = 0; j < 4; j++) r |= (uint32_t)((q[i] >> j) & 1) << (8 * j + i);
	}
	return r;
}

void hw_aes128_init(hw_aes128 *k, const uint8_t key[16]) {
	static const uint8_t rcon[10] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};
	for (int i = 0; i < 4; i++) k->rk[i] = be32(key + 4 * i);
	for (int i = 4; i < 44; i++) {
		uint32_t t = k->rk[i - 1];
		if (i % 4 == 0) t = aes_sub_word(t << 8 | t >> 24) ^ (uint32_t)rcon[i / 4 - 1] << 24;
		k->rk[i] = k->rk[i - 4] ^ t;
	}
}

void hw_aes128_encrypt(const hw_aes128 *k, const uint8_t in[16], uint8_t out[16]) {
	if (aes_hw()) {
		aes_hw_encrypt(k, in, out);
		return;
	}
	aes_bs_keys bk;
	aes_bs_expand(k, &bk);
	uint64_t q[8] = {0};
	aes_load(q, in, 0);
	aes_bs_encrypt(&bk, q);
	aes_store(q, out, 0);
}

// ---- GCM ----------------------------------------------------------------------------------
// htable[0] and htable[1] hold H as two big-endian halves, htable[2] their XOR (Karatsuba's
// middle operand). There is no table: the multiply below is constant-time. Where the CPU has
// AES-NI, htable[4..19] hold H^1 to H^8 for its kernel (GCM_HW_POWERS); the rest is zero.
#define GCM_HW_POWERS 4

// The carry-less product of two 32-bit words. Each operand is split into four with three-bit
// holes, so a column of any partial product sums at most eight bits and its carries stay in the
// holes, which the final mask drops.
static uint64_t bmul32(uint32_t x, uint32_t y) {
	uint64_t x0 = x & 0x11111111, x1 = x & 0x22222222, x2 = x & 0x44444444, x3 = x & 0x88888888;
	uint64_t y0 = y & 0x11111111, y1 = y & 0x22222222, y2 = y & 0x44444444, y3 = y & 0x88888888;
	uint64_t z0 = (x0 * y0) ^ (x1 * y3) ^ (x2 * y2) ^ (x3 * y1);
	uint64_t z1 = (x0 * y1) ^ (x1 * y0) ^ (x2 * y3) ^ (x3 * y2);
	uint64_t z2 = (x0 * y2) ^ (x1 * y1) ^ (x2 * y0) ^ (x3 * y3);
	uint64_t z3 = (x0 * y3) ^ (x1 * y2) ^ (x2 * y1) ^ (x3 * y0);
	return (z0 & 0x1111111111111111) | (z1 & 0x2222222222222222) | (z2 & 0x4444444444444444) |
	       (z3 & 0x8888888888888888);
}

// 64 x 64 -> 128 carry-less, Karatsuba over the 32-bit halves.
static void clmul64(uint64_t a, uint64_t b, uint64_t *hi, uint64_t *lo) {
	uint32_t a0 = (uint32_t)a, a1 = (uint32_t)(a >> 32), b0 = (uint32_t)b, b1 = (uint32_t)(b >> 32);
	uint64_t l = bmul32(a0, b0), h = bmul32(a1, b1), m = bmul32(a0 ^ a1, b0 ^ b1) ^ l ^ h;
	*lo = l ^ (m << 32);
	*hi = h ^ (m >> 32);
}

// y = y * H in GF(2^128) with GCM's reflected bit order (y[0] is bytes 0..7, big-endian). The
// carry-less product of reflected operands is the reflected product shifted right by one bit;
// it is shifted back, and its upper half folded down by x^128 = x^7 + x^2 + x + 1, which in
// reflected order is a right shift by 7, 2 and 1.
static void ghash_mul(uint64_t y[2], const uint64_t *ht) {
	uint64_t l1, l0, h1, h0, m1, m0;
	clmul64(y[1], ht[1], &l1, &l0);
	clmul64(y[0], ht[0], &h1, &h0);
	clmul64(y[0] ^ y[1], ht[2], &m1, &m0);
	m1 ^= l1 ^ h1;
	m0 ^= l0 ^ h0;
	uint64_t z3 = h1, z2 = h0 ^ m1, z1 = l1 ^ m0, z0 = l0;
	z3 = z3 << 1 | z2 >> 63;
	z2 = z2 << 1 | z1 >> 63;
	z1 = z1 << 1 | z0 >> 63;
	z0 <<= 1;
	uint64_t s = (z0 << 63) ^ (z0 << 62) ^ (z0 << 57); // the bits the first fold pushes past x^127
	y[0] = z3 ^ z1 ^ (z1 >> 1) ^ (z1 >> 2) ^ (z1 >> 7) ^ s ^ (s >> 1) ^ (s >> 2) ^ (s >> 7);
	y[1] = z2 ^ z0 ^ (z0 >> 1 | z1 << 63) ^ (z0 >> 2 | z1 << 62) ^ (z0 >> 7 | z1 << 57);
}

// Absorbs len bytes, the last block padded with zeros.
static void ghash_update(uint64_t y[2], const uint64_t *ht, const uint8_t *p, size_t len) {
	for (; len >= 16; p += 16, len -= 16) {
		y[0] ^= be64(p);
		y[1] ^= be64(p + 8);
		ghash_mul(y, ht);
	}
	if (len) {
		uint8_t b[16] = {0};
		memcpy(b, p, len);
		ghash_update(y, ht, b, 16);
	}
}

void hw_aes128gcm_init(hw_aes128gcm *g, const uint8_t key[16]) {
	static const uint8_t zero[16] = {0};
	uint8_t h[16];
	hw_aes128_init(&g->aes, key);
	hw_aes128_encrypt(&g->aes, zero, h);
	memset(g->htable, 0, sizeof g->htable);
	g->htable[0] = be64(h);
	g->htable[1] = be64(h + 8);
	g->htable[2] = g->htable[0] ^ g->htable[1];
	if (aes_hw_cpu()) gcm_hw_init(g);
}

// CTR from J0 = nonce || 1: the first keystream block (E(J0), which masks the tag) goes to
// tag_mask, the rest is XORed from in to out.
static void gcm_ctr(const hw_aes128gcm *g, const uint8_t nonce[HW_AEAD_NONCE], const uint8_t *in, size_t len,
                    uint8_t *out, uint8_t tag_mask[16]) {
	aes_bs_keys bk;
	aes_bs_expand(&g->aes, &bk);
	uint8_t ctr[16], ks[64];
	memcpy(ctr, nonce, HW_AEAD_NONCE);
	uint32_t n = 1;
	size_t off = 0;
	int first = 1;
	while (first || off < len) {
		uint64_t q[8] = {0};
		for (int b = 0; b < 4; b++) {
			put_be32(ctr + 12, n++);
			aes_load(q, ctr, b);
		}
		aes_bs_encrypt(&bk, q);
		for (int b = 0; b < 4; b++) aes_store(q, ks + 16 * b, b);
		const uint8_t *k = ks;
		size_t avail = 64;
		if (first) {
			memcpy(tag_mask, ks, 16);
			k += 16;
			avail -= 16;
			first = 0;
		}
		size_t take = HW_MIN(avail, len - off);
		for (size_t i = 0; i < take; i++) out[off + i] = in[off + i] ^ k[i];
		off += take;
	}
}

static void gcm_tag(const hw_aes128gcm *g, const uint8_t *aad, size_t aad_len, const uint8_t *ct, size_t len,
                    const uint8_t tag_mask[16], uint8_t tag[16]) {
	uint64_t y[2] = {0, 0};
	ghash_update(y, g->htable, aad, aad_len);
	ghash_update(y, g->htable, ct, len);
	y[0] ^= (uint64_t)aad_len * 8;
	y[1] ^= (uint64_t)len * 8;
	ghash_mul(y, g->htable);
	put_be64(tag, y[0]);
	put_be64(tag + 8, y[1]);
	for (int i = 0; i < 16; i++) tag[i] ^= tag_mask[i];
}

void hw_aes128gcm_seal(const hw_aes128gcm *g, const uint8_t nonce[HW_AEAD_NONCE], const uint8_t *aad, size_t aad_len,
                       const uint8_t *in, size_t len, uint8_t *out) {
	if (aes_hw()) {
		gcm_hw_seal(g, nonce, aad, aad_len, in, len, out);
		return;
	}
	uint8_t mask[16];
	gcm_ctr(g, nonce, in, len, out, mask);
	gcm_tag(g, aad, aad_len, out, len, mask, out + len);
}

int hw_aes128gcm_open(const hw_aes128gcm *g, const uint8_t nonce[HW_AEAD_NONCE], const uint8_t *aad, size_t aad_len,
                      const uint8_t *in, size_t len, uint8_t *out) {
	if (len < HW_AEAD_TAG) return -1;
	if (aes_hw()) return gcm_hw_open(g, nonce, aad, aad_len, in, len - HW_AEAD_TAG, out);
	len -= HW_AEAD_TAG;
	uint8_t want[16], mask[16];
	memcpy(want, in + len, 16); // in place, out may be in; the tag is past what is decrypted
	uint64_t y[2] = {0, 0};
	ghash_update(y, g->htable, aad, aad_len);
	ghash_update(y, g->htable, in, len);
	y[0] ^= (uint64_t)aad_len * 8;
	y[1] ^= (uint64_t)len * 8;
	ghash_mul(y, g->htable);
	gcm_ctr(g, nonce, in, len, out, mask);
	uint8_t tag[16];
	put_be64(tag, y[0]);
	put_be64(tag + 8, y[1]);
	for (int i = 0; i < 16; i++) tag[i] ^= mask[i];
	if (!hw_ct_equal(tag, want, 16)) {
		if (len) memset(out, 0, len);
		return -1;
	}
	return 0;
}

// ---- ChaCha20 and Poly1305: the scalar code and the vector kernels ------------------------
#define CHACHA_ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define CHACHA_QR(a, b, c, d)       \
	do {                            \
		(a) += (b);                 \
		(d) ^= (a);                 \
		(d) = CHACHA_ROTL((d), 16); \
		(c) += (d);                 \
		(b) ^= (c);                 \
		(b) = CHACHA_ROTL((b), 12); \
		(a) += (b);                 \
		(d) ^= (a);                 \
		(d) = CHACHA_ROTL((d), 8);  \
		(c) += (d);                 \
		(b) ^= (c);                 \
		(b) = CHACHA_ROTL((b), 7);  \
	} while (0)
#define CHACHA_DOUBLE_ROUND(x)                       \
	do {                                             \
		CHACHA_QR((x)[0], (x)[4], (x)[8], (x)[12]);  \
		CHACHA_QR((x)[1], (x)[5], (x)[9], (x)[13]);  \
		CHACHA_QR((x)[2], (x)[6], (x)[10], (x)[14]); \
		CHACHA_QR((x)[3], (x)[7], (x)[11], (x)[15]); \
		CHACHA_QR((x)[0], (x)[5], (x)[10], (x)[15]); \
		CHACHA_QR((x)[1], (x)[6], (x)[11], (x)[12]); \
		CHACHA_QR((x)[2], (x)[7], (x)[8], (x)[13]);  \
		CHACHA_QR((x)[3], (x)[4], (x)[9], (x)[14]);  \
	} while (0)

static void chacha_init(uint32_t st[16], const uint8_t key[32], uint32_t counter, const uint8_t nonce[HW_AEAD_NONCE]) {
	st[0] = 0x61707865; // "expand 32-byte k"
	st[1] = 0x3320646e;
	st[2] = 0x79622d32;
	st[3] = 0x6b206574;
	for (int i = 0; i < 8; i++) st[4 + i] = le32(key + 4 * i);
	st[12] = counter;
	for (int i = 0; i < 3; i++) st[13 + i] = le32(nonce + 4 * i);
}

// One block of keystream XORed into n <= 64 bytes.
static void chacha_block_xor(const uint32_t st[16], const uint8_t *in, uint8_t *out, size_t n) {
	uint32_t x[16];
	memcpy(x, st, sizeof x);
	for (int i = 0; i < 10; i++) CHACHA_DOUBLE_ROUND(x);
	uint8_t ks[64];
	for (int i = 0; i < 16; i++) put_le32(ks + 4 * i, x[i] + st[i]);
	for (size_t i = 0; i < n; i++) out[i] = in[i] ^ ks[i];
}

typedef uint32_t u32x8 __attribute__((vector_size(32)));
typedef uint32_t u32x4 __attribute__((vector_size(16)));
typedef uint64_t u64x4 __attribute__((vector_size(32)));

#define CHACHA_V8_BLOCKS 8
#define CHACHA_V8_BYTES  (64 * CHACHA_V8_BLOCKS)

static inline __attribute__((always_inline)) void chacha_piece_xor(u32x4 v, const uint8_t *in, uint8_t *out) {
	u32x4 m;
	memcpy(&m, in, 16);
	m ^= v;
	memcpy(out, &m, 16);
}

// Four blocks of keystream XORed from in to out (256 bytes each), lane j of x[i] being word i of
// block j. The words leave as 16-byte pieces: a 4x4 transpose of four vectors gives four
// consecutive words of each block. Without AVX2 this is the kernel, twice per eight blocks.
static inline __attribute__((always_inline)) void chacha_v4_run(const uint32_t st[16], const uint8_t *in,
                                                                uint8_t *out) {
	u32x4 x[16];
	for (int i = 0; i < 16; i++) x[i] = (u32x4){0} + st[i];
	x[12] += (u32x4){0, 1, 2, 3};
	for (int i = 0; i < 10; i++) CHACHA_DOUBLE_ROUND(x);
	for (int i = 0; i < 16; i++) x[i] += st[i];
	x[12] += (u32x4){0, 1, 2, 3};
	for (int g = 0; g < 4; g++) {
		u32x4 a = x[4 * g], b = x[4 * g + 1], c = x[4 * g + 2], d = x[4 * g + 3];
		u32x4 t0 = __builtin_shufflevector(a, b, 0, 4, 1, 5);
		u32x4 t1 = __builtin_shufflevector(a, b, 2, 6, 3, 7);
		u32x4 t2 = __builtin_shufflevector(c, d, 0, 4, 1, 5);
		u32x4 t3 = __builtin_shufflevector(c, d, 2, 6, 3, 7);
		size_t o = 16 * (size_t)g;
		chacha_piece_xor(__builtin_shufflevector(t0, t2, 0, 1, 4, 5), in + o, out + o);
		chacha_piece_xor(__builtin_shufflevector(t0, t2, 2, 3, 6, 7), in + 64 + o, out + 64 + o);
		chacha_piece_xor(__builtin_shufflevector(t1, t3, 0, 1, 4, 5), in + 128 + o, out + 128 + o);
		chacha_piece_xor(__builtin_shufflevector(t1, t3, 2, 3, 6, 7), in + 192 + o, out + 192 + o);
	}
}

// Poly1305 keeps h, r and the products in 26-bit limbs: a product of two limbs (one of them
// times 5) fits in 59 bits and a sum of five of them still in 64, so all of it is uint64_t
// arithmetic, on any target. Once the vector kernel needs them, rk[i] holds limb i of r^4, r^2,
// r^3 and r: the multipliers of its last step, in the order of its lanes (poly_v4_run).
typedef struct {
	uint32_t r[5], s[4], h[5], pad[4];
	uint64_t rk[5][4];
	int have_rk;
} poly1305;

#define POLY_MASK     0x3ffffff
#define POLY_V4_BYTES 64

// The 64-bit lanes the vector kernel multiplies hold values below 2^32, which a mask makes
// visible to the compiler: then clang makes each product one 32x32->64 multiply (pmuludq,
// umull). GCC does not look through the mask and makes three multiplies of a 64-bit product,
// at half the speed, so the AVX2 kernel names the instruction instead (poly_mul_avx2).
#define POLY_LO32(v) ((v) & 0xffffffff)

// One step's 25 products before the carries, d = a * k mod 2^130 - 5: limb i of d sums a[j] times
// k[i - j], or times s[i - j + 5] = 5 k[i - j + 5] where i - j is negative (2^130 = 5 mod p).
// Every lane of a, k and s is below 2^32; s[0] is not read.
static inline __attribute__((always_inline)) void poly_mul_generic(u64x4 d[5], const u64x4 a[5], const u64x4 k[5],
                                                                   const u64x4 s[5]) {
	u64x4 a0 = POLY_LO32(a[0]), a1 = POLY_LO32(a[1]), a2 = POLY_LO32(a[2]), a3 = POLY_LO32(a[3]);
	u64x4 a4 = POLY_LO32(a[4]), k0 = POLY_LO32(k[0]), k1 = POLY_LO32(k[1]), k2 = POLY_LO32(k[2]);
	u64x4 k3 = POLY_LO32(k[3]), k4 = POLY_LO32(k[4]);
	u64x4 s1 = POLY_LO32(s[1]), s2 = POLY_LO32(s[2]), s3 = POLY_LO32(s[3]), s4 = POLY_LO32(s[4]);
	d[0] = a0 * k0 + a1 * s4 + a2 * s3 + a3 * s2 + a4 * s1;
	d[1] = a0 * k1 + a1 * k0 + a2 * s4 + a3 * s3 + a4 * s2;
	d[2] = a0 * k2 + a1 * k1 + a2 * k0 + a3 * s4 + a4 * s3;
	d[3] = a0 * k3 + a1 * k2 + a2 * k1 + a3 * k0 + a4 * s4;
	d[4] = a0 * k4 + a1 * k3 + a2 * k2 + a3 * k1 + a4 * k0;
}

typedef void (*poly_mul_fn)(u64x4 d[5], const u64x4 a[5], const u64x4 k[5], const u64x4 s[5]);

// h += 64 * n bytes at m, four blocks per step, each step multiplying by r^4. The lanes hold
// blocks 0, 2, 1 and 3 of each step, in that order: unpacking the two 32-byte loads within their
// 16-byte halves is one instruction (punpcklqdq, zip1), and the blocks' own order would take a
// permute across them. So the last step multiplies by r^4, r^2, r^3 and r, which leaves h the
// sum of the lanes. mul is a poly_mul_* function: a constant after inlining, inlined itself.
static inline __attribute__((always_inline)) void poly_v4_run(poly1305 *p, const uint8_t *m, size_t n,
                                                              poly_mul_fn mul) {
	u64x4 a[5] = {{p->h[0]}, {p->h[1]}, {p->h[2]}, {p->h[3]}, {p->h[4]}}, d[5];
	u64x4 k[5] = {(u64x4){0} + p->rk[0][0], (u64x4){0} + p->rk[1][0], (u64x4){0} + p->rk[2][0],
	              (u64x4){0} + p->rk[3][0], (u64x4){0} + p->rk[4][0]};
	u64x4 s[5] = {{0}, k[1] * 5, k[2] * 5, k[3] * 5, k[4] * 5};
	for (size_t i = 0; i < n; i++, m += POLY_V4_BYTES) {
		if (i == n - 1) {
			memcpy(k, p->rk, sizeof k);
			s[1] = k[1] * 5;
			s[2] = k[2] * 5;
			s[3] = k[3] * 5;
			s[4] = k[4] * 5;
		}
		u64x4 x, y; // blocks 0 and 1, blocks 2 and 3
		memcpy(&x, m, 32);
		memcpy(&y, m + 32, 32);
		u64x4 lo = __builtin_shufflevector(x, y, 0, 4, 2, 6), hi = __builtin_shufflevector(x, y, 1, 5, 3, 7);
		a[0] += lo & POLY_MASK; // the limbs start at bits 0, 26, 52, 78 and 104
		a[1] += (lo >> 26) & POLY_MASK;
		a[2] += (lo >> 52 | hi << 12) & POLY_MASK;
		a[3] += (hi >> 14) & POLY_MASK;
		a[4] += hi >> 40 | 1u << 24;
		mul(d, a, k, s);
		d[1] += d[0] >> 26;
		d[2] += d[1] >> 26;
		d[3] += d[2] >> 26;
		d[4] += d[3] >> 26;
		a[0] = (d[0] & POLY_MASK) + (d[4] >> 26) * 5;
		a[1] = (d[1] & POLY_MASK) + (a[0] >> 26);
		a[0] &= POLY_MASK;
		a[2] = d[2] & POLY_MASK;
		a[3] = d[3] & POLY_MASK;
		a[4] = d[4] & POLY_MASK;
	}
	// The sum of the lanes, carried back into limbs below 2^26 (h1 a little over).
	uint64_t h0 = a[0][0] + a[0][1] + a[0][2] + a[0][3], h1 = a[1][0] + a[1][1] + a[1][2] + a[1][3];
	uint64_t h2 = a[2][0] + a[2][1] + a[2][2] + a[2][3], h3 = a[3][0] + a[3][1] + a[3][2] + a[3][3];
	uint64_t h4 = a[4][0] + a[4][1] + a[4][2] + a[4][3];
	h1 += h0 >> 26;
	h2 += h1 >> 26;
	h3 += h2 >> 26;
	h4 += h3 >> 26;
	h0 = (h0 & POLY_MASK) + (h4 >> 26) * 5;
	p->h[1] = (uint32_t)((h1 & POLY_MASK) + (h0 >> 26));
	p->h[0] = (uint32_t)(h0 & POLY_MASK);
	p->h[2] = (uint32_t)(h2 & POLY_MASK);
	p->h[3] = (uint32_t)(h3 & POLY_MASK);
	p->h[4] = (uint32_t)(h4 & POLY_MASK);
}

static void chacha_v8_base(const uint32_t st[16], const uint8_t *in, uint8_t *out) {
	uint32_t next[16];
	memcpy(next, st, sizeof next);
	next[12] += 4;
	chacha_v4_run(st, in, out);
	chacha_v4_run(next, in + 256, out + 256);
}

static void poly_v4_base(poly1305 *p, const uint8_t *m, size_t n) {
	poly_v4_run(p, m, n, poly_mul_generic);
}

// The one architecture #if of this file, as in ws.c's unmask: AVX2 is not in the x86-64 baseline
// the release builds target, so the kernels are compiled for it as well and picked by asking the
// CPU, once. With it, eight ChaCha20 blocks are one step in 256-bit registers, and Poly1305's
// multiplies four lanes wide, one vpmuludq each: on a Ryzen 7950X at 16 KiB, ChaCha20 2.1 against
// 4.3 GB/s and Poly1305 6.3 against 10.9 GB/s with clang -O2; with GCC 2.0 against 3.8 and 1.5
// against 8.3 GB/s (the base kernel's products are GCC's three multiplies, see POLY_LO32).
#if defined(__x86_64__)
#include <cpuid.h>
#include <stdatomic.h>

typedef int32_t i32x8 __attribute__((vector_size(32)));

// Eight blocks of keystream XORed from in to out (512 bytes each), lane j of x[i] being word i
// of block j. The words leave as 16-byte pieces: a 4x4 transpose within each half of four
// vectors gives four consecutive words of one block per half.
static inline __attribute__((always_inline)) void chacha_v8_run(const uint32_t st[16], const uint8_t *in,
                                                                uint8_t *out) {
	u32x8 x[16];
	for (int i = 0; i < 16; i++) x[i] = (u32x8){0} + st[i];
	x[12] += (u32x8){0, 1, 2, 3, 4, 5, 6, 7};
	for (int i = 0; i < 10; i++) CHACHA_DOUBLE_ROUND(x);
	for (int i = 0; i < 16; i++) x[i] += st[i];
	x[12] += (u32x8){0, 1, 2, 3, 4, 5, 6, 7};
	for (int g = 0; g < 4; g++) {
		u32x8 a = x[4 * g], b = x[4 * g + 1], c = x[4 * g + 2], d = x[4 * g + 3];
		u32x8 t0 = __builtin_shufflevector(a, b, 0, 8, 1, 9, 4, 12, 5, 13);
		u32x8 t1 = __builtin_shufflevector(a, b, 2, 10, 3, 11, 6, 14, 7, 15);
		u32x8 t2 = __builtin_shufflevector(c, d, 0, 8, 1, 9, 4, 12, 5, 13);
		u32x8 t3 = __builtin_shufflevector(c, d, 2, 10, 3, 11, 6, 14, 7, 15);
		u32x8 y[4] = {
		    __builtin_shufflevector(t0, t2, 0, 1, 8, 9, 4, 5, 12, 13),
		    __builtin_shufflevector(t0, t2, 2, 3, 10, 11, 6, 7, 14, 15),
		    __builtin_shufflevector(t1, t3, 0, 1, 8, 9, 4, 5, 12, 13),
		    __builtin_shufflevector(t1, t3, 2, 3, 10, 11, 6, 7, 14, 15),
		};
		for (int k = 0; k < 4; k++) {
			size_t lo = 64 * (size_t)k + 16 * (size_t)g, hi = lo + 256;
			chacha_piece_xor(__builtin_shufflevector(y[k], y[k], 0, 1, 2, 3), in + lo, out + lo);
			chacha_piece_xor(__builtin_shufflevector(y[k], y[k], 4, 5, 6, 7), in + hi, out + hi);
		}
	}
}

// The products of poly_mul_generic, each one vpmuludq (the low 32 bits of each 64-bit lane
// multiplied to 64), whatever the compiler makes of a mask. The builtin is GCC's and clang's
// both, and the target attribute is what allows it here.
__attribute__((target("avx2"), always_inline)) static inline u64x4 mul32_avx2(u64x4 x, u64x4 y) {
	return (u64x4)__builtin_ia32_pmuludq256((i32x8)x, (i32x8)y);
}

__attribute__((target("avx2"), always_inline)) static inline void poly_mul_avx2(u64x4 d[5], const u64x4 a[5],
                                                                                const u64x4 k[5], const u64x4 s[5]) {
	d[0] = mul32_avx2(a[0], k[0]) + mul32_avx2(a[1], s[4]) + mul32_avx2(a[2], s[3]) + mul32_avx2(a[3], s[2]) +
	       mul32_avx2(a[4], s[1]);
	d[1] = mul32_avx2(a[0], k[1]) + mul32_avx2(a[1], k[0]) + mul32_avx2(a[2], s[4]) + mul32_avx2(a[3], s[3]) +
	       mul32_avx2(a[4], s[2]);
	d[2] = mul32_avx2(a[0], k[2]) + mul32_avx2(a[1], k[1]) + mul32_avx2(a[2], k[0]) + mul32_avx2(a[3], s[4]) +
	       mul32_avx2(a[4], s[3]);
	d[3] = mul32_avx2(a[0], k[3]) + mul32_avx2(a[1], k[2]) + mul32_avx2(a[2], k[1]) + mul32_avx2(a[3], k[0]) +
	       mul32_avx2(a[4], s[4]);
	d[4] = mul32_avx2(a[0], k[4]) + mul32_avx2(a[1], k[3]) + mul32_avx2(a[2], k[2]) + mul32_avx2(a[3], k[1]) +
	       mul32_avx2(a[4], k[0]);
}

__attribute__((target("avx2"))) static void chacha_v8_avx2(const uint32_t st[16], const uint8_t *in, uint8_t *out) {
	chacha_v8_run(st, in, out);
}

__attribute__((target("avx2"))) static void poly_v4_avx2(poly1305 *p, const uint8_t *m, size_t n) {
	poly_v4_run(p, m, n, poly_mul_avx2);
}

// AVX2 in the CPU (leaf 7) and its registers saved by the OS (OSXSAVE, then XCR0's SSE and AVX
// bits): a CPU that has it under an OS that does not save YMM faults on the first use.
static int cpu_has_avx2(void) {
	unsigned a, b, c, d;
	if (!__get_cpuid(1, &a, &b, &c, &d) || !(c & bit_OSXSAVE) || !(c & bit_AVX)) return 0;
	unsigned lo, hi;
	__asm__ volatile("xgetbv" : "=a"(lo), "=d"(hi) : "c"(0));
	if ((lo & 6) != 6) return 0;
	if (!__get_cpuid_count(7, 0, &a, &b, &c, &d)) return 0;
	return (b & bit_AVX2) != 0;
}

// -1 until the first use, which every thread answers the same; 0 also when a test forces the base
// kernels (hw_aead_force_base_kernels).
static _Atomic int g_aead_avx2 = -1;

static int aead_avx2(void) {
	int avx2 = atomic_load_explicit(&g_aead_avx2, memory_order_relaxed);
	if (avx2 < 0) {
		avx2 = cpu_has_avx2();
		atomic_store_explicit(&g_aead_avx2, avx2, memory_order_relaxed);
	}
	return avx2;
}

static void chacha_v8(const uint32_t st[16], const uint8_t *in, uint8_t *out) {
	if (aead_avx2()) {
		chacha_v8_avx2(st, in, out);
	} else {
		chacha_v8_base(st, in, out);
	}
}

static void poly_v4(poly1305 *p, const uint8_t *m, size_t n) {
	if (aead_avx2()) {
		poly_v4_avx2(p, m, n);
	} else {
		poly_v4_base(p, m, n);
	}
}

// ---- AES-128-GCM on AES-NI and PCLMULQDQ
// The blocks are FIPS 197's bytes in an XMM register, the round keys hw_aes128's words with each
// one's bytes reversed (rk[] holds them as big-endian words). GHASH works on byte-reversed
// blocks, where the reflected field element is an ordinary 128-bit carry-less product shifted
// left by one; the product of eight blocks with H^8 down to H^1 is summed before it is reduced
// once (Gueron and Kounavis, Intel's "Carry-Less Multiplication and Its Usage for Computing the
// GCM Mode", 2014), which is linear and so the same as reducing each.
#include <immintrin.h>

#define AESNI_FN     __attribute__((target("aes,pclmul,ssse3,sse4.1"))) static
#define AESNI_INLINE __attribute__((target("aes,pclmul,ssse3,sse4.1"), always_inline)) static inline
#define GCM_HW_WIDE  8 // blocks per step: AES-NI's latency is hidden by eight independent blocks

AESNI_INLINE __m128i xmm_load(const uint8_t *p) {
	return _mm_loadu_si128((const __m128i *)p);
}

AESNI_INLINE void xmm_store(uint8_t *p, __m128i x) {
	_mm_storeu_si128((__m128i *)p, x);
}

AESNI_INLINE __m128i xmm_bswap(__m128i x) {
	return _mm_shuffle_epi8(x, _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15));
}

AESNI_INLINE void aesni_keys(const hw_aes128 *k, __m128i rk[11]) {
	const __m128i words = _mm_set_epi8(12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3);
	for (int r = 0; r < 11; r++) {
		rk[r] = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *)(k->rk + 4 * r)), words);
	}
}

AESNI_INLINE __m128i aesni_block(const __m128i rk[11], __m128i x) {
	x = _mm_xor_si128(x, rk[0]);
	for (int r = 1; r < 10; r++) x = _mm_aesenc_si128(x, rk[r]);
	return _mm_aesenclast_si128(x, rk[10]);
}

// The counter block nonce || n, from j (the nonce with a zero counter).
AESNI_INLINE __m128i gcm_counter(__m128i j, uint32_t n) {
	return _mm_insert_epi32(j, (int)__builtin_bswap32(n), 3);
}

// A carry-less product before its reduction: the low, middle and high 128 bits of 256.
typedef struct {
	__m128i lo, mid, hi;
} clmul_sum;

AESNI_INLINE void clmul_add(clmul_sum *a, __m128i x, __m128i h) {
	a->lo = _mm_xor_si128(a->lo, _mm_clmulepi64_si128(x, h, 0x00));
	a->hi = _mm_xor_si128(a->hi, _mm_clmulepi64_si128(x, h, 0x11));
	a->mid = _mm_xor_si128(a->mid, _mm_xor_si128(_mm_clmulepi64_si128(x, h, 0x10), _mm_clmulepi64_si128(x, h, 0x01)));
}

// The 256-bit sum shifted left by one (the reflection), then folded by x^128 = x^7 + x^2 + x + 1.
AESNI_INLINE __m128i clmul_reduce(const clmul_sum *a) {
	__m128i lo = _mm_xor_si128(a->lo, _mm_slli_si128(a->mid, 8));
	__m128i hi = _mm_xor_si128(a->hi, _mm_srli_si128(a->mid, 8));
	__m128i lo_c = _mm_srli_epi32(lo, 31), hi_c = _mm_srli_epi32(hi, 31);
	lo = _mm_slli_epi32(lo, 1);
	hi = _mm_slli_epi32(hi, 1);
	hi = _mm_or_si128(hi, _mm_srli_si128(lo_c, 12));
	hi = _mm_or_si128(hi, _mm_slli_si128(hi_c, 4));
	lo = _mm_or_si128(lo, _mm_slli_si128(lo_c, 4));
	__m128i f = _mm_xor_si128(_mm_xor_si128(_mm_slli_epi32(lo, 31), _mm_slli_epi32(lo, 30)), _mm_slli_epi32(lo, 25));
	__m128i f_hi = _mm_srli_si128(f, 4);
	lo = _mm_xor_si128(lo, _mm_slli_si128(f, 12));
	__m128i g = _mm_xor_si128(_mm_xor_si128(_mm_srli_epi32(lo, 1), _mm_srli_epi32(lo, 2)), _mm_srli_epi32(lo, 7));
	g = _mm_xor_si128(g, f_hi);
	return _mm_xor_si128(hi, _mm_xor_si128(lo, g));
}

AESNI_INLINE __m128i gf_mul(__m128i x, __m128i h) {
	clmul_sum a = {_mm_setzero_si128(), _mm_setzero_si128(), _mm_setzero_si128()};
	clmul_add(&a, x, h);
	return clmul_reduce(&a);
}

// y absorbs len bytes, the last block padded with zeros; hp[i] is H^(i + 1).
AESNI_INLINE __m128i ghash_hw(__m128i y, const __m128i hp[GCM_HW_WIDE], const uint8_t *p, size_t len) {
	for (; len >= 16 * GCM_HW_WIDE; p += 16 * GCM_HW_WIDE, len -= 16 * GCM_HW_WIDE) {
		clmul_sum a = {_mm_setzero_si128(), _mm_setzero_si128(), _mm_setzero_si128()};
		clmul_add(&a, _mm_xor_si128(y, xmm_bswap(xmm_load(p))), hp[GCM_HW_WIDE - 1]);
		for (int i = 1; i < GCM_HW_WIDE; i++) clmul_add(&a, xmm_bswap(xmm_load(p + 16 * i)), hp[GCM_HW_WIDE - 1 - i]);
		y = clmul_reduce(&a);
	}
	for (; len >= 16; p += 16, len -= 16) y = gf_mul(_mm_xor_si128(y, xmm_bswap(xmm_load(p))), hp[0]);
	if (len) {
		uint8_t b[16] = {0};
		memcpy(b, p, len);
		y = gf_mul(_mm_xor_si128(y, xmm_bswap(xmm_load(b))), hp[0]);
	}
	return y;
}

AESNI_INLINE void gcm_hw_powers(const hw_aes128gcm *g, __m128i hp[GCM_HW_WIDE]) {
	for (int i = 0; i < GCM_HW_WIDE; i++) {
		hp[i] = _mm_loadu_si128((const __m128i *)(g->htable + GCM_HW_POWERS + 2 * i));
	}
}

// The tag before E(J0) masks it: GHASH of aad, ct and their lengths in bits, bytes in GCM's order.
AESNI_INLINE __m128i gcm_hw_hash(const __m128i hp[GCM_HW_WIDE], const uint8_t *aad, size_t aad_len, const uint8_t *ct,
                                 size_t len) {
	__m128i y = ghash_hw(_mm_setzero_si128(), hp, aad, aad_len);
	y = ghash_hw(y, hp, ct, len);
	uint64_t aad_bits = (uint64_t)aad_len * 8, ct_bits = (uint64_t)len * 8;
	y = _mm_xor_si128(y, _mm_set_epi64x((long long)aad_bits, (long long)ct_bits));
	return xmm_bswap(gf_mul(y, hp[0]));
}

// CTR from nonce || 2 over len bytes, eight blocks at a time; out may equal in.
AESNI_INLINE void gcm_hw_ctr(const __m128i rk[11], __m128i j, const uint8_t *in, size_t len, uint8_t *out) {
	uint32_t n = 2;
	for (; len >= 16 * GCM_HW_WIDE; in += 16 * GCM_HW_WIDE, out += 16 * GCM_HW_WIDE, len -= 16 * GCM_HW_WIDE) {
		__m128i b[GCM_HW_WIDE];
		for (int i = 0; i < GCM_HW_WIDE; i++) b[i] = _mm_xor_si128(gcm_counter(j, n + (uint32_t)i), rk[0]);
		for (int r = 1; r < 10; r++) {
			for (int i = 0; i < GCM_HW_WIDE; i++) b[i] = _mm_aesenc_si128(b[i], rk[r]);
		}
		for (int i = 0; i < GCM_HW_WIDE; i++) {
			b[i] = _mm_aesenclast_si128(b[i], rk[10]);
			xmm_store(out + 16 * i, _mm_xor_si128(xmm_load(in + 16 * i), b[i]));
		}
		n += GCM_HW_WIDE;
	}
	for (; len >= 16; in += 16, out += 16, len -= 16) {
		xmm_store(out, _mm_xor_si128(xmm_load(in), aesni_block(rk, gcm_counter(j, n++))));
	}
	if (len) {
		uint8_t ks[16];
		xmm_store(ks, aesni_block(rk, gcm_counter(j, n)));
		for (size_t i = 0; i < len; i++) out[i] = in[i] ^ ks[i];
		wipe(ks, sizeof ks);
	}
}

AESNI_INLINE __m128i gcm_hw_nonce(const uint8_t nonce[HW_AEAD_NONCE]) {
	uint8_t b[16] = {0};
	memcpy(b, nonce, HW_AEAD_NONCE);
	return xmm_load(b);
}

AESNI_FN void aes_hw_encrypt(const hw_aes128 *k, const uint8_t in[16], uint8_t out[16]) {
	__m128i rk[11];
	aesni_keys(k, rk);
	xmm_store(out, aesni_block(rk, xmm_load(in)));
}

AESNI_FN void gcm_hw_init(hw_aes128gcm *g) {
	__m128i rk[11];
	aesni_keys(&g->aes, rk);
	__m128i h = xmm_bswap(aesni_block(rk, _mm_setzero_si128())), p = h;
	for (int i = 0; i < GCM_HW_WIDE; i++) {
		_mm_storeu_si128((__m128i *)(g->htable + GCM_HW_POWERS + 2 * i), p);
		p = gf_mul(p, h);
	}
}

AESNI_FN void gcm_hw_seal(const hw_aes128gcm *g, const uint8_t nonce[HW_AEAD_NONCE], const uint8_t *aad, size_t aad_len,
                          const uint8_t *in, size_t len, uint8_t *out) {
	__m128i rk[11], hp[GCM_HW_WIDE];
	aesni_keys(&g->aes, rk);
	gcm_hw_powers(g, hp);
	__m128i j = gcm_hw_nonce(nonce);
	gcm_hw_ctr(rk, j, in, len, out);
	__m128i tag = _mm_xor_si128(gcm_hw_hash(hp, aad, aad_len, out, len), aesni_block(rk, gcm_counter(j, 1)));
	xmm_store(out + len, tag);
}

// len excludes the tag, which follows the ciphertext in in. Nothing is decrypted unless the tag
// verifies.
AESNI_FN int gcm_hw_open(const hw_aes128gcm *g, const uint8_t nonce[HW_AEAD_NONCE], const uint8_t *aad, size_t aad_len,
                         const uint8_t *in, size_t len, uint8_t *out) {
	__m128i rk[11], hp[GCM_HW_WIDE];
	aesni_keys(&g->aes, rk);
	gcm_hw_powers(g, hp);
	__m128i j = gcm_hw_nonce(nonce);
	uint8_t tag[16];
	xmm_store(tag, _mm_xor_si128(gcm_hw_hash(hp, aad, aad_len, in, len), aesni_block(rk, gcm_counter(j, 1))));
	if (!hw_ct_equal(tag, in + len, 16)) {
		if (len) memset(out, 0, len);
		return -1;
	}
	gcm_hw_ctr(rk, j, in, len, out);
	return 0;
}

// AES-NI, PCLMULQDQ and the SSSE3 and SSE4.1 the kernel's shuffles and inserts are: XMM state is
// x86-64's baseline, which every OS saves.
static int cpu_has_aesni(void) {
	unsigned a, b, c, d;
	if (!__get_cpuid(1, &a, &b, &c, &d)) return 0;
	return (c & bit_AES) && (c & bit_PCLMUL) && (c & bit_SSSE3) && (c & bit_SSE4_1);
}

// -1 until the first look; g_aes_hw_off is set while a test forces the base kernels.
static _Atomic int g_aes_hw_cpu = -1;
static _Atomic int g_aes_hw_off = 0;

static int aes_hw_cpu(void) {
	int has = atomic_load_explicit(&g_aes_hw_cpu, memory_order_relaxed);
	if (has < 0) {
		has = cpu_has_aesni();
		atomic_store_explicit(&g_aes_hw_cpu, has, memory_order_relaxed);
	}
	return has;
}

static int aes_hw(void) {
	return !atomic_load_explicit(&g_aes_hw_off, memory_order_relaxed) && aes_hw_cpu();
}

int hw_aead_force_base_kernels(int on) {
	atomic_store_explicit(&g_aead_avx2, on ? 0 : -1, memory_order_relaxed);
	atomic_store_explicit(&g_aes_hw_off, on ? 1 : 0, memory_order_relaxed);
	return cpu_has_avx2() || cpu_has_aesni();
}
#else
static void chacha_v8(const uint32_t st[16], const uint8_t *in, uint8_t *out) {
	chacha_v8_base(st, in, out);
}

static void poly_v4(poly1305 *p, const uint8_t *m, size_t n) {
	poly_v4_base(p, m, n);
}

static int aes_hw_cpu(void) {
	return 0;
}

static int aes_hw(void) {
	return 0;
}

static void aes_hw_encrypt(const hw_aes128 *k, const uint8_t in[16], uint8_t out[16]) {
}

static void gcm_hw_init(hw_aes128gcm *g) {
}

static void gcm_hw_seal(const hw_aes128gcm *g, const uint8_t nonce[HW_AEAD_NONCE], const uint8_t *aad, size_t aad_len,
                        const uint8_t *in, size_t len, uint8_t *out) {
}

static int gcm_hw_open(const hw_aes128gcm *g, const uint8_t nonce[HW_AEAD_NONCE], const uint8_t *aad, size_t aad_len,
                       const uint8_t *in, size_t len, uint8_t *out) {
	return -1;
}

int hw_aead_force_base_kernels(int on) {
	(void)on;
	return 0;
}
#endif

int hw_aes128gcm_hw(void) {
	return aes_hw();
}

// ---- ChaCha20 -----------------------------------------------------------------------------
// The keystream from st's counter XORed into len bytes; st's counter is advanced past it.
static void chacha_xor(uint32_t st[16], const uint8_t *in, uint8_t *out, size_t len) {
	for (; len >= CHACHA_V8_BYTES; in += CHACHA_V8_BYTES, out += CHACHA_V8_BYTES, len -= CHACHA_V8_BYTES) {
		chacha_v8(st, in, out);
		st[12] += CHACHA_V8_BLOCKS;
	}
	if (len > 64) {
		uint8_t buf[CHACHA_V8_BYTES];
		memcpy(buf, in, len);
		chacha_v8(st, buf, buf);
		memcpy(out, buf, len);
		st[12] += (uint32_t)((len + 63) / 64);
	} else if (len) {
		chacha_block_xor(st, in, out, len);
		st[12]++;
	}
}

void hw_chacha20_xor(const uint8_t key[32], uint32_t counter, const uint8_t nonce[HW_AEAD_NONCE], const uint8_t *in,
                     uint8_t *out, size_t len) {
	uint32_t st[16];
	chacha_init(st, key, counter, nonce);
	chacha_xor(st, in, out, len);
}

// ---- Poly1305 -----------------------------------------------------------------------------
static void poly_init(poly1305 *p, const uint8_t key[32]) {
	uint32_t t0 = le32(key) & 0x0fffffff, t1 = le32(key + 4) & 0x0ffffffc;
	uint32_t t2 = le32(key + 8) & 0x0ffffffc, t3 = le32(key + 12) & 0x0ffffffc;
	p->r[0] = t0 & POLY_MASK;
	p->r[1] = (t0 >> 26 | t1 << 6) & POLY_MASK;
	p->r[2] = (t1 >> 20 | t2 << 12) & POLY_MASK;
	p->r[3] = (t2 >> 14 | t3 << 18) & POLY_MASK;
	p->r[4] = t3 >> 8;
	for (int i = 0; i < 4; i++) p->s[i] = p->r[i + 1] * 5; // 2^130 = 5 mod p
	memset(p->h, 0, sizeof p->h);
	for (int i = 0; i < 4; i++) p->pad[i] = le32(key + 16 + 4 * i);
	p->have_rk = 0;
}

// out = a * b mod 2^130 - 5, limbs carried below 2^26 (out[1] a little over). Inputs below 2^27.
static void poly_mul(uint32_t out[5], const uint32_t a[5], const uint32_t b[5]) {
	const uint64_t a0 = a[0], a1 = a[1], a2 = a[2], a3 = a[3], a4 = a[4];
	const uint64_t b0 = b[0], b1 = b[1], b2 = b[2], b3 = b[3], b4 = b[4];
	const uint64_t c1 = b1 * 5, c2 = b2 * 5, c3 = b3 * 5, c4 = b4 * 5;
	uint64_t d0 = a0 * b0 + a1 * c4 + a2 * c3 + a3 * c2 + a4 * c1;
	uint64_t d1 = a0 * b1 + a1 * b0 + a2 * c4 + a3 * c3 + a4 * c2;
	uint64_t d2 = a0 * b2 + a1 * b1 + a2 * b0 + a3 * c4 + a4 * c3;
	uint64_t d3 = a0 * b3 + a1 * b2 + a2 * b1 + a3 * b0 + a4 * c4;
	uint64_t d4 = a0 * b4 + a1 * b3 + a2 * b2 + a3 * b1 + a4 * b0;
	d1 += d0 >> 26;
	d2 += d1 >> 26;
	d3 += d2 >> 26;
	d4 += d3 >> 26;
	d0 = (d0 & POLY_MASK) + (d4 >> 26) * 5;
	out[0] = (uint32_t)(d0 & POLY_MASK);
	out[1] = (uint32_t)((d1 & POLY_MASK) + (d0 >> 26));
	out[2] = (uint32_t)(d2 & POLY_MASK);
	out[3] = (uint32_t)(d3 & POLY_MASK);
	out[4] = (uint32_t)(d4 & POLY_MASK);
}

// Whole 16-byte blocks; hibit is 1 << 24 for a block that is full, 0 for a padded last one.
// Runs of 256 bytes or more go four blocks at a time through the vector kernel.
static void poly_blocks(poly1305 *p, const uint8_t *m, size_t len, uint32_t hibit) {
	if (hibit && len >= 4 * POLY_V4_BYTES) {
		if (!p->have_rk) {
			uint32_t rp[3][5]; // r^2, r^3 and r^4
			poly_mul(rp[0], p->r, p->r);
			poly_mul(rp[1], rp[0], p->r);
			poly_mul(rp[2], rp[1], p->r);
			for (int i = 0; i < 5; i++) {
				p->rk[i][0] = rp[2][i];
				p->rk[i][1] = rp[0][i];
				p->rk[i][2] = rp[1][i];
				p->rk[i][3] = p->r[i];
			}
			wipe(rp, sizeof rp);
			p->have_rk = 1;
		}
		size_t n = len / POLY_V4_BYTES;
		poly_v4(p, m, n);
		m += n * POLY_V4_BYTES;
		len -= n * POLY_V4_BYTES;
	}
	const uint64_t r0 = p->r[0], r1 = p->r[1], r2 = p->r[2], r3 = p->r[3], r4 = p->r[4];
	const uint64_t s1 = p->s[0], s2 = p->s[1], s3 = p->s[2], s4 = p->s[3];
	uint32_t h0 = p->h[0], h1 = p->h[1], h2 = p->h[2], h3 = p->h[3], h4 = p->h[4];
	for (; len >= 16; m += 16, len -= 16) {
		uint32_t w0 = le32(m), w1 = le32(m + 4), w2 = le32(m + 8), w3 = le32(m + 12);
		h0 += w0 & POLY_MASK;
		h1 += (w0 >> 26 | w1 << 6) & POLY_MASK;
		h2 += (w1 >> 20 | w2 << 12) & POLY_MASK;
		h3 += (w2 >> 14 | w3 << 18) & POLY_MASK;
		h4 += w3 >> 8 | hibit;
		uint64_t d0 = h0 * r0 + h1 * s4 + h2 * s3 + h3 * s2 + h4 * s1;
		uint64_t d1 = h0 * r1 + h1 * r0 + h2 * s4 + h3 * s3 + h4 * s2;
		uint64_t d2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * s4 + h4 * s3;
		uint64_t d3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * s4;
		uint64_t d4 = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0;
		d1 += d0 >> 26;
		d2 += d1 >> 26;
		d3 += d2 >> 26;
		d4 += d3 >> 26;
		uint64_t c0 = (d0 & POLY_MASK) + (d4 >> 26) * 5;
		h1 = (uint32_t)((d1 & POLY_MASK) + (c0 >> 26));
		h0 = (uint32_t)(c0 & POLY_MASK);
		h2 = (uint32_t)(d2 & POLY_MASK);
		h3 = (uint32_t)(d3 & POLY_MASK);
		h4 = (uint32_t)(d4 & POLY_MASK);
	}
	p->h[0] = h0;
	p->h[1] = h1;
	p->h[2] = h2;
	p->h[3] = h3;
	p->h[4] = h4;
}

// Absorbs len bytes zero-padded to whole blocks, as the AEAD's MAC input is.
static void poly_padded(poly1305 *p, const uint8_t *m, size_t len) {
	size_t whole = len & ~(size_t)15;
	poly_blocks(p, m, whole, 1u << 24);
	if (len > whole) {
		uint8_t b[16] = {0};
		memcpy(b, m + whole, len - whole);
		poly_blocks(p, b, 16, 1u << 24);
	}
}
static void poly_finish(poly1305 *p, uint8_t tag[16]) {
	uint32_t h0 = p->h[0], h1 = p->h[1], h2 = p->h[2], h3 = p->h[3], h4 = p->h[4];
	// Carry fully, then subtract p = 2^130 - 5 if h >= p, chosen without a branch.
	h2 += h1 >> 26;
	h1 &= 0x3ffffff;
	h3 += h2 >> 26;
	h2 &= 0x3ffffff;
	h4 += h3 >> 26;
	h3 &= 0x3ffffff;
	h0 += (h4 >> 26) * 5;
	h4 &= 0x3ffffff;
	h1 += h0 >> 26;
	h0 &= 0x3ffffff;
	uint32_t g0 = h0 + 5, g1 = h1 + (g0 >> 26);
	g0 &= 0x3ffffff;
	uint32_t g2 = h2 + (g1 >> 26);
	g1 &= 0x3ffffff;
	uint32_t g3 = h3 + (g2 >> 26);
	g2 &= 0x3ffffff;
	uint32_t g4 = h4 + (g3 >> 26) - (1u << 26);
	g3 &= 0x3ffffff;
	uint32_t keep_g = (g4 >> 31) - 1; // all ones when h + 5 - 2^130 did not go negative
	h0 = (h0 & ~keep_g) | (g0 & keep_g);
	h1 = (h1 & ~keep_g) | (g1 & keep_g);
	h2 = (h2 & ~keep_g) | (g2 & keep_g);
	h3 = (h3 & ~keep_g) | (g3 & keep_g);
	h4 = (h4 & ~keep_g) | (g4 & keep_g);
	// h mod 2^128 plus the pad, in four words.
	uint64_t f = (uint64_t)(h0 | h1 << 26) + p->pad[0];
	put_le32(tag, (uint32_t)f);
	f = (uint64_t)(h1 >> 6 | h2 << 20) + p->pad[1] + (f >> 32);
	put_le32(tag + 4, (uint32_t)f);
	f = (uint64_t)(h2 >> 12 | h3 << 14) + p->pad[2] + (f >> 32);
	put_le32(tag + 8, (uint32_t)f);
	f = (uint64_t)(h3 >> 18 | h4 << 8) + p->pad[3] + (f >> 32);
	put_le32(tag + 12, (uint32_t)f);
	wipe(p, sizeof *p);
}

void hw_poly1305(const uint8_t key[32], const uint8_t *msg, size_t len, uint8_t tag[HW_AEAD_TAG]) {
	poly1305 p;
	poly_init(&p, key);
	size_t whole = len & ~(size_t)15;
	poly_blocks(&p, msg, whole, 1u << 24);
	if (len > whole) {
		uint8_t b[16] = {0};
		memcpy(b, msg + whole, len - whole);
		b[len - whole] = 1;
		poly_blocks(&p, b, 16, 0);
	}
	poly_finish(&p, tag);
}

// ---- ChaCha20-Poly1305 --------------------------------------------------------------------
// The first eight blocks are made in one pass over a copy of the first 448 bytes: block 0's
// keystream, XORed into zeros, is the one-time Poly1305 key, and blocks 1..7 cover the text.
#define AEAD_HEAD (CHACHA_V8_BYTES - 64)

static void aead_head(uint32_t st[16], const uint8_t key[32], const uint8_t nonce[HW_AEAD_NONCE], const uint8_t *in,
                      size_t n, uint8_t buf[CHACHA_V8_BYTES]) {
	chacha_init(st, key, 0, nonce);
	memset(buf, 0, 64);
	if (n) memcpy(buf + 64, in, n);
	chacha_v8(st, buf, buf);
	st[12] = CHACHA_V8_BLOCKS;
}

static void aead_tag(const uint8_t poly_key[32], const uint8_t *aad, size_t aad_len, const uint8_t *ct, size_t len,
                     uint8_t tag[16]) {
	poly1305 p;
	poly_init(&p, poly_key);
	poly_padded(&p, aad, aad_len);
	poly_padded(&p, ct, len);
	uint8_t lens[16];
	put_le64(lens, aad_len);
	put_le64(lens + 8, len);
	poly_blocks(&p, lens, 16, 1u << 24);
	poly_finish(&p, tag);
}

void hw_chacha20poly1305_seal(const uint8_t key[32], const uint8_t nonce[HW_AEAD_NONCE], const uint8_t *aad,
                              size_t aad_len, const uint8_t *in, size_t len, uint8_t *out) {
	uint32_t st[16];
	uint8_t buf[CHACHA_V8_BYTES];
	size_t n = HW_MIN(len, (size_t)AEAD_HEAD);
	aead_head(st, key, nonce, in, n, buf);
	if (n) memcpy(out, buf + 64, n);
	if (len > n) chacha_xor(st, in + n, out + n, len - n);
	aead_tag(buf, aad, aad_len, out, len, out + len);
	wipe(buf, sizeof buf);
	wipe(st, sizeof st);
}

int hw_chacha20poly1305_open(const uint8_t key[32], const uint8_t nonce[HW_AEAD_NONCE], const uint8_t *aad,
                             size_t aad_len, const uint8_t *in, size_t len, uint8_t *out) {
	if (len < HW_AEAD_TAG) return -1;
	len -= HW_AEAD_TAG;
	uint32_t st[16];
	uint8_t buf[CHACHA_V8_BYTES], tag[16];
	size_t n = HW_MIN(len, (size_t)AEAD_HEAD);
	aead_head(st, key, nonce, in, n, buf);
	aead_tag(buf, aad, aad_len, in, len, tag);
	int ok = hw_ct_equal(tag, in + len, 16);
	if (ok) {
		if (n) memcpy(out, buf + 64, n);
		if (len > n) chacha_xor(st, in + n, out + n, len - n);
	} else if (len) {
		memset(out, 0, len);
	}
	wipe(buf, sizeof buf);
	wipe(st, sizeof st);
	return ok ? 0 : -1;
}
