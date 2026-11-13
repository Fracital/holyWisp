/*
 * holywisp/blake2b.h implementation, after RFC 7693's reference code.
 */
#include "holywisp/blake2b.h"

#include <string.h>

static const uint64_t BLAKE2B_IV[8] = {
    0x6A09E667F3BCC908ULL, 0xBB67AE8584CAA73BULL, 0x3C6EF372FE94F82BULL, 0xA54FF53A5F1D36F1ULL,
    0x510E527FADE682D1ULL, 0x9B05688C2B3E6C1FULL, 0x1F83D9ABFB41BD6BULL, 0x5BE0CD19137E2179ULL,
};

static const uint8_t BLAKE2B_SIGMA[12][16] = {
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}, {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
    {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4}, {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
    {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13}, {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
    {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11}, {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
    {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5}, {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}, {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
};

typedef struct {
	uint64_t h[8];
	uint64_t t[2];
	uint8_t b[128];
	size_t c; // bytes in b
} blake2b_ctx;

static uint64_t rotr64(uint64_t x, unsigned n) {
	return (x >> n) | (x << (64 - n));
}

static uint64_t load64(const uint8_t *p) {
	uint64_t v = 0;
	for (int i = 7; i >= 0; i--) v = v << 8 | p[i];
	return v;
}

#define B2B_G(a, b, c, d, x, y)         \
	do {                                \
		v[a] = v[a] + v[b] + (x);       \
		v[d] = rotr64(v[d] ^ v[a], 32); \
		v[c] = v[c] + v[d];             \
		v[b] = rotr64(v[b] ^ v[c], 24); \
		v[a] = v[a] + v[b] + (y);       \
		v[d] = rotr64(v[d] ^ v[a], 16); \
		v[c] = v[c] + v[d];             \
		v[b] = rotr64(v[b] ^ v[c], 63); \
	} while (0)

static void blake2b_compress(blake2b_ctx *ctx, int last) {
	uint64_t v[16], m[16];
	for (int i = 0; i < 8; i++) {
		v[i] = ctx->h[i];
		v[i + 8] = BLAKE2B_IV[i];
	}
	v[12] ^= ctx->t[0];
	v[13] ^= ctx->t[1];
	if (last) v[14] = ~v[14];
	for (int i = 0; i < 16; i++) m[i] = load64(ctx->b + 8 * i);
	for (int i = 0; i < 12; i++) {
		const uint8_t *s = BLAKE2B_SIGMA[i];
		B2B_G(0, 4, 8, 12, m[s[0]], m[s[1]]);
		B2B_G(1, 5, 9, 13, m[s[2]], m[s[3]]);
		B2B_G(2, 6, 10, 14, m[s[4]], m[s[5]]);
		B2B_G(3, 7, 11, 15, m[s[6]], m[s[7]]);
		B2B_G(0, 5, 10, 15, m[s[8]], m[s[9]]);
		B2B_G(1, 6, 11, 12, m[s[10]], m[s[11]]);
		B2B_G(2, 7, 8, 13, m[s[12]], m[s[13]]);
		B2B_G(3, 4, 9, 14, m[s[14]], m[s[15]]);
	}
	for (int i = 0; i < 8; i++) ctx->h[i] ^= v[i] ^ v[i + 8];
}

void hw_blake2b(const void *data, size_t len, uint8_t *out, size_t outlen) {
	if (outlen < 1) return;
	if (outlen > HW_BLAKE2B_MAX) outlen = HW_BLAKE2B_MAX;
	blake2b_ctx ctx;
	memset(&ctx, 0, sizeof(ctx));
	for (int i = 0; i < 8; i++) ctx.h[i] = BLAKE2B_IV[i];
	ctx.h[0] ^= 0x01010000ULL ^ (uint64_t)outlen; // parameter block: no key, fanout 1, depth 1
	const uint8_t *in = data;
	for (size_t i = 0; i < len; i++) {
		if (ctx.c == sizeof(ctx.b)) {
			ctx.t[0] += ctx.c;
			if (ctx.t[0] < ctx.c) ctx.t[1]++;
			blake2b_compress(&ctx, 0);
			ctx.c = 0;
		}
		ctx.b[ctx.c++] = in[i];
	}
	ctx.t[0] += ctx.c;
	if (ctx.t[0] < ctx.c) ctx.t[1]++;
	memset(ctx.b + ctx.c, 0, sizeof(ctx.b) - ctx.c);
	blake2b_compress(&ctx, 1);
	for (size_t i = 0; i < outlen; i++) out[i] = (uint8_t)(ctx.h[i >> 3] >> (8 * (i & 7)));
}
