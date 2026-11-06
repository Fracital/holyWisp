/*
 * holywisp/sha1.h implementation (FIPS 180-1). Only used to hash a 60-byte handshake string, so
 * clarity wins over speed.
 */
#include "holywisp/sha1.h"

#include <string.h>

static uint32_t rol(uint32_t v, int bits) {
	return (v << bits) | (v >> (32 - bits));
}

static void sha1_block(uint32_t h[5], const uint8_t block[64]) {
	uint32_t w[80];
	for (int i = 0; i < 16; i++) {
		w[i] = (uint32_t)block[i * 4] << 24 | (uint32_t)block[i * 4 + 1] << 16 | (uint32_t)block[i * 4 + 2] << 8 |
		       (uint32_t)block[i * 4 + 3];
	}
	for (int i = 16; i < 80; i++) w[i] = rol(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);

	uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];
	for (int i = 0; i < 80; i++) {
		uint32_t f, k;
		if (i < 20) {
			f = (b & c) | (~b & d);
			k = 0x5A827999;
		} else if (i < 40) {
			f = b ^ c ^ d;
			k = 0x6ED9EBA1;
		} else if (i < 60) {
			f = (b & c) | (b & d) | (c & d);
			k = 0x8F1BBCDC;
		} else {
			f = b ^ c ^ d;
			k = 0xCA62C1D6;
		}
		uint32_t t = rol(a, 5) + f + e + k + w[i];
		e = d;
		d = c;
		c = rol(b, 30);
		b = a;
		a = t;
	}
	h[0] += a;
	h[1] += b;
	h[2] += c;
	h[3] += d;
	h[4] += e;
}

void hw_sha1(const void *data, size_t len, uint8_t out[HW_SHA1_LEN]) {
	uint32_t h[5] = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};
	const uint8_t *p = data;
	size_t remaining = len;
	while (remaining >= 64) {
		sha1_block(h, p);
		p += 64;
		remaining -= 64;
	}
	uint8_t tail[128];
	memset(tail, 0, sizeof(tail));
	memcpy(tail, p, remaining);
	tail[remaining] = 0x80;
	size_t tail_len = remaining + 1 <= 56 ? 64 : 128;
	uint64_t bits = (uint64_t)len * 8;
	for (int i = 0; i < 8; i++) tail[tail_len - 1 - i] = (uint8_t)(bits >> (8 * i));
	sha1_block(h, tail);
	if (tail_len == 128) sha1_block(h, tail + 64);
	for (int i = 0; i < 5; i++) {
		out[i * 4] = (uint8_t)(h[i] >> 24);
		out[i * 4 + 1] = (uint8_t)(h[i] >> 16);
		out[i * 4 + 2] = (uint8_t)(h[i] >> 8);
		out[i * 4 + 3] = (uint8_t)h[i];
	}
}
