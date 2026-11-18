/*
 * holywisp/sha256.h implementation: FIPS 180-4 SHA-256, then HMAC (RFC 2104) and HKDF (RFC 5869)
 * on top of it.
 */
#include "holywisp/sha256.h"

#include <string.h>

static const uint32_t SHA256_K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

static uint32_t rotr32(uint32_t x, unsigned n) {
	return (x >> n) | (x << (32 - n));
}

static void sha256_block(hw_sha256_ctx *c, const uint8_t *p) {
	uint32_t w[64];
	for (int i = 0; i < 16; i++) {
		w[i] = (uint32_t)p[4 * i] << 24 | (uint32_t)p[4 * i + 1] << 16 | (uint32_t)p[4 * i + 2] << 8 | p[4 * i + 3];
	}
	for (int i = 16; i < 64; i++) {
		uint32_t s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
		uint32_t s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
		w[i] = w[i - 16] + s0 + w[i - 7] + s1;
	}
	uint32_t a = c->h[0], b = c->h[1], cc = c->h[2], d = c->h[3];
	uint32_t e = c->h[4], f = c->h[5], g = c->h[6], h = c->h[7];
	for (int i = 0; i < 64; i++) {
		uint32_t s1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
		uint32_t ch = (e & f) ^ (~e & g);
		uint32_t t1 = h + s1 + ch + SHA256_K[i] + w[i];
		uint32_t s0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
		uint32_t maj = (a & b) ^ (a & cc) ^ (b & cc);
		uint32_t t2 = s0 + maj;
		h = g;
		g = f;
		f = e;
		e = d + t1;
		d = cc;
		cc = b;
		b = a;
		a = t1 + t2;
	}
	c->h[0] += a;
	c->h[1] += b;
	c->h[2] += cc;
	c->h[3] += d;
	c->h[4] += e;
	c->h[5] += f;
	c->h[6] += g;
	c->h[7] += h;
}

void hw_sha256_init(hw_sha256_ctx *c) {
	static const uint32_t iv[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
	                               0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
	memcpy(c->h, iv, sizeof iv);
	c->len = 0;
	c->n = 0;
}

void hw_sha256_update(hw_sha256_ctx *c, const void *data, size_t len) {
	const uint8_t *p = data;
	c->len += len;
	if (c->n) {
		size_t take = HW_SHA256_BLOCK - c->n;
		if (take > len) take = len;
		memcpy(c->buf + c->n, p, take);
		c->n += take;
		p += take;
		len -= take;
		if (c->n < HW_SHA256_BLOCK) return;
		sha256_block(c, c->buf);
		c->n = 0;
	}
	for (; len >= HW_SHA256_BLOCK; p += HW_SHA256_BLOCK, len -= HW_SHA256_BLOCK) sha256_block(c, p);
	if (len) {
		memcpy(c->buf, p, len);
		c->n = len;
	}
}

void hw_sha256_final(hw_sha256_ctx *c, uint8_t out[HW_SHA256_LEN]) {
	uint64_t bits = c->len * 8;
	uint8_t pad[HW_SHA256_BLOCK + 8] = {0x80};
	size_t padlen = (c->n < 56 ? 56 : 120) - c->n;
	for (int i = 0; i < 8; i++) pad[padlen + (size_t)i] = (uint8_t)(bits >> (56 - 8 * i));
	hw_sha256_update(c, pad, padlen + 8);
	for (int i = 0; i < 8; i++) {
		out[4 * i] = (uint8_t)(c->h[i] >> 24);
		out[4 * i + 1] = (uint8_t)(c->h[i] >> 16);
		out[4 * i + 2] = (uint8_t)(c->h[i] >> 8);
		out[4 * i + 3] = (uint8_t)c->h[i];
	}
	memset(c, 0, sizeof *c);
}

void hw_sha256(const void *data, size_t len, uint8_t out[HW_SHA256_LEN]) {
	hw_sha256_ctx c;
	hw_sha256_init(&c);
	hw_sha256_update(&c, data, len);
	hw_sha256_final(&c, out);
}

// The two keyed contexts of an HMAC: the inner and outer hashes, each with its pad block absorbed.
typedef struct {
	hw_sha256_ctx inner, outer;
} hmac_ctx;

static void hmac_init(hmac_ctx *m, const uint8_t *key, size_t key_len) {
	uint8_t k[HW_SHA256_BLOCK] = {0};
	if (key_len > HW_SHA256_BLOCK) {
		hw_sha256(key, key_len, k);
	} else if (key_len) {
		memcpy(k, key, key_len);
	}
	uint8_t ipad[HW_SHA256_BLOCK], opad[HW_SHA256_BLOCK];
	for (int i = 0; i < HW_SHA256_BLOCK; i++) {
		ipad[i] = k[i] ^ 0x36;
		opad[i] = k[i] ^ 0x5c;
	}
	hw_sha256_init(&m->inner);
	hw_sha256_update(&m->inner, ipad, sizeof ipad);
	hw_sha256_init(&m->outer);
	hw_sha256_update(&m->outer, opad, sizeof opad);
	memset(k, 0, sizeof k);
	memset(ipad, 0, sizeof ipad);
	memset(opad, 0, sizeof opad);
}

static void hmac_final(hmac_ctx *m, uint8_t out[HW_SHA256_LEN]) {
	uint8_t ih[HW_SHA256_LEN];
	hw_sha256_final(&m->inner, ih);
	hw_sha256_update(&m->outer, ih, sizeof ih);
	hw_sha256_final(&m->outer, out);
	memset(ih, 0, sizeof ih);
}

void hw_hmac_sha256(const uint8_t *key, size_t key_len, const void *data, size_t len, uint8_t out[HW_SHA256_LEN]) {
	hmac_ctx m;
	hmac_init(&m, key, key_len);
	hw_sha256_update(&m.inner, data, len);
	hmac_final(&m, out);
}

void hw_hkdf_extract(const uint8_t *salt, size_t salt_len, const uint8_t *ikm, size_t ikm_len,
                     uint8_t prk[HW_SHA256_LEN]) {
	static const uint8_t zero[HW_SHA256_LEN];
	if (!salt || !salt_len) {
		salt = zero;
		salt_len = sizeof zero;
	}
	hw_hmac_sha256(salt, salt_len, ikm, ikm_len, prk);
}

int hw_hkdf_expand(const uint8_t prk[HW_SHA256_LEN], const uint8_t *info, size_t info_len, uint8_t *out,
                   size_t out_len) {
	if (out_len > 255 * HW_SHA256_LEN) return -1;
	uint8_t t[HW_SHA256_LEN];
	size_t t_len = 0;
	for (uint8_t i = 1; out_len; i++) {
		hmac_ctx m;
		hmac_init(&m, prk, HW_SHA256_LEN);
		hw_sha256_update(&m.inner, t, t_len);
		if (info_len) hw_sha256_update(&m.inner, info, info_len);
		hw_sha256_update(&m.inner, &i, 1);
		hmac_final(&m, t);
		t_len = HW_SHA256_LEN;
		size_t take = out_len < HW_SHA256_LEN ? out_len : HW_SHA256_LEN;
		memcpy(out, t, take);
		out += take;
		out_len -= take;
	}
	memset(t, 0, sizeof t);
	return 0;
}

int hw_hkdf_expand_label(const uint8_t secret[HW_SHA256_LEN], const char *label, const uint8_t *context,
                         size_t context_len, uint8_t *out, size_t out_len) {
	static const char prefix[] = "tls13 ";
	size_t label_len = strlen(label);
	if (label_len > 255 - (sizeof prefix - 1) || context_len > 255 || out_len > 255 * HW_SHA256_LEN) return -1;
	// struct { uint16 length; opaque label<7..255>; opaque context<0..255>; } HkdfLabel;
	uint8_t info[2 + 1 + 255 + 1 + 255];
	size_t n = 0;
	info[n++] = (uint8_t)(out_len >> 8);
	info[n++] = (uint8_t)out_len;
	info[n++] = (uint8_t)(sizeof prefix - 1 + label_len);
	memcpy(info + n, prefix, sizeof prefix - 1);
	n += sizeof prefix - 1;
	// HkdfLabel carries the label by its length byte, with no NUL: bugprone-not-null-terminated-result
	// takes the strlen above for a string copy.
	memcpy(info + n, label, label_len); // NOLINT(bugprone-not-null-terminated-result)
	n += label_len;
	info[n++] = (uint8_t)context_len;
	if (context_len) memcpy(info + n, context, context_len);
	n += context_len;
	return hw_hkdf_expand(secret, info, n, out, out_len);
}
