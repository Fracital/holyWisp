/*
 * src/common/p256.c - ECDSA over NIST P-256 with SHA-256 (FIPS 186-5, SEC 1), with the
 * deterministic nonces of RFC 6979.
 *
 * Numbers are eight 32-bit limbs, least significant first. Both moduli (the field prime p and the
 * group order n) use one Montgomery multiplication (CIOS, 64-bit products) with a final
 * subtraction chosen by mask, so arithmetic mod p and mod n has no branch on its values.
 * Points are projective (X : Y : Z) with coordinates in Montgomery form, added and doubled with
 * the complete formulas of Renes, Costello and Batina (2016, algorithms 4 and 6, a = -3): the
 * same code is right for P + Q, P + P, P + (-P) and the point at infinity (0 : 1 : 0), so no
 * case needs a branch. A scalar multiplication is a fixed window of 4 bits over all 64 nibbles,
 * each table entry read by scanning the whole table under a mask.
 *
 * Signing and key generation take secrets through these paths only. Verification works on
 * public data and is allowed to branch, but uses the same code.
 */
#include "holywisp/ecc.h"
#include "holywisp/sha256.h"
#include "holywisp/sys.h"

#include <string.h>

#define NLIMBS 8

typedef uint32_t u256[NLIMBS];

typedef struct {
	u256 m;
	uint32_t m0inv; // -m^-1 mod 2^32
	u256 rr;        // R^2 mod m, R = 2^256
	u256 one;       // R mod m: 1 in Montgomery form
	u256 m_minus_2; // the exponent of an inverse
} mont_mod;

static const mont_mod MOD_P = {
    .m = {0xffffffff, 0xffffffff, 0xffffffff, 0x00000000, 0x00000000, 0x00000000, 0x00000001, 0xffffffff},
    .m0inv = 1,
    .rr = {0x00000003, 0x00000000, 0xffffffff, 0xfffffffb, 0xfffffffe, 0xffffffff, 0xfffffffd, 0x00000004},
    .one = {0x00000001, 0x00000000, 0x00000000, 0xffffffff, 0xffffffff, 0xffffffff, 0xfffffffe, 0x00000000},
    .m_minus_2 = {0xfffffffd, 0xffffffff, 0xffffffff, 0x00000000, 0x00000000, 0x00000000, 0x00000001, 0xffffffff},
};

static const mont_mod MOD_N = {
    .m = {0xfc632551, 0xf3b9cac2, 0xa7179e84, 0xbce6faad, 0xffffffff, 0xffffffff, 0x00000000, 0xffffffff},
    .m0inv = 0xee00bc4f,
    .rr = {0xbe79eea2, 0x83244c95, 0x49bd6fa6, 0x4699799c, 0x2b6bec59, 0x2845b239, 0xf3d95620, 0x66e12d94},
    .one = {0x039cdaaf, 0x0c46353d, 0x58e8617b, 0x43190552, 0x00000000, 0x00000000, 0xffffffff, 0x00000000},
    .m_minus_2 = {0xfc63254f, 0xf3b9cac2, 0xa7179e84, 0xbce6faad, 0xffffffff, 0xffffffff, 0x00000000, 0xffffffff},
};

// The curve's b and the base point G, in Montgomery form (times R mod p).
static const u256 B_MONT = {0x29c4bddf, 0xd89cdf62, 0x78843090, 0xacf005cd,
                            0xf7212ed6, 0xe5a220ab, 0x04874834, 0xdc30061d};
static const u256 GX_MONT = {0x18a9143c, 0x79e730d4, 0x5fedb601, 0x75ba95fc,
                             0x77622510, 0x79fb732b, 0xa53755c6, 0x18905f76};
static const u256 GY_MONT = {0xce95560a, 0xddf25357, 0xba19e45c, 0x8b4ab8e4,
                             0xdd21f325, 0xd2e88688, 0x25885d85, 0x8571ff18};

static void wipe(void *p, size_t n) {
	volatile uint8_t *v = p;
	while (n--) *v++ = 0;
}

static void u256_from_be(u256 r, const uint8_t b[32]) {
	for (unsigned i = 0; i < NLIMBS; i++) {
		const uint8_t *q = b + 28 - 4 * i;
		r[i] = (uint32_t)q[0] << 24 | (uint32_t)q[1] << 16 | (uint32_t)q[2] << 8 | (uint32_t)q[3];
	}
}

static void u256_to_be(uint8_t b[32], const u256 a) {
	for (unsigned i = 0; i < NLIMBS; i++) {
		uint8_t *q = b + 28 - 4 * i;
		q[0] = (uint8_t)(a[i] >> 24);
		q[1] = (uint8_t)(a[i] >> 16);
		q[2] = (uint8_t)(a[i] >> 8);
		q[3] = (uint8_t)a[i];
	}
}

// r = a - b; returns the borrow (1 when a < b).
static uint32_t u256_sub(u256 r, const u256 a, const u256 b) {
	uint64_t borrow = 0;
	for (unsigned i = 0; i < NLIMBS; i++) {
		uint64_t d = (uint64_t)a[i] - b[i] - borrow;
		r[i] = (uint32_t)d;
		borrow = (d >> 32) & 1;
	}
	return (uint32_t)borrow;
}

// r = mask ? a : b, for mask all ones or zero.
static void u256_select(u256 r, uint32_t mask, const u256 a, const u256 b) {
	for (unsigned i = 0; i < NLIMBS; i++) r[i] = (a[i] & mask) | (b[i] & ~mask);
}

// All ones when a is zero, else zero.
static uint32_t u256_is_zero_mask(const u256 a) {
	uint32_t acc = 0;
	for (unsigned i = 0; i < NLIMBS; i++) acc |= a[i];
	return 0u - (uint32_t)(((uint64_t)acc - 1) >> 63);
}

// 1 when 1 <= a < m, with no branch on a.
static uint32_t u256_in_range(const u256 a, const u256 m) {
	u256 t;
	uint32_t below = u256_sub(t, a, m);
	return below & ~u256_is_zero_mask(a) & 1;
}

// Reduces a < 2^256 below m (> 2^255) with one masked subtraction.
static void u256_reduce_once(u256 r, const u256 a, const u256 m) {
	u256 t;
	uint32_t borrow = u256_sub(t, a, m);
	u256_select(r, 0u - borrow, a, t);
}

// r = a * b / R mod m for a, b < m (CIOS). The accumulator ends below 2m; the final subtraction
// is kept or dropped by mask.
static void mont_mul(u256 r, const u256 a, const u256 b, const mont_mod *mod) {
	uint32_t t[NLIMBS + 2] = {0};
	for (unsigned i = 0; i < NLIMBS; i++) {
		uint64_t c = 0;
		for (unsigned j = 0; j < NLIMBS; j++) {
			c += (uint64_t)a[j] * b[i] + t[j];
			t[j] = (uint32_t)c;
			c >>= 32;
		}
		c += t[NLIMBS];
		t[NLIMBS] = (uint32_t)c;
		t[NLIMBS + 1] = (uint32_t)(c >> 32);

		uint32_t q = t[0] * mod->m0inv;
		c = ((uint64_t)q * mod->m[0] + t[0]) >> 32;
		for (unsigned j = 1; j < NLIMBS; j++) {
			c += (uint64_t)q * mod->m[j] + t[j];
			t[j - 1] = (uint32_t)c;
			c >>= 32;
		}
		c += t[NLIMBS];
		t[NLIMBS - 1] = (uint32_t)c;
		t[NLIMBS] = t[NLIMBS + 1] + (uint32_t)(c >> 32);
	}
	u256 s;
	uint32_t borrow = u256_sub(s, t, mod->m);
	// Subtract when the accumulator overflowed 256 bits or did not borrow.
	uint32_t use = (t[NLIMBS] | (borrow ^ 1)) & 1;
	u256_select(r, 0u - use, s, t);
}

static void mont_add(u256 r, const u256 a, const u256 b, const mont_mod *mod) {
	u256 sum, s;
	uint64_t c = 0;
	for (unsigned i = 0; i < NLIMBS; i++) {
		c += (uint64_t)a[i] + b[i];
		sum[i] = (uint32_t)c;
		c >>= 32;
	}
	uint32_t borrow = u256_sub(s, sum, mod->m);
	uint32_t use = ((uint32_t)c | (borrow ^ 1)) & 1;
	u256_select(r, 0u - use, s, sum);
}

static void mont_sub(u256 r, const u256 a, const u256 b, const mont_mod *mod) {
	u256 d;
	uint32_t mask = 0u - u256_sub(d, a, b);
	uint64_t c = 0;
	for (unsigned i = 0; i < NLIMBS; i++) {
		c += (uint64_t)d[i] + (mod->m[i] & mask);
		r[i] = (uint32_t)c;
		c >>= 32;
	}
}

static void mont_to(u256 r, const u256 a, const mont_mod *mod) {
	mont_mul(r, a, mod->rr, mod);
}

static void mont_from(u256 r, const u256 a, const mont_mod *mod) {
	static const u256 one = {1};
	mont_mul(r, a, one, mod);
}

// a^(m - 2) = 1/a in Montgomery form (0 for 0). The exponent is public.
static void mont_inv(u256 r, const u256 a, const mont_mod *mod) {
	u256 x;
	memcpy(x, mod->one, sizeof(u256));
	for (int i = 255; i >= 0; i--) {
		mont_mul(x, x, x, mod);
		if ((mod->m_minus_2[i / 32] >> (i % 32)) & 1) mont_mul(x, x, a, mod);
	}
	memcpy(r, x, sizeof(u256));
}

// Field shorthands.
static void fp_mul(u256 r, const u256 a, const u256 b) {
	mont_mul(r, a, b, &MOD_P);
}
static void fp_add(u256 r, const u256 a, const u256 b) {
	mont_add(r, a, b, &MOD_P);
}
static void fp_sub(u256 r, const u256 a, const u256 b) {
	mont_sub(r, a, b, &MOD_P);
}

typedef struct {
	u256 x, y, z;
} point;

static void point_identity(point *r) {
	memset(r, 0, sizeof(*r));
	memcpy(r->y, MOD_P.one, sizeof(u256));
}

// r = p + q (Renes-Costello-Batina algorithm 4). Any of r, p, q may alias.
static void point_add(point *r, const point *p, const point *q) {
	u256 t0, t1, t2, t3, t4, x3, y3, z3;
	fp_mul(t0, p->x, q->x);
	fp_mul(t1, p->y, q->y);
	fp_mul(t2, p->z, q->z);
	fp_add(t3, p->x, p->y);
	fp_add(t4, q->x, q->y);
	fp_mul(t3, t3, t4);
	fp_add(t4, t0, t1);
	fp_sub(t3, t3, t4);
	fp_add(t4, p->y, p->z);
	fp_add(x3, q->y, q->z);
	fp_mul(t4, t4, x3);
	fp_add(x3, t1, t2);
	fp_sub(t4, t4, x3);
	fp_add(x3, p->x, p->z);
	fp_add(y3, q->x, q->z);
	fp_mul(x3, x3, y3);
	fp_add(y3, t0, t2);
	fp_sub(y3, x3, y3);
	fp_mul(z3, B_MONT, t2);
	fp_sub(x3, y3, z3);
	fp_add(z3, x3, x3);
	fp_add(x3, x3, z3);
	fp_sub(z3, t1, x3);
	fp_add(x3, t1, x3);
	fp_mul(y3, B_MONT, y3);
	fp_add(t1, t2, t2);
	fp_add(t2, t1, t2);
	fp_sub(y3, y3, t2);
	fp_sub(y3, y3, t0);
	fp_add(t1, y3, y3);
	fp_add(y3, t1, y3);
	fp_add(t1, t0, t0);
	fp_add(t0, t1, t0);
	fp_sub(t0, t0, t2);
	fp_mul(t1, t4, y3);
	fp_mul(t2, t0, y3);
	fp_mul(y3, x3, z3);
	fp_add(y3, y3, t2);
	fp_mul(x3, t3, x3);
	fp_sub(x3, x3, t1);
	fp_mul(z3, t4, z3);
	fp_mul(t1, t3, t0);
	fp_add(z3, z3, t1);
	memcpy(r->x, x3, sizeof(u256));
	memcpy(r->y, y3, sizeof(u256));
	memcpy(r->z, z3, sizeof(u256));
}

// r = 2p (Renes-Costello-Batina algorithm 6). r and p may alias.
static void point_double(point *r, const point *p) {
	u256 t0, t1, t2, t3, x3, y3, z3;
	fp_mul(t0, p->x, p->x);
	fp_mul(t1, p->y, p->y);
	fp_mul(t2, p->z, p->z);
	fp_mul(t3, p->x, p->y);
	fp_add(t3, t3, t3);
	fp_mul(z3, p->x, p->z);
	fp_add(z3, z3, z3);
	fp_mul(y3, B_MONT, t2);
	fp_sub(y3, y3, z3);
	fp_add(x3, y3, y3);
	fp_add(y3, x3, y3);
	fp_sub(x3, t1, y3);
	fp_add(y3, t1, y3);
	fp_mul(y3, x3, y3);
	fp_mul(x3, x3, t3);
	fp_add(t3, t2, t2);
	fp_add(t2, t2, t3);
	fp_mul(z3, B_MONT, z3);
	fp_sub(z3, z3, t2);
	fp_sub(z3, z3, t0);
	fp_add(t3, z3, z3);
	fp_add(z3, z3, t3);
	fp_add(t3, t0, t0);
	fp_add(t0, t3, t0);
	fp_sub(t0, t0, t2);
	fp_mul(t0, t0, z3);
	fp_add(y3, y3, t0);
	fp_mul(t0, p->y, p->z);
	fp_add(t0, t0, t0);
	fp_mul(z3, t0, z3);
	fp_sub(x3, x3, z3);
	fp_mul(z3, t0, t1);
	fp_add(z3, z3, z3);
	fp_add(z3, z3, z3);
	memcpy(r->x, x3, sizeof(u256));
	memcpy(r->y, y3, sizeof(u256));
	memcpy(r->z, z3, sizeof(u256));
}

#define WINDOW_BITS 4
#define TABLE_LEN   (1 << WINDOW_BITS)

// r = table[idx], reading every entry so that the index leaves no trace in memory accesses.
static void table_select(point *r, const point table[TABLE_LEN], uint32_t idx) {
	memset(r, 0, sizeof(*r));
	for (uint32_t j = 0; j < TABLE_LEN; j++) {
		uint32_t mask = 0u - (uint32_t)(((uint64_t)(j ^ idx) - 1) >> 63);
		for (unsigned i = 0; i < NLIMBS; i++) {
			r->x[i] |= table[j].x[i] & mask;
			r->y[i] |= table[j].y[i] & mask;
			r->z[i] |= table[j].z[i] & mask;
		}
	}
}

// r = k * p for a 256-bit big-endian scalar k, any value (0 and multiples of the order give the
// point at infinity). Constant-time in k: 252 doublings and 64 additions whatever its bits.
static void point_mul(point *r, const point *p, const uint8_t k[32]) {
	point table[TABLE_LEN], acc, t;
	point_identity(&table[0]);
	table[1] = *p;
	for (unsigned i = 2; i < TABLE_LEN; i++) {
		if (i & 1) {
			point_add(&table[i], &table[i - 1], p);
		} else {
			point_double(&table[i], &table[i / 2]);
		}
	}
	point_identity(&acc);
	for (unsigned i = 0; i < 64; i++) {
		if (i) {
			for (unsigned d = 0; d < WINDOW_BITS; d++) point_double(&acc, &acc);
		}
		uint32_t nib = (uint32_t)(k[i / 2] >> ((i & 1) ? 0 : 4)) & 0xf;
		table_select(&t, table, nib);
		point_add(&acc, &acc, &t);
	}
	*r = acc;
	wipe(table, sizeof(table));
	wipe(&t, sizeof(t));
	wipe(&acc, sizeof(acc));
}

static void point_base(point *g) {
	memcpy(g->x, GX_MONT, sizeof(u256));
	memcpy(g->y, GY_MONT, sizeof(u256));
	memcpy(g->z, MOD_P.one, sizeof(u256));
}

// The affine coordinates of p, out of Montgomery form. The point at infinity gives (0, 0).
static void point_affine(u256 x, u256 y, const point *p) {
	u256 zinv, t;
	mont_inv(zinv, p->z, &MOD_P);
	fp_mul(t, p->x, zinv);
	mont_from(x, t, &MOD_P);
	fp_mul(t, p->y, zinv);
	mont_from(y, t, &MOD_P);
}

static void point_encode(uint8_t pub[HW_P256_PUB_LEN], const point *p) {
	u256 x, y;
	point_affine(x, y, p);
	pub[0] = 0x04;
	u256_to_be(pub + 1, x);
	u256_to_be(pub + 33, y);
}

// The point pub (0x04 || X || Y) when X, Y < p and it lies on y^2 = x^3 - 3x + b. Public data.
static int point_decode(point *r, const uint8_t pub[HW_P256_PUB_LEN]) {
	if (pub[0] != 0x04) return -1;
	u256 x, y, t;
	u256_from_be(x, pub + 1);
	u256_from_be(y, pub + 33);
	if (u256_sub(t, x, MOD_P.m) == 0 || u256_sub(t, y, MOD_P.m) == 0) return -1;
	mont_to(r->x, x, &MOD_P);
	mont_to(r->y, y, &MOD_P);
	memcpy(r->z, MOD_P.one, sizeof(u256));
	u256 lhs, rhs;
	fp_mul(lhs, r->y, r->y);
	fp_mul(rhs, r->x, r->x);
	fp_mul(rhs, rhs, r->x);
	fp_add(t, r->x, r->x);
	fp_add(t, t, r->x);
	fp_sub(rhs, rhs, t);
	fp_add(rhs, rhs, B_MONT);
	return memcmp(lhs, rhs, sizeof(u256)) == 0 ? 0 : -1;
}

int hw_p256_public(const uint8_t priv[HW_P256_PRIV_LEN], uint8_t pub[HW_P256_PUB_LEN]) {
	u256 d;
	u256_from_be(d, priv);
	uint32_t ok = u256_in_range(d, MOD_N.m);
	wipe(d, sizeof(d));
	if (!ok) return -1;
	point g, q;
	point_base(&g);
	point_mul(&q, &g, priv);
	point_encode(pub, &q);
	return 0;
}

int hw_p256_keygen(uint8_t priv[HW_P256_PRIV_LEN], uint8_t pub[HW_P256_PUB_LEN]) {
	// Rejection sampling: a draw is out of range with probability about 2^-32.
	for (int tries = 0; tries < 64; tries++) {
		if (hw_sys_random(priv, HW_P256_PRIV_LEN) != 0) return -1;
		if (hw_p256_public(priv, pub) == 0) return 0;
	}
	return -1;
}

int hw_p256_public_valid(const uint8_t pub[HW_P256_PUB_LEN]) {
	point q;
	return point_decode(&q, pub) == 0;
}

// DER INTEGER of a non-negative 32-byte big-endian value: minimal, with a 0x00 in front of a set
// top bit. Returns the bytes written (at most 35). The value is a public signature half.
static size_t der_put_int(uint8_t *out, const uint8_t v[32]) {
	size_t i = 0;
	while (i < 31 && v[i] == 0) i++;
	size_t pad = (v[i] & 0x80) ? 1 : 0;
	size_t len = 32 - i + pad;
	out[0] = 0x02;
	out[1] = (uint8_t)len;
	if (pad) out[2] = 0;
	memcpy(out + 2 + pad, v + i, 32 - i);
	return 2 + len;
}

// Reads one DER INTEGER at *p into a 32-byte value. Strict: minimal, non-negative, at most 32
// significant bytes. Returns 0 and advances *p, or -1.
static int der_get_int(const uint8_t **p, const uint8_t *end, uint8_t v[32]) {
	const uint8_t *q = *p;
	if (end - q < 2 || q[0] != 0x02) return -1;
	size_t len = q[1];
	q += 2;
	if (len == 0 || len > 33 || (size_t)(end - q) < len) return -1;
	if (q[0] & 0x80) return -1;                            // negative
	if (len > 1 && q[0] == 0 && !(q[1] & 0x80)) return -1; // not minimal
	if (len == 33 && q[0] != 0) return -1;                 // over 256 bits
	if (len == 33) {
		q++;
		len--;
	}
	memset(v, 0, 32);
	memcpy(v + 32 - len, q, len);
	*p = q + len;
	return 0;
}

// out = HMAC-SHA-256(key, data), with out free to alias either input.
static void hmac(const uint8_t key[HW_SHA256_LEN], const uint8_t *data, size_t len, uint8_t out[HW_SHA256_LEN]) {
	uint8_t t[HW_SHA256_LEN];
	hw_hmac_sha256(key, HW_SHA256_LEN, data, len, t);
	memcpy(out, t, HW_SHA256_LEN);
	wipe(t, sizeof(t));
}

int hw_p256_sign(const uint8_t priv[HW_P256_PRIV_LEN], const uint8_t digest[32], uint8_t sig[HW_P256_SIG_DER_MAX]) {
	u256 d, z, k, r, s, t, u;
	u256_from_be(d, priv);
	if (!u256_in_range(d, MOD_N.m)) {
		wipe(d, sizeof(d));
		return -1;
	}
	u256_from_be(t, digest);
	u256_reduce_once(z, t, MOD_N.m); // bits2int: qlen = hlen = 256, so the digest as it is, mod n

	// RFC 6979 section 3.2, with HMAC-SHA-256. buf holds V || tag || int2octets(x) || bits2octets(h1).
	uint8_t kk[HW_SHA256_LEN], v[HW_SHA256_LEN], buf[HW_SHA256_LEN + 1 + 64], kb[32], rb[32], sb[32];
	memset(kk, 0x00, sizeof(kk));
	memset(v, 0x01, sizeof(v));
	memcpy(buf + HW_SHA256_LEN + 1, priv, 32);
	u256_to_be(buf + HW_SHA256_LEN + 1 + 32, z);
	for (uint8_t tag = 0; tag < 2; tag++) {
		memcpy(buf, v, HW_SHA256_LEN);
		buf[HW_SHA256_LEN] = tag;
		hmac(kk, buf, sizeof(buf), kk);
		hmac(kk, v, sizeof(v), v);
	}

	point g, kg;
	point_base(&g);
	u256 dm, zm;
	mont_to(dm, d, &MOD_N);
	mont_to(zm, z, &MOD_N);
	int len = -1;
	for (int tries = 0; tries < 64; tries++) {
		hmac(kk, v, sizeof(v), v);
		memcpy(kb, v, 32);
		u256_from_be(k, kb);
		// Out of range (probability about 2^-32) or a zero r or s (about 2^-256): the next k.
		if (u256_in_range(k, MOD_N.m)) {
			point_mul(&kg, &g, kb);
			point_affine(t, u, &kg);
			u256_reduce_once(r, t, MOD_N.m);
			if (!u256_is_zero_mask(r)) {
				u256 km, rm;
				mont_to(km, k, &MOD_N);
				mont_inv(km, km, &MOD_N);
				mont_to(rm, r, &MOD_N);
				mont_mul(t, rm, dm, &MOD_N);
				mont_add(t, t, zm, &MOD_N);
				mont_mul(t, t, km, &MOD_N);
				mont_from(s, t, &MOD_N);
				wipe(km, sizeof(km));
				if (!u256_is_zero_mask(s)) {
					u256_to_be(rb, r);
					u256_to_be(sb, s);
					size_t n = der_put_int(sig + 2, rb);
					n += der_put_int(sig + 2 + n, sb);
					sig[0] = 0x30;
					sig[1] = (uint8_t)n;
					len = (int)(n + 2);
					break;
				}
			}
		}
		memcpy(buf, v, HW_SHA256_LEN);
		buf[HW_SHA256_LEN] = 0x00;
		hmac(kk, buf, HW_SHA256_LEN + 1, kk);
		hmac(kk, v, sizeof(v), v);
	}
	wipe(d, sizeof(d));
	wipe(dm, sizeof(dm));
	wipe(k, sizeof(k));
	wipe(kb, sizeof(kb));
	wipe(kk, sizeof(kk));
	wipe(v, sizeof(v));
	wipe(buf, sizeof(buf));
	wipe(&kg, sizeof(kg));
	wipe(t, sizeof(t));
	return len;
}

int hw_p256_verify(const uint8_t pub[HW_P256_PUB_LEN], const uint8_t digest[32], const uint8_t *sig, size_t sig_len) {
	if (!sig || sig_len < 8 || sig_len > HW_P256_SIG_DER_MAX) return 0;
	// SEQUENCE in the short form: its content is at most 70 bytes, and DER allows no other.
	if (sig[0] != 0x30 || sig[1] != sig_len - 2) return 0;
	const uint8_t *p = sig + 2, *end = sig + sig_len;
	uint8_t rb[32], sb[32];
	if (der_get_int(&p, end, rb) != 0 || der_get_int(&p, end, sb) != 0 || p != end) return 0;
	u256 r, s, z, t;
	u256_from_be(r, rb);
	u256_from_be(s, sb);
	if (!u256_in_range(r, MOD_N.m) || !u256_in_range(s, MOD_N.m)) return 0;
	point q;
	if (point_decode(&q, pub) != 0) return 0;

	u256_from_be(t, digest);
	u256_reduce_once(z, t, MOD_N.m);
	u256 w, u1, u2;
	mont_to(w, s, &MOD_N);
	mont_inv(w, w, &MOD_N);
	mont_to(t, z, &MOD_N);
	mont_mul(t, t, w, &MOD_N);
	mont_from(u1, t, &MOD_N);
	mont_to(t, r, &MOD_N);
	mont_mul(t, t, w, &MOD_N);
	mont_from(u2, t, &MOD_N);

	uint8_t u1b[32], u2b[32];
	u256_to_be(u1b, u1);
	u256_to_be(u2b, u2);
	point g, a, b;
	point_base(&g);
	point_mul(&a, &g, u1b);
	point_mul(&b, &q, u2b);
	point_add(&a, &a, &b);
	if (u256_is_zero_mask(a.z)) return 0;
	u256 x, y;
	point_affine(x, y, &a);
	u256_reduce_once(x, x, MOD_N.m);
	return memcmp(x, r, sizeof(u256)) == 0;
}
