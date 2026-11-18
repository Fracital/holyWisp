/*
 * tests/test_ecc.c - X25519 (RFC 7748 sections 5.2 and 6.1, the iterated vectors, small-order
 * points) and ECDSA P-256 (RFC 6979 A.2.5, multiples of G checked against Python's
 * cryptography, round trips, and a verify that refuses every tampered or malformed input).
 * HW_TEST_SLOW=1 adds the 1,000,000-iteration X25519 vector (minutes under the sanitizers).
 */
#include "holywisp/ecc.h"
#include "holywisp/hw.h"
#include "holywisp/sha256.h"
#include "holywisp/sys.h"

#include "test.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>

static int nibble(char c) {
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	return -1;
}

static void hex(const char *s, uint8_t *out, size_t n) {
	CHECK(strlen(s) == 2 * n, "vector length %zu != %zu", strlen(s), 2 * n);
	for (size_t i = 0; i < n; i++) {
		int hi = nibble(s[2 * i]), lo = nibble(s[2 * i + 1]);
		CHECK(hi >= 0 && lo >= 0, "bad hex in %s", s);
		out[i] = (uint8_t)(hi << 4 | lo);
	}
}

#define CHECK_HEX(got, n, want)                                          \
	do {                                                                 \
		uint8_t want_[128];                                              \
		hex(want, want_, n);                                             \
		CHECK(memcmp(got, want_, n) == 0, "bytes differ from %s", want); \
	} while (0)

static double now_s(void) {
	struct timespec ts;
	timespec_get(&ts, TIME_UTC);
	return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static void x25519_check(const char *k_hex, const char *u_hex, const char *want) {
	uint8_t k[32], u[32], out[32];
	hex(k_hex, k, 32);
	hex(u_hex, u, 32);
	CHECK(hw_x25519(out, k, u) == 0, "x25519 failed");
	CHECK_HEX(out, 32, want);
}

static void test_x25519_vectors(void) {
	x25519_check("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
	             "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
	             "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");
	// This u has bit 255 set, which must be ignored.
	x25519_check("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
	             "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
	             "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957");
}

// RFC 7748 section 5.2: k = u = 9, then `count` times k, u = X25519(k, u), k.
static void x25519_iterate(uint8_t k[32], long count) {
	uint8_t u[32], out[32];
	memset(k, 0, 32);
	k[0] = 9;
	memcpy(u, k, 32);
	for (long i = 0; i < count; i++) {
		CHECK(hw_x25519(out, k, u) == 0, "iteration %ld", i);
		memcpy(u, k, 32);
		memcpy(k, out, 32);
	}
}

static void test_x25519_iterated(void) {
	uint8_t k[32];
	x25519_iterate(k, 1);
	CHECK_HEX(k, 32, "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079");
	double t0 = now_s();
	x25519_iterate(k, 1000);
	double t1 = now_s();
	CHECK_HEX(k, 32, "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51");
	printf("# x25519: %.1f us per operation\n", (t1 - t0) * 1e6 / 1000);
	const char *slow = getenv("HW_TEST_SLOW");
	if (slow && *slow == '1') {
		x25519_iterate(k, 1000000);
		CHECK_HEX(k, 32, "7c3911e0ab2586fd864497297e575e6f3bc601c0883c30df5f4dd2d24f665424");
	}
}

static void test_x25519_dh(void) {
	uint8_t a[32], b[32], apub[32], bpub[32], s1[32], s2[32];
	static const uint8_t nine[32] = {9};
	hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a", a, 32);
	hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb", b, 32);
	CHECK(hw_x25519(apub, a, nine) == 0, "alice pub");
	CHECK(hw_x25519(bpub, b, nine) == 0, "bob pub");
	CHECK_HEX(apub, 32, "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
	CHECK_HEX(bpub, 32, "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
	CHECK(hw_x25519(s1, a, bpub) == 0, "alice shared");
	CHECK(hw_x25519(s2, b, apub) == 0, "bob shared");
	CHECK_HEX(s1, 32, "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
	CHECK_HEX(s2, 32, "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

	// Fresh key pairs agree with each other.
	for (int i = 0; i < 8; i++) {
		CHECK(hw_x25519_keygen(a, apub) == 0, "keygen");
		CHECK(hw_x25519_keygen(b, bpub) == 0, "keygen");
		CHECK(hw_x25519(s1, a, bpub) == 0 && hw_x25519(s2, b, apub) == 0, "shared");
		CHECK(memcmp(s1, s2, 32) == 0, "keygen pairs disagree");
	}
}

// Every point whose order divides 8 (and their non-canonical encodings, with and without bit 255)
// gives the all-zero output, which hw_x25519 refuses.
static void test_x25519_small_order(void) {
	static const char *const points[] = {
	    "0000000000000000000000000000000000000000000000000000000000000000", // 0, order 2
	    "0100000000000000000000000000000000000000000000000000000000000000", // 1, order 4
	    "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800", // order 8
	    "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157", // order 8
	    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // p - 1
	    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // p, i.e. 0
	    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // p + 1, i.e. 1
	    "0000000000000000000000000000000000000000000000000000000000000080", // 0 with bit 255
	    "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b880", // order 8 with bit 255
	};
	uint8_t k[32], u[32], out[32];
	for (size_t i = 0; i < HW_ARRAY_LEN(points); i++) {
		hex(points[i], u, 32);
		for (int j = 0; j < 4; j++) {
			CHECK(hw_sys_random(k, sizeof(k)) == 0, "random");
			CHECK(hw_x25519(out, k, u) == -1, "point %zu not refused", i);
			uint8_t acc = 0;
			for (int b = 0; b < 32; b++) acc |= out[b];
			CHECK(acc == 0, "point %zu: output not zero", i);
		}
	}
}

// RFC 6979 A.2.5: the P-256 key and its SHA-256 signatures of "sample" and "test".
static const char *const A25_PRIV = "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721";
static const char *const A25_PUB = "0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6"
                                   "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299";

static void test_p256_rfc6979(void) {
	uint8_t priv[32], pub[65], want_pub[65], digest[32], sig[HW_P256_SIG_DER_MAX];
	hex(A25_PRIV, priv, 32);
	hex(A25_PUB, want_pub, 65);
	CHECK(hw_p256_public(priv, pub) == 0, "public");
	CHECK(memcmp(pub, want_pub, 65) == 0, "A.2.5 public key");
	CHECK(hw_p256_public_valid(pub) == 1, "A.2.5 public key valid");

	hw_sha256("sample", 6, digest);
	int n = hw_p256_sign(priv, digest, sig);
	CHECK_EQ(n, 72);
	CHECK_HEX(sig, 72,
	          "3046022100efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716"
	          "022100f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8");
	CHECK(hw_p256_verify(pub, digest, sig, (size_t)n) == 1, "verify sample");

	hw_sha256("test", 4, digest);
	n = hw_p256_sign(priv, digest, sig);
	CHECK_EQ(n, 71);
	CHECK_HEX(sig, 71,
	          "3045022100f1abb023518351cd71d881567b1ea663ed3efcf6c5132b354f28d3b0b7d38367"
	          "0220019f4113742a2b14bd25926b49c649155f267e60d3814b4c0cc84250e46f0083");
	CHECK(hw_p256_verify(pub, digest, sig, (size_t)n) == 1, "verify test");
}

static void scalar(uint8_t out[32], unsigned v) {
	memset(out, 0, 32);
	out[28] = (uint8_t)(v >> 24);
	out[29] = (uint8_t)(v >> 16);
	out[30] = (uint8_t)(v >> 8);
	out[31] = (uint8_t)v;
}

static void test_p256_public_edges(void) {
	uint8_t k[32], pub[65];
	static const char *const n_hex = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";
	scalar(k, 0);
	CHECK(hw_p256_public(k, pub) == -1, "0 accepted");
	hex(n_hex, k, 32);
	CHECK(hw_p256_public(k, pub) == -1, "n accepted");
	k[31] = 0x52; // n + 1
	CHECK(hw_p256_public(k, pub) == -1, "n + 1 accepted");
	memset(k, 0xff, 32);
	CHECK(hw_p256_public(k, pub) == -1, "2^256 - 1 accepted");

	// 1, 2 and 3 times G, and (n - 1) G = -G, from Python's cryptography.
	scalar(k, 1);
	CHECK(hw_p256_public(k, pub) == 0, "1");
	CHECK_HEX(pub, 65,
	          "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
	          "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5");
	scalar(k, 2);
	CHECK(hw_p256_public(k, pub) == 0, "2");
	CHECK_HEX(pub, 65,
	          "047cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978"
	          "07775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1");
	scalar(k, 3);
	CHECK(hw_p256_public(k, pub) == 0, "3");
	CHECK_HEX(pub, 65,
	          "045ecbe4d1a6330a44c8f7ef951d4bf165e6c6b721efada985fb41661bc6e7fd6c"
	          "8734640c4998ff7e374b06ce1a64a2ecd82ab036384fb83d9a79b127a27d5032");
	hex(n_hex, k, 32);
	k[31] = 0x50;
	CHECK(hw_p256_public(k, pub) == 0, "n - 1");
	CHECK_HEX(pub, 65,
	          "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
	          "b01cbd1c01e58065711814b583f061e9d431cca994cea1313449bf97c840ae0a");
	CHECK(hw_p256_public_valid(pub) == 1, "-G valid");
}

static void test_p256_roundtrip(void) {
	uint8_t priv[32], pub[65], pub2[65], digest[32], sig[HW_P256_SIG_DER_MAX];
	double sign_s = 0, verify_s = 0;
	const int rounds = 16;
	for (int i = 0; i < rounds; i++) {
		CHECK(hw_p256_keygen(priv, pub) == 0, "keygen");
		CHECK(hw_p256_public(priv, pub2) == 0 && memcmp(pub, pub2, 65) == 0, "keygen public");
		CHECK(hw_p256_public_valid(pub) == 1, "keygen point valid");
		CHECK(hw_sys_random(digest, sizeof(digest)) == 0, "random");
		double t0 = now_s();
		int n = hw_p256_sign(priv, digest, sig);
		double t1 = now_s();
		CHECK(n >= 8 && n <= HW_P256_SIG_DER_MAX, "sign length %d", n);
		CHECK(hw_p256_verify(pub, digest, sig, (size_t)n) == 1, "round trip %d", i);
		double t2 = now_s();
		sign_s += t1 - t0;
		verify_s += t2 - t1;

		uint8_t sig2[HW_P256_SIG_DER_MAX];
		CHECK(hw_p256_sign(priv, digest, sig2) == n && memcmp(sig, sig2, (size_t)n) == 0, "not deterministic");

		uint8_t d2[32];
		memcpy(d2, digest, 32);
		d2[i % 32] ^= (uint8_t)(1u << (i % 8));
		CHECK(hw_p256_verify(pub, d2, sig, (size_t)n) == 0, "tampered digest accepted");
		// Every byte of the signature flipped, in two of the rounds (a verify is slow under ASan).
		for (int b = 0; b < n && i < 2; b++) {
			uint8_t t[HW_P256_SIG_DER_MAX];
			memcpy(t, sig, (size_t)n);
			t[b] ^= (uint8_t)(1u << ((b + i) % 8));
			CHECK(hw_p256_verify(pub, digest, t, (size_t)n) == 0, "signature with byte %d flipped accepted", b);
		}
		uint8_t other_priv[32], other_pub[65];
		CHECK(hw_p256_keygen(other_priv, other_pub) == 0, "keygen");
		CHECK(hw_p256_verify(other_pub, digest, sig, (size_t)n) == 0, "wrong key accepted");
		uint8_t bad[65];
		memcpy(bad, pub, 65);
		bad[64] ^= 1; // off the curve
		CHECK(hw_p256_public_valid(bad) == 0, "point off the curve valid");
		CHECK(hw_p256_verify(bad, digest, sig, (size_t)n) == 0, "key off the curve accepted");
	}
	printf("# p256: sign %.0f us, verify %.0f us\n", sign_s * 1e6 / rounds, verify_s * 1e6 / rounds);
}

// Builds SEQUENCE { INTEGER r, INTEGER s } from the given INTEGER contents, unchecked.
static size_t der_sig(uint8_t *out, const uint8_t *r, size_t rl, const uint8_t *s, size_t sl) {
	out[0] = 0x30;
	out[1] = (uint8_t)(4 + rl + sl);
	out[2] = 0x02;
	out[3] = (uint8_t)rl;
	memcpy(out + 4, r, rl);
	out[4 + rl] = 0x02;
	out[5 + rl] = (uint8_t)sl;
	memcpy(out + 6 + rl, s, sl);
	return 6 + rl + sl;
}

static void test_p256_verify_malformed(void) {
	uint8_t priv[32], pub[65], digest[32], sig[HW_P256_SIG_DER_MAX], buf[160];
	hex(A25_PRIV, priv, 32);
	hex(A25_PUB, pub, 65);
	hw_sha256("sample", 6, digest);
	int n = hw_p256_sign(priv, digest, sig);
	CHECK_EQ(n, 72);

	// Every truncation, from a heap copy of exactly that length so ASan sees any overread.
	for (int len = 0; len < n; len++) {
		uint8_t *t = malloc(len ? (size_t)len : 1);
		CHECK(t != NULL, "malloc");
		memcpy(t, sig, (size_t)len);
		CHECK(hw_p256_verify(pub, digest, t, (size_t)len) == 0, "truncated to %d accepted", len);
		free(t);
	}
	CHECK(hw_p256_verify(pub, digest, NULL, 0) == 0, "NULL accepted");
	// Trailing bytes, inside and outside the SEQUENCE.
	memcpy(buf, sig, 72);
	buf[72] = 0;
	CHECK(hw_p256_verify(pub, digest, buf, 73) == 0, "trailing byte accepted");
	buf[1] = 71;
	CHECK(hw_p256_verify(pub, digest, buf, 73) == 0, "trailing byte in SEQUENCE accepted");
	// The long form of the SEQUENCE length.
	buf[0] = 0x30;
	buf[1] = 0x81;
	buf[2] = 70;
	memcpy(buf + 3, sig + 2, 70);
	CHECK(hw_p256_verify(pub, digest, buf, 73) == 0, "long-form length accepted");
	// Wrong tags.
	memcpy(buf, sig, 72);
	buf[0] = 0x31;
	CHECK(hw_p256_verify(pub, digest, buf, 72) == 0, "SET accepted");
	memcpy(buf, sig, 72);
	buf[2] = 0x03;
	CHECK(hw_p256_verify(pub, digest, buf, 72) == 0, "BIT STRING r accepted");

	const uint8_t *r = sig + 4, *s = sig + 4 + 33 + 2; // 33-byte INTEGER contents, 0x00 first
	size_t m = der_sig(buf, r, 33, s, 33);
	CHECK(hw_p256_verify(pub, digest, buf, m) == 1, "rebuilt signature rejected");
	// r without its required 0x00: negative.
	m = der_sig(buf, r + 1, 32, s, 33);
	CHECK(hw_p256_verify(pub, digest, buf, m) == 0, "negative r accepted");
	// An extra, non-minimal 0x00.
	uint8_t padded[34] = {0};
	memcpy(padded + 1, r, 33);
	m = der_sig(buf, padded, 34, s, 33);
	CHECK(hw_p256_verify(pub, digest, buf, m) == 0, "non-minimal r accepted");

	// r or s of 0, n and n + 1, and a 33-byte value over 2^256.
	uint8_t nbytes[33] = {0};
	hex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", nbytes + 1, 32);
	static const uint8_t zero[1] = {0};
	m = der_sig(buf, zero, 1, s, 33);
	CHECK(hw_p256_verify(pub, digest, buf, m) == 0, "r = 0 accepted");
	m = der_sig(buf, r, 33, zero, 1);
	CHECK(hw_p256_verify(pub, digest, buf, m) == 0, "s = 0 accepted");
	m = der_sig(buf, nbytes, 33, s, 33);
	CHECK(hw_p256_verify(pub, digest, buf, m) == 0, "r = n accepted");
	m = der_sig(buf, r, 33, nbytes, 33);
	CHECK(hw_p256_verify(pub, digest, buf, m) == 0, "s = n accepted");
	uint8_t big[33];
	memset(big, 0xff, 33);
	big[0] = 0x01;
	m = der_sig(buf, big, 33, s, 33);
	CHECK(hw_p256_verify(pub, digest, buf, m) == 0, "r over 256 bits accepted");
	// INTEGER lengths that run past the SEQUENCE.
	memcpy(buf, sig, 72);
	buf[3] = 0x7f;
	CHECK(hw_p256_verify(pub, digest, buf, 72) == 0, "r length past the end accepted");
	memcpy(buf, sig, 72);
	buf[4 + 33 + 1] = 0x22;
	CHECK(hw_p256_verify(pub, digest, buf, 72) == 0, "s length past the end accepted");
	memcpy(buf, sig, 72);
	buf[3] = 0;
	CHECK(hw_p256_verify(pub, digest, buf, 72) == 0, "empty r accepted");

	// Bad public keys: compressed prefix, x = p, all zero.
	uint8_t badpub[65];
	memcpy(badpub, pub, 65);
	badpub[0] = 0x02;
	CHECK(hw_p256_verify(badpub, digest, sig, 72) == 0, "prefix 02 accepted");
	CHECK(hw_p256_public_valid(badpub) == 0, "prefix 02 valid");
	memset(badpub, 0, 65);
	badpub[0] = 0x04;
	CHECK(hw_p256_public_valid(badpub) == 0, "(0, 0) valid");
	hex("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", badpub + 1, 32);
	CHECK(hw_p256_public_valid(badpub) == 0, "x = p valid");
	// G with y replaced by p: a coordinate that is not reduced.
	uint8_t gp[65];
	hex("046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
	    "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
	    gp, 65);
	CHECK(hw_p256_public_valid(gp) == 1, "G valid");
	hex("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", gp + 33, 32);
	CHECK(hw_p256_public_valid(gp) == 0, "y = p valid");

	// Garbage of every length up to the maximum.
	for (size_t len = 0; len <= sizeof(buf); len++) {
		uint8_t *t = malloc(len ? len : 1);
		CHECK(t != NULL, "malloc");
		CHECK(hw_sys_random(t, len ? len : 1) == 0, "random");
		if (len >= 2) {
			t[0] = 0x30;
			t[1] = (uint8_t)(len - 2);
		}
		CHECK(hw_p256_verify(pub, digest, t, len) == 0, "garbage of %zu accepted", len);
		free(t);
	}
}

int main(void) {
	RUN(test_x25519_vectors);
	RUN(test_x25519_iterated);
	RUN(test_x25519_dh);
	RUN(test_x25519_small_order);
	RUN(test_p256_rfc6979);
	RUN(test_p256_public_edges);
	RUN(test_p256_roundtrip);
	RUN(test_p256_verify_malformed);
	return 0;
}
