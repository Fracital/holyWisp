/*
 * tests/test_sha256.c - SHA-256 (FIPS 180-4 examples), HMAC-SHA-256 (RFC 4231), HKDF (RFC 5869)
 * and HKDF-Expand-Label, the last through the QUIC Initial keys of RFC 9001 Appendix A.1.
 */
#include "holywisp/sha256.h"

#include "test.h"

#include <stdlib.h>
#include <string.h>

static uint8_t nibble(char c) {
	return (uint8_t)(c <= '9' ? c - '0' : (c | 0x20) - 'a' + 10);
}

static void hex(const char *s, uint8_t *out, size_t n) {
	for (size_t i = 0; i < n; i++) out[i] = (uint8_t)(nibble(s[2 * i]) << 4 | nibble(s[2 * i + 1]));
}

#define CHECK_HEX(got, n, want)                                                                    \
	do {                                                                                           \
		uint8_t want_[256];                                                                        \
		CHECK(strlen(want) == 2 * (n), "vector length %zu != %zu", strlen(want), 2 * (size_t)(n)); \
		hex(want, want_, n);                                                                       \
		CHECK(memcmp(got, want_, n) == 0, "bytes differ from %s", want);                           \
	} while (0)

static void test_sha256_vectors(void) {
	uint8_t d[HW_SHA256_LEN];
	hw_sha256("", 0, d);
	CHECK_HEX(d, 32, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
	hw_sha256("abc", 3, d);
	CHECK_HEX(d, 32, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
	const char *m448 = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
	hw_sha256(m448, strlen(m448), d);
	CHECK_HEX(d, 32, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
}

// A million 'a's fed in uneven pieces, so every path of the block buffer is taken.
static void test_sha256_incremental(void) {
	char *a = malloc(1000000);
	CHECK(a != NULL, "malloc");
	memset(a, 'a', 1000000);
	hw_sha256_ctx c;
	hw_sha256_init(&c);
	size_t off = 0, step = 1;
	while (off < 1000000) {
		size_t n = step < 1000000 - off ? step : 1000000 - off;
		hw_sha256_update(&c, a + off, n);
		off += n;
		step = step * 7 % 997 + 1;
	}
	uint8_t d[HW_SHA256_LEN];
	hw_sha256_final(&c, d);
	CHECK_HEX(d, 32, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
	// A copied context forks the hash: both halves finish on their own.
	hw_sha256_ctx x, y;
	hw_sha256_init(&x);
	hw_sha256_update(&x, "ab", 2);
	y = x;
	hw_sha256_update(&x, "c", 1);
	hw_sha256_final(&x, d);
	CHECK_HEX(d, 32, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
	hw_sha256_update(&y, "c", 1);
	hw_sha256_final(&y, d);
	CHECK_HEX(d, 32, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
	free(a);
}

static void test_hmac_rfc4231(void) {
	uint8_t key[131], d[HW_SHA256_LEN];
	memset(key, 0x0b, 20);
	hw_hmac_sha256(key, 20, "Hi There", 8, d);
	CHECK_HEX(d, 32, "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
	memset(key, 0xaa, 131); // longer than a block: hashed first
	const char *m = "Test Using Larger Than Block-Size Key - Hash Key First";
	hw_hmac_sha256(key, 131, m, strlen(m), d);
	CHECK_HEX(d, 32, "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");
}

static void test_hkdf_rfc5869(void) {
	uint8_t ikm[22], salt[13], info[10], prk[HW_SHA256_LEN], okm[42];
	memset(ikm, 0x0b, sizeof ikm);
	for (int i = 0; i < 13; i++) salt[i] = (uint8_t)i;
	for (int i = 0; i < 10; i++) info[i] = (uint8_t)(0xf0 + i);
	hw_hkdf_extract(salt, sizeof salt, ikm, sizeof ikm, prk);
	CHECK_HEX(prk, 32, "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
	CHECK_EQ(hw_hkdf_expand(prk, info, sizeof info, okm, sizeof okm), 0);
	CHECK_HEX(okm, 42, "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");
	uint8_t big[1];
	CHECK_EQ(hw_hkdf_expand(prk, NULL, 0, big, 255 * HW_SHA256_LEN + 1), -1);
}

// RFC 9001 A.1: the Initial secrets and the client's packet keys for DCID 0x8394c8f03e515708.
static void test_expand_label_quic_initial(void) {
	uint8_t salt[20], dcid[8], initial[32], client[32], server[32], key[16], iv[12], hp[16];
	hex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a", salt, sizeof salt);
	hex("8394c8f03e515708", dcid, sizeof dcid);
	hw_hkdf_extract(salt, sizeof salt, dcid, sizeof dcid, initial);
	CHECK_HEX(initial, 32, "7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44");
	CHECK_EQ(hw_hkdf_expand_label(initial, "client in", NULL, 0, client, 32), 0);
	CHECK_HEX(client, 32, "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea");
	CHECK_EQ(hw_hkdf_expand_label(initial, "server in", NULL, 0, server, 32), 0);
	CHECK_HEX(server, 32, "3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b");
	CHECK_EQ(hw_hkdf_expand_label(client, "quic key", NULL, 0, key, 16), 0);
	CHECK_HEX(key, 16, "1f369613dd76d5467730efcbe3b1a22d");
	CHECK_EQ(hw_hkdf_expand_label(client, "quic iv", NULL, 0, iv, 12), 0);
	CHECK_HEX(iv, 12, "fa044b2f42a3fd3b46fb255c");
	CHECK_EQ(hw_hkdf_expand_label(client, "quic hp", NULL, 0, hp, 16), 0);
	CHECK_HEX(hp, 16, "9f50449e04a0e810283a1e9933adedd2");
	char long_label[251];
	memset(long_label, 'x', 250);
	long_label[250] = '\0';
	CHECK_EQ(hw_hkdf_expand_label(client, long_label, NULL, 0, key, 16), -1);
}

int main(void) {
	RUN(test_sha256_vectors);
	RUN(test_sha256_incremental);
	RUN(test_hmac_rfc4231);
	RUN(test_hkdf_rfc5869);
	RUN(test_expand_label_quic_initial);
	return 0;
}
