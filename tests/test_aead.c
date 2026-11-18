/*
 * tests/test_aead.c - AES-128 (FIPS 197 C.1), AES-128-GCM (McGrew and Viega's test cases 1 to 4),
 * ChaCha20, Poly1305 and ChaCha20-Poly1305 (RFC 8439 sections 2.3.2 to 2.8.2 and A.1 to A.5), the
 * header protection masks of RFC 9001 A.2 and A.5, and length sweeps whose digests were made once
 * with Python's `cryptography` 48 (OpenSSL 3.5) and are checked in here. The ChaCha20 and
 * Poly1305 cases run twice: on the kernels the CPU picks, then on the base ones.
 */
#include "holywisp/aead.h"
#include "holywisp/hw.h"
#include "holywisp/sha256.h"

#include "common/aead_internal.h"
#include "test.h"

#include <stdlib.h>
#include <string.h>

#define HEX_MAX 512

static unsigned nibble(char c) {
	if (c >= '0' && c <= '9') return (unsigned)(c - '0');
	if (c >= 'a' && c <= 'f') return (unsigned)(c - 'a' + 10);
	CHECK(c >= 'A' && c <= 'F', "not a hex digit: %c", c);
	return (unsigned)(c - 'A' + 10);
}

static void hex(const char *s, uint8_t *out, size_t n) {
	for (size_t i = 0; i < n; i++) out[i] = (uint8_t)(nibble(s[2 * i]) << 4 | nibble(s[2 * i + 1]));
}

#define CHECK_HEX(got, n, want)                                                                    \
	do {                                                                                           \
		uint8_t want_[HEX_MAX];                                                                    \
		CHECK(strlen(want) == 2 * (n), "vector length %zu != %zu", strlen(want), 2 * (size_t)(n)); \
		hex(want, want_, n);                                                                       \
		CHECK(memcmp(got, want_, n) == 0, "bytes differ from %s", want);                           \
	} while (0)

static const char SUNSCREEN[] = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the "
                                "future, sunscreen would be it.";
static const char IETF[] = "Any submission to the IETF intended by the Contributor for publication as all or part of "
                           "an IETF Internet-Draft or RFC and any statement made within the context of an IETF "
                           "activity is considered an \"IETF Contribution\". Such statements include oral statements "
                           "in IETF sessions, as well as written and electronic communications made at any time or "
                           "place, which are addressed to";
static const char JABBERWOCKY[] = "'Twas brillig, and the slithy toves\nDid gyre and gimble in the wabe:\nAll mimsy "
                                  "were the borogoves,\nAnd the mome raths outgrabe.";
static const char *const KEY_1C92 = "1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0";

static void pattern(uint8_t *p, size_t n, unsigned a, unsigned b) {
	for (size_t i = 0; i < n; i++) p[i] = (uint8_t)(i * a + b);
}

static void test_ct_equal(void) {
	uint8_t a[32], b[32];
	pattern(a, 32, 3, 1);
	memcpy(b, a, 32);
	CHECK_EQ(hw_ct_equal(a, b, 32), 1);
	CHECK_EQ(hw_ct_equal(a, b, 0), 1);
	for (int i = 0; i < 32; i++) {
		for (int bit = 0; bit < 8; bit++) {
			b[i] ^= (uint8_t)(1 << bit);
			CHECK_EQ(hw_ct_equal(a, b, 32), 0);
			b[i] ^= (uint8_t)(1 << bit);
		}
	}
}

static void test_aes128(void) {
	uint8_t key[16], in[16], out[16];
	hw_aes128 k;
	// FIPS 197 A.1: the key expansion's first and last words.
	hex("2b7e151628aed2a6abf7158809cf4f3c", key, 16);
	hw_aes128_init(&k, key);
	CHECK_EQ(k.rk[4], 0xa0fafe17);
	CHECK_EQ(k.rk[43], 0xb6630ca6);
	// FIPS 197 C.1.
	hex("000102030405060708090a0b0c0d0e0f", key, 16);
	hex("00112233445566778899aabbccddeeff", in, 16);
	hw_aes128_init(&k, key);
	hw_aes128_encrypt(&k, in, out);
	CHECK_HEX(out, 16, "69c4e0d86a7b0430d8cdb78070b4c55a");
	// Every S-box entry many times over: four chained encryptions under 64 keys.
	hw_sha256_ctx d;
	hw_sha256_init(&d);
	for (unsigned i = 0; i < 64; i++) {
		pattern(key, 16, 37 + i, i * 11);
		pattern(in, 16, 53, i * 29);
		hw_aes128_init(&k, key);
		for (int r = 0; r < 4; r++) hw_aes128_encrypt(&k, in, in);
		hw_sha256_update(&d, in, 16);
	}
	uint8_t dig[HW_SHA256_LEN];
	hw_sha256_final(&d, dig);
	CHECK_HEX(dig, 32, "8c68597320ddfbce9875d4010d2e5499c7251bf0adb3cc2f8c55fbe8c1659bbe");
	// RFC 9001 A.2: the client Initial's header protection mask.
	hex("9f50449e04a0e810283a1e9933adedd2", key, 16);
	hex("d1b1c98dd7689fb8ec11d242b123dc9b", in, 16);
	hw_aes128_init(&k, key);
	hw_aes128_encrypt(&k, in, out);
	CHECK_HEX(out, 5, "437b9aec36");
}

// One GCM vector: seal, then open it back, in place as well.
static void gcm_case(const char *key_hex, const char *iv_hex, const char *aad_hex, const char *pt_hex,
                     const char *want) {
	uint8_t key[16], iv[12], aad[64], pt[64], ct[80], back[64];
	size_t aad_len = strlen(aad_hex) / 2, len = strlen(pt_hex) / 2;
	hex(key_hex, key, 16);
	hex(iv_hex, iv, 12);
	hex(aad_hex, aad, aad_len);
	hex(pt_hex, pt, len);
	hw_aes128gcm g;
	hw_aes128gcm_init(&g, key);
	hw_aes128gcm_seal(&g, iv, aad, aad_len, pt, len, ct);
	CHECK_HEX(ct, len + HW_AEAD_TAG, want);
	CHECK_EQ(hw_aes128gcm_open(&g, iv, aad, aad_len, ct, len + HW_AEAD_TAG, back), 0);
	CHECK(memcmp(back, pt, len) == 0, "open gave back other bytes");
	CHECK_EQ(hw_aes128gcm_open(&g, iv, aad, aad_len, ct, len + HW_AEAD_TAG, ct), 0);
	CHECK(memcmp(ct, pt, len) == 0, "open in place gave back other bytes");
}

static void test_gcm_vectors(void) {
	static const char *const p3 = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
	                              "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255";
	static const char *const c3 = "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e"
	                              "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091";
	char pt4[121], want3[192], want4[192];
	memcpy(pt4, p3, 120);
	pt4[120] = '\0';
	snprintf(want3, sizeof want3, "%s473f5985%s", c3, "4d5c2af327cd64a62cf35abd2ba6fab4");
	snprintf(want4, sizeof want4, "%s%s", c3, "5bc94fbc3221a5db94fae95ae7121a47");
	const char *zk = "00000000000000000000000000000000", *ziv = "000000000000000000000000";
	gcm_case(zk, ziv, "", "", "58e2fccefa7e3061367f1d57a4e7455a");
	gcm_case(zk, ziv, "", zk, "0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf");
	gcm_case("feffe9928665731c6d6a8f9467308308", "cafebabefacedbaddecaf888", "", p3, want3);
	gcm_case("feffe9928665731c6d6a8f9467308308", "cafebabefacedbaddecaf888", "feedfacedeadbeeffeedfacedeadbeefabaddad2",
	         pt4, want4);
}

typedef int (*open_fn)(const void *ctx, const uint8_t *nonce, const uint8_t *aad, size_t aad_len, const uint8_t *in,
                       size_t len, uint8_t *out);

static int gcm_open(const void *ctx, const uint8_t *nonce, const uint8_t *aad, size_t aad_len, const uint8_t *in,
                    size_t len, uint8_t *out) {
	return hw_aes128gcm_open(ctx, nonce, aad, aad_len, in, len, out);
}

static int chacha_open(const void *ctx, const uint8_t *nonce, const uint8_t *aad, size_t aad_len, const uint8_t *in,
                       size_t len, uint8_t *out) {
	return hw_chacha20poly1305_open(ctx, nonce, aad, aad_len, in, len, out);
}

// Every single-bit flip of the ciphertext, the tag and the AAD is refused, and the output is
// zeroed; the unflipped message still opens; a message shorter than a tag is refused.
static void reject_flips(open_fn open, const void *ctx, const uint8_t *nonce, uint8_t *aad, size_t aad_len, uint8_t *ct,
                         size_t len) {
	uint8_t out[128];
	for (size_t i = 0; i < len + HW_AEAD_TAG; i++) {
		for (int bit = 0; bit < 8; bit += 3) {
			ct[i] ^= (uint8_t)(1 << bit);
			memset(out, 0xa5, sizeof out);
			CHECK_EQ(open(ctx, nonce, aad, aad_len, ct, len + HW_AEAD_TAG, out), -1);
			for (size_t j = 0; j < len; j++) CHECK(out[j] == 0, "output byte %zu not zeroed", j);
			ct[i] ^= (uint8_t)(1 << bit);
		}
	}
	for (size_t i = 0; i < aad_len; i++) {
		aad[i] ^= 0x80;
		CHECK_EQ(open(ctx, nonce, aad, aad_len, ct, len + HW_AEAD_TAG, out), -1);
		aad[i] ^= 0x80;
	}
	CHECK_EQ(open(ctx, nonce, aad, aad_len ? aad_len - 1 : 0, ct, len + HW_AEAD_TAG, out), aad_len ? -1 : 0);
	CHECK_EQ(open(ctx, nonce, aad, aad_len, ct, HW_AEAD_TAG - 1, out), -1);
	CHECK_EQ(open(ctx, nonce, aad, aad_len, ct, len + HW_AEAD_TAG, out), 0);
	// A refused in-place open zeroes the text it was given.
	ct[0] ^= 1;
	CHECK_EQ(open(ctx, nonce, aad, aad_len, ct, len + HW_AEAD_TAG, ct), -1);
	for (size_t j = 0; j < len; j++) CHECK(ct[j] == 0, "in-place byte %zu not zeroed", j);
}

static void test_aead_rejects(void) {
	uint8_t key[32], nonce[12], aad[20], pt[70], ct[70 + HW_AEAD_TAG];
	pattern(key, 32, 5, 9);
	pattern(nonce, 12, 3, 1);
	pattern(aad, 20, 7, 2);
	pattern(pt, 70, 11, 4);
	hw_aes128gcm g;
	hw_aes128gcm_init(&g, key);
	hw_aes128gcm_seal(&g, nonce, aad, sizeof aad, pt, sizeof pt, ct);
	reject_flips(gcm_open, &g, nonce, aad, sizeof aad, ct, sizeof pt);
	hw_chacha20poly1305_seal(key, nonce, aad, sizeof aad, pt, sizeof pt, ct);
	reject_flips(chacha_open, key, nonce, aad, sizeof aad, ct, sizeof pt);
	hw_chacha20poly1305_seal(key, nonce, NULL, 0, pt, 0, ct); // an empty text has only its tag
	reject_flips(chacha_open, key, nonce, aad, 0, ct, 0);
}

// The keystream of `counter` and `nonce` (given in hex) over len bytes of in.
static void chacha_hex(const char *key_hex, uint32_t counter, const char *nonce_hex, const uint8_t *in, size_t len,
                       uint8_t *out) {
	uint8_t key[32], nonce[12];
	hex(key_hex, key, 32);
	hex(nonce_hex, nonce, 12);
	hw_chacha20_xor(key, counter, nonce, in, out, len);
}

static const char *const KEY_SEQ = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
static const char *const KEY_ZERO = "0000000000000000000000000000000000000000000000000000000000000000";
static const char *const KEY_ONE = "0000000000000000000000000000000000000000000000000000000000000001";

// RFC 8439 2.3.2 and A.1: the block function, as the keystream over zeros.
static void test_chacha20_block(void) {
	uint8_t zero[64] = {0}, out[64];
	chacha_hex(KEY_SEQ, 1, "000000090000004a00000000", zero, 64, out);
	CHECK_HEX(out, 64,
	          "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e"
	          "d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e");
	chacha_hex(KEY_ZERO, 0, "000000000000000000000000", zero, 64, out);
	CHECK_HEX(out, 64,
	          "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7"
	          "da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586");
	chacha_hex(KEY_ZERO, 1, "000000000000000000000000", zero, 64, out);
	CHECK_HEX(out, 64,
	          "9f07e7be5551387a98ba977c732d080dcb0f29a048e3656912c6533e32ee7aed"
	          "29b721769ce64e43d57133b074d839d531ed1f28510afb45ace10a1f4b794d6f");
	chacha_hex(KEY_ONE, 1, "000000000000000000000000", zero, 64, out);
	CHECK_HEX(out, 64,
	          "3aeb5224ecf849929b9d828db1ced4dd832025e8018b8160b82284f3c949aa5a"
	          "8eca00bbb4a73bdad192b5c42f73f2fd4e273644c8b36125a64addeb006c13a0");
	chacha_hex("00ff000000000000000000000000000000000000000000000000000000000000", 2, "000000000000000000000000", zero,
	           64, out);
	CHECK_HEX(out, 64,
	          "72d54dfbf12ec44b362692df94137f328fea8da73990265ec1bbbea1ae9af0ca"
	          "13b25aa26cb4a648cb9b9d1be65b2c0924a66c54d545ec1b7374f4872e99f096");
	chacha_hex(KEY_ZERO, 0, "000000000000000000000002", zero, 64, out);
	CHECK_HEX(out, 64,
	          "c2c64d378cd536374ae204b9ef933fcd1a8b2288b3dfa49672ab765b54ee27c7"
	          "8a970e0e955c14f3a88e741b97c286f75f8fc299e8148362fa198a39531bed6d");
}

// RFC 8439 2.4.2 and A.2.
static void test_chacha20_encrypt(void) {
	uint8_t out[HEX_MAX];
	chacha_hex(KEY_SEQ, 1, "000000000000004a00000000", (const uint8_t *)SUNSCREEN, strlen(SUNSCREEN), out);
	CHECK_HEX(out, strlen(SUNSCREEN),
	          "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b357"
	          "1639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736"
	          "5af90bbf74a35be6b40b8eedf2785e42874d");
	uint8_t zero[64] = {0};
	chacha_hex(KEY_ZERO, 0, "000000000000000000000000", zero, 64, out);
	CHECK_HEX(out, 64,
	          "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7"
	          "da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586");
	chacha_hex(KEY_ONE, 1, "000000000000000000000002", (const uint8_t *)IETF, strlen(IETF), out);
	CHECK_HEX(out, strlen(IETF),
	          "a3fbf07df3fa2fde4f376ca23e82737041605d9f4f4f57bd8cff2c1d4b7955ec2a97948bd3722915c8f3d337f7d37005"
	          "0e9e96d647b7c39f56e031ca5eb6250d4042e02785ececfa4b4bb5e8ead0440e20b6e8db09d881a7c6132f420e527950"
	          "42bdfa7773d8a9051447b3291ce1411c680465552aa6c405b7764d5e87bea85ad00f8449ed8f72d0d662ab052691ca66"
	          "424bc86d2df80ea41f43abf937d3259dc4b2d0dfb48a6c9139ddd7f76966e928e635553ba76c5c879d7b35d49eb2e62b"
	          "0871cdac638939e25e8a1e0ef9d5280fa8ca328b351c3c765989cbcf3daa8b6ccc3aaf9f3979c92b3720fc88dc95ed84"
	          "a1be059c6499b9fda236e7e818b04b0bc39c1e876b193bfe5569753f88128cc08aaa9b63d1a16f80ef2554d7189c411f"
	          "5869ca52c5b83fa36ff216b9c1d30062bebcfd2dc5bce0911934fda79a86f6e698ced759c3ff9b6477338f3da4f9cd85"
	          "14ea9982ccafb341b2384dd902f3d1ab7ac61dd29c6f21ba5b862f3730e37cfdc4fd806c22f221");
	chacha_hex(KEY_1C92, 42, "000000000000000000000002", (const uint8_t *)JABBERWOCKY, strlen(JABBERWOCKY), out);
	CHECK_HEX(out, strlen(JABBERWOCKY),
	          "62e6347f95ed87a45ffae7426f27a1df5fb69110044c0d73118effa95b01e5cf166d3df2d721caf9b21e5fb14c616871"
	          "fd84c54f9d65b283196c7fe4f60553ebf39c6402c42234e32a356b3e764312a61a5532055716ead6962568f87d3f3f77"
	          "04c6a8d1bcd1bf4d50d6154b6da731b187b58dfd728afa36757a797ac188d1");
}

static void poly_case(const char *key_hex, const uint8_t *msg, size_t len, const char *want) {
	uint8_t key[32], tag[16];
	hex(key_hex, key, 32);
	hw_poly1305(key, msg, len, tag);
	CHECK_HEX(tag, 16, want);
}

static void poly_hex(const char *key_hex, const char *msg_hex, const char *want) {
	uint8_t msg[64];
	size_t len = strlen(msg_hex) / 2;
	hex(msg_hex, msg, len);
	poly_case(key_hex, msg, len, want);
}

// RFC 8439 2.5.2 and A.3 (A.3.5 to A.3.11 are the edge cases of the final reduction).
static void test_poly1305(void) {
	const char *m = "Cryptographic Forum Research Group";
	poly_case("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b", (const uint8_t *)m, strlen(m),
	          "a8061dc1305136c6c22b8baf0c0127a9");
	uint8_t zero[64] = {0};
	poly_case(KEY_ZERO, zero, 64, "00000000000000000000000000000000");
	poly_case("0000000000000000000000000000000036e5f6b5c5e06070f0efca96227a863e", (const uint8_t *)IETF, strlen(IETF),
	          "36e5f6b5c5e06070f0efca96227a863e");
	poly_case("36e5f6b5c5e06070f0efca96227a863e00000000000000000000000000000000", (const uint8_t *)IETF, strlen(IETF),
	          "f3477e7cd95417af89a6b8794c310cf0");
	poly_case(KEY_1C92, (const uint8_t *)JABBERWOCKY, strlen(JABBERWOCKY), "4541669a7eaaee61e708dc7cbcc5eb62");
	const char *r2 = "0200000000000000000000000000000000000000000000000000000000000000";
	const char *r1 = "0100000000000000000000000000000000000000000000000000000000000000";
	const char *ff = "ffffffffffffffffffffffffffffffff";
	poly_hex(r2, ff, "03000000000000000000000000000000");
	poly_hex("02000000000000000000000000000000ffffffffffffffffffffffffffffffff", "02000000000000000000000000000000",
	         "03000000000000000000000000000000");
	poly_hex(r1, "fffffffffffffffffffffffffffffffff0ffffffffffffffffffffffffffffff11000000000000000000000000000000",
	         "05000000000000000000000000000000");
	poly_hex(r1, "fffffffffffffffffffffffffffffffffbfefefefefefefefefefefefefefefe01010101010101010101010101010101",
	         "00000000000000000000000000000000");
	poly_hex(r2, "fdffffffffffffffffffffffffffffff", "faffffffffffffffffffffffffffffff");
	const char *r10 = "0100000000000000040000000000000000000000000000000000000000000000";
	const char *m10 = "e33594d7505e43b90000000000000000"
	                  "3394d7505e4379cd0100000000000000"
	                  "00000000000000000000000000000000"
	                  "01000000000000000000000000000000";
	poly_hex(r10, m10, "14000000000000005500000000000000");
	char m11[97];
	memcpy(m11, m10, 96);
	m11[96] = '\0';
	poly_hex(r10, m11, "13000000000000000000000000000000");
}

// RFC 8439 2.6.2 and A.4: the one-time key is the first 32 bytes of block 0.
static void test_poly1305_keygen(void) {
	uint8_t zero[32] = {0}, out[32];
	chacha_hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f", 0, "000000000001020304050607", zero,
	           32, out);
	CHECK_HEX(out, 32, "8ad5a08b905f81cc815040274ab29471a833b637e3fd0da508dbb8e2fdd1a646");
	chacha_hex(KEY_ZERO, 0, "000000000000000000000000", zero, 32, out);
	CHECK_HEX(out, 32, "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7");
	chacha_hex(KEY_ONE, 0, "000000000000000000000002", zero, 32, out);
	CHECK_HEX(out, 32, "ecfa254f845f647473d3cb140da9e87606cb33066c447b87bc2666dde3fbb739");
	chacha_hex(KEY_1C92, 0, "000000000000000000000002", zero, 32, out);
	CHECK_HEX(out, 32, "965e3bc6f9ec7ed9560808f4d229f94b137ff275ca9b3fcbdd59deaad23310ae");
}

// RFC 8439 2.8.2 (seal) and A.5 (open).
static void test_chacha20poly1305(void) {
	uint8_t key[32], nonce[12], aad[12], ct[HEX_MAX], pt[HEX_MAX];
	size_t len = strlen(SUNSCREEN);
	hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f", key, 32);
	hex("070000004041424344454647", nonce, 12);
	hex("50515253c0c1c2c3c4c5c6c7", aad, 12);
	hw_chacha20poly1305_seal(key, nonce, aad, 12, (const uint8_t *)SUNSCREEN, len, ct);
	CHECK_HEX(ct, len + HW_AEAD_TAG,
	          "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b"
	          "1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
	          "3ff4def08e4b7a9de576d26586cec64b6116"
	          "1ae10b594f09e26a7e902ecbd0600691");
	CHECK_EQ(hw_chacha20poly1305_open(key, nonce, aad, 12, ct, len + HW_AEAD_TAG, pt), 0);
	CHECK(memcmp(pt, SUNSCREEN, len) == 0, "2.8.2 does not open");

	static const char *const a5 =
	    "64a0861575861af460f062c79be643bd5e805cfd345cf389f108670ac76c8cb24c6cfc18755d43eea09ee94e382d26b0bdb7b73c321b"
	    "0100d4f03b7f355894cf332f830e710b97ce98c8a84abd0b948114ad176e008d33bd60f982b1ff37c8559797a06ef4f0ef61c186324e"
	    "2b3506383606907b6a7c02b0f9f6157b53c867e4b9166c767b804d46a59b5216cde7a4e99040c5a40433225ee282a1b0a06c523eaf45"
	    "34d7f83fa1155b0047718cbc546a0d072b04b3564eea1b422273f548271a0bb2316053fa76991955ebd63159434ecebb4e466dae5a10"
	    "73a6727627097a1049e617d91d361094fa68f0ff77987130305beaba2eda04df997b714d6c6f2c29a6ad5cb4022b02709b"
	    "eead9d67890cbb22392336fea1851f38";
	static const char drafts[] = "Internet-Drafts are draft documents valid for a maximum of six months and may be "
	                             "updated, replaced, or obsoleted by other documents at any time. It is inappropriate "
	                             "to use Internet-Drafts as reference material or to cite them other than as "
	                             "/\xe2\x80\x9cwork in progress./\xe2\x80\x9d";
	size_t n = strlen(a5) / 2;
	hex(KEY_1C92, key, 32);
	hex("000000000102030405060708", nonce, 12);
	hex("f33388860000000000004e91", aad, 12);
	hex(a5, ct, n);
	CHECK_EQ(n - HW_AEAD_TAG, strlen(drafts));
	CHECK_EQ(hw_chacha20poly1305_open(key, nonce, aad, 12, ct, n, pt), 0);
	CHECK(memcmp(pt, drafts, n - HW_AEAD_TAG) == 0, "A.5 decrypts to other text");
}

// RFC 9001 A.5: the ChaCha20 header protection mask (counter and nonce from the sample) and
// the one-byte payload it protects.
static void test_quic_chacha20(void) {
	uint8_t key[32], sample[16], zero[5] = {0}, mask[5];
	hex("25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4", key, 32);
	hex("5e5cd55c41f69080575d7999c25a5bfb", sample, 16);
	uint32_t counter = (uint32_t)sample[0] | (uint32_t)sample[1] << 8 | (uint32_t)sample[2] << 16 |
	                   (uint32_t)sample[3] << 24;
	hw_chacha20_xor(key, counter, sample + 4, zero, mask, 5);
	CHECK_HEX(mask, 5, "aefefe7d03");
	uint8_t nonce[12], aad[4], one = 1, ct[17];
	hex("c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8", key, 32);
	hex("e0459b3474bdd0e46d417eb0", nonce, 12); // the IV XOR packet number 654360564
	hex("4200bff4", aad, 4);
	hw_chacha20poly1305_seal(key, nonce, aad, 4, &one, 1, ct);
	CHECK_HEX(ct, 17, "655e5cd55c41f69080575d7999c25a5bfb");
}

#define SWEEP_MAX 16385

// Every length from 0 to 300 and the ones around the eight-block and AEAD-head boundaries:
// the digests of all ciphertexts and tags match the ones Python made, every message opens again,
// and sealing and opening in place give the same bytes.
static void test_length_sweeps(void) {
	static const size_t extra[] = {447,  448,  449,  511,  512,  513,  959,   960,   961,
	                               1023, 1024, 1025, 1200, 1500, 4096, 16383, 16384, 16385};
	uint8_t *m = malloc(SWEEP_MAX), *ct = malloc(SWEEP_MAX + HW_AEAD_TAG), *buf = malloc(SWEEP_MAX + HW_AEAD_TAG);
	CHECK(m && ct && buf, "malloc");
	hw_sha256_ctx d_cp, d_gcm, d_cc;
	hw_sha256_init(&d_cp);
	hw_sha256_init(&d_gcm);
	hw_sha256_init(&d_cc);
	for (size_t idx = 0; idx < 301 + HW_ARRAY_LEN(extra); idx++) {
		size_t len = idx < 301 ? idx : extra[idx - 301];
		unsigned l = (unsigned)len;
		uint8_t key[32], nonce[12], aad[37];
		size_t aad_len = len % 37;
		pattern(key, 32, 7, l);
		pattern(nonce, 12, 13, l);
		pattern(aad, aad_len, 1, 3 * l);
		pattern(m, len, 31, l);

		hw_chacha20poly1305_seal(key, nonce, aad, aad_len, m, len, ct);
		hw_sha256_update(&d_cp, ct, len + HW_AEAD_TAG);
		memcpy(buf, m, len);
		hw_chacha20poly1305_seal(key, nonce, aad, aad_len, buf, len, buf);
		CHECK(memcmp(buf, ct, len + HW_AEAD_TAG) == 0, "chacha20poly1305 in-place seal differs at %zu", len);
		CHECK_EQ(hw_chacha20poly1305_open(key, nonce, aad, aad_len, buf, len + HW_AEAD_TAG, buf), 0);
		CHECK(memcmp(buf, m, len) == 0, "chacha20poly1305 in-place open differs at %zu", len);

		hw_aes128gcm g;
		hw_aes128gcm_init(&g, key);
		hw_aes128gcm_seal(&g, nonce, aad, aad_len, m, len, ct);
		hw_sha256_update(&d_gcm, ct, len + HW_AEAD_TAG);
		memcpy(buf, m, len);
		hw_aes128gcm_seal(&g, nonce, aad, aad_len, buf, len, buf);
		CHECK(memcmp(buf, ct, len + HW_AEAD_TAG) == 0, "gcm in-place seal differs at %zu", len);
		CHECK_EQ(hw_aes128gcm_open(&g, nonce, aad, aad_len, buf, len + HW_AEAD_TAG, buf), 0);
		CHECK(memcmp(buf, m, len) == 0, "gcm in-place open differs at %zu", len);

		hw_chacha20_xor(key, 3 * l, nonce, m, ct, len);
		hw_sha256_update(&d_cc, ct, len);
	}
	uint8_t dig[HW_SHA256_LEN];
	hw_sha256_final(&d_cp, dig);
	CHECK_HEX(dig, 32, "0c3d1b621edb8d0b53be20654f3420152aa58c1e291888010311fec8f0e9b67a");
	hw_sha256_final(&d_gcm, dig);
	CHECK_HEX(dig, 32, "a9bff16d28b7efdb4bc451c06bd8e2bf732b37c2079a0c540e4621cfbea08cf6");
	hw_sha256_final(&d_cc, dig);
	CHECK_HEX(dig, 32, "1337e97f5c75f5f3c89acdb3f5cd264c0e9303f3a3c8b8d35501a96c6380ef3b");
	free(m);
	free(ct);
	free(buf);
}

// The keystream in one call equals the keystream in pieces that start on block boundaries with
// the counter advanced, for every split of every length up to 1100 bytes into two pieces.
static void test_chacha20_pieces(void) {
	enum {
		N = 1100
	};
	uint8_t key[32], nonce[12], in[N], whole[N], parts[N];
	pattern(key, 32, 9, 1);
	pattern(nonce, 12, 5, 7);
	pattern(in, N, 17, 3);
	for (size_t len = 0; len <= N; len += 7) {
		hw_chacha20_xor(key, 5, nonce, in, whole, len);
		for (size_t cut = 0; cut <= len; cut += 64) {
			hw_chacha20_xor(key, 5, nonce, in, parts, cut);
			hw_chacha20_xor(key, 5 + (uint32_t)(cut / 64), nonce, in + cut, parts + cut, len - cut);
			CHECK(memcmp(whole, parts, len) == 0, "length %zu split at %zu differs", len, cut);
		}
		memcpy(parts, in, len);
		hw_chacha20_xor(key, 5, nonce, parts, parts, len);
		CHECK(memcmp(whole, parts, len) == 0, "length %zu in place differs", len);
	}
}

// The cases that reach the ChaCha20 and Poly1305 kernels, on the base kernels. Where the CPU has
// others (AVX2 on x86-64) the cases above ran only those, and the base ones are what a CPU
// without them runs; elsewhere this repeats the same kernels.
static void test_base_kernels(void) {
	int other = hw_aead_force_base_kernels(1);
	printf("# base kernels%s\n", other ? "" : " (the only ones on this CPU)");
	test_aead_rejects();
	test_chacha20_block();
	test_chacha20_encrypt();
	test_poly1305();
	test_poly1305_keygen();
	test_chacha20poly1305();
	test_quic_chacha20();
	test_length_sweeps();
	test_chacha20_pieces();
	CHECK_EQ(hw_aead_force_base_kernels(0), other);
}

int main(void) {
	RUN(test_ct_equal);
	RUN(test_aes128);
	RUN(test_gcm_vectors);
	RUN(test_aead_rejects);
	RUN(test_chacha20_block);
	RUN(test_chacha20_encrypt);
	RUN(test_poly1305);
	RUN(test_poly1305_keygen);
	RUN(test_chacha20poly1305);
	RUN(test_quic_chacha20);
	RUN(test_length_sweeps);
	RUN(test_chacha20_pieces);
	RUN(test_base_kernels);
	return 0;
}
