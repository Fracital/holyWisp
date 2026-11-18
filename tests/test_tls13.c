/*
 * tests/test_tls13.c - the TLS 1.3 handshake of src/quic/tls13.c: its key schedule against the
 * RFC 8448 section 3 trace, both roles against each other in memory (whole flights and byte by
 * byte, with and without a HelloRetryRequest), the refusals with their alerts, a Chrome-shaped
 * ClientHello (GREASE, a hybrid post-quantum share before the X25519 one, ECH GREASE, ALPS, ...)
 * whose handshake the test finishes itself from its own key schedule, and truncated and mutated
 * ClientHellos and server flights from a fixed seed, which must only ever be refused.
 */
#include "holywisp/cert.h"
#include "holywisp/ecc.h"
#include "holywisp/hw.h"
#include "holywisp/sha256.h"
#include "holywisp/tls13.h"

#include "quic/tls13_internal.h"
#include "test.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static unsigned nibble(char c) {
	if (c >= '0' && c <= '9') return (unsigned)(c - '0');
	if (c >= 'a' && c <= 'f') return (unsigned)(c - 'a' + 10);
	CHECK(0, "bad hex digit %c", c);
	return 0;
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

// ---- RFC 8448 section 3: the simple 1-RTT handshake, message by message --------------------
static const uint8_t RFC8448_CH[196] = {
    0x01, 0x00, 0x00, 0xc0, 0x03, 0x03, 0xcb, 0x34, 0xec, 0xb1, 0xe7, 0x81, 0x63, 0xba, 0x1c, 0x38, 0xc6, 0xda,
    0xcb, 0x19, 0x6a, 0x6d, 0xff, 0xa2, 0x1a, 0x8d, 0x99, 0x12, 0xec, 0x18, 0xa2, 0xef, 0x62, 0x83, 0x02, 0x4d,
    0xec, 0xe7, 0x00, 0x00, 0x06, 0x13, 0x01, 0x13, 0x03, 0x13, 0x02, 0x01, 0x00, 0x00, 0x91, 0x00, 0x00, 0x00,
    0x0b, 0x00, 0x09, 0x00, 0x00, 0x06, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0xff, 0x01, 0x00, 0x01, 0x00, 0x00,
    0x0a, 0x00, 0x14, 0x00, 0x12, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19, 0x01, 0x00, 0x01, 0x01, 0x01,
    0x02, 0x01, 0x03, 0x01, 0x04, 0x00, 0x23, 0x00, 0x00, 0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1d, 0x00,
    0x20, 0x99, 0x38, 0x1d, 0xe5, 0x60, 0xe4, 0xbd, 0x43, 0xd2, 0x3d, 0x8e, 0x43, 0x5a, 0x7d, 0xba, 0xfe, 0xb3,
    0xc0, 0x6e, 0x51, 0xc1, 0x3c, 0xae, 0x4d, 0x54, 0x13, 0x69, 0x1e, 0x52, 0x9a, 0xaf, 0x2c, 0x00, 0x2b, 0x00,
    0x03, 0x02, 0x03, 0x04, 0x00, 0x0d, 0x00, 0x20, 0x00, 0x1e, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x02, 0x03,
    0x08, 0x04, 0x08, 0x05, 0x08, 0x06, 0x04, 0x01, 0x05, 0x01, 0x06, 0x01, 0x02, 0x01, 0x04, 0x02, 0x05, 0x02,
    0x06, 0x02, 0x02, 0x02, 0x00, 0x2d, 0x00, 0x02, 0x01, 0x01, 0x00, 0x1c, 0x00, 0x02, 0x40, 0x01,
};
static const uint8_t RFC8448_SH[90] = {
    0x02, 0x00, 0x00, 0x56, 0x03, 0x03, 0xa6, 0xaf, 0x06, 0xa4, 0x12, 0x18, 0x60, 0xdc, 0x5e, 0x6e, 0x60, 0x24,
    0x9c, 0xd3, 0x4c, 0x95, 0x93, 0x0c, 0x8a, 0xc5, 0xcb, 0x14, 0x34, 0xda, 0xc1, 0x55, 0x77, 0x2e, 0xd3, 0xe2,
    0x69, 0x28, 0x00, 0x13, 0x01, 0x00, 0x00, 0x2e, 0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20, 0xc9, 0x82,
    0x88, 0x76, 0x11, 0x20, 0x95, 0xfe, 0x66, 0x76, 0x2b, 0xdb, 0xf7, 0xc6, 0x72, 0xe1, 0x56, 0xd6, 0xcc, 0x25,
    0x3b, 0x83, 0x3d, 0xf1, 0xdd, 0x69, 0xb1, 0xb0, 0x4e, 0x75, 0x1f, 0x0f, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04,
};
static const uint8_t RFC8448_EE[40] = {
    0x08, 0x00, 0x00, 0x24, 0x00, 0x22, 0x00, 0x0a, 0x00, 0x14, 0x00, 0x12, 0x00, 0x1d,
    0x00, 0x17, 0x00, 0x18, 0x00, 0x19, 0x01, 0x00, 0x01, 0x01, 0x01, 0x02, 0x01, 0x03,
    0x01, 0x04, 0x00, 0x1c, 0x00, 0x02, 0x40, 0x01, 0x00, 0x00, 0x00, 0x00,
};
static const uint8_t RFC8448_CERT[445] = {
    0x0b, 0x00, 0x01, 0xb9, 0x00, 0x00, 0x01, 0xb5, 0x00, 0x01, 0xb0, 0x30, 0x82, 0x01, 0xac, 0x30, 0x82, 0x01, 0x15,
    0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x01, 0x02, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01,
    0x01, 0x0b, 0x05, 0x00, 0x30, 0x0e, 0x31, 0x0c, 0x30, 0x0a, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x03, 0x72, 0x73,
    0x61, 0x30, 0x1e, 0x17, 0x0d, 0x31, 0x36, 0x30, 0x37, 0x33, 0x30, 0x30, 0x31, 0x32, 0x33, 0x35, 0x39, 0x5a, 0x17,
    0x0d, 0x32, 0x36, 0x30, 0x37, 0x33, 0x30, 0x30, 0x31, 0x32, 0x33, 0x35, 0x39, 0x5a, 0x30, 0x0e, 0x31, 0x0c, 0x30,
    0x0a, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x03, 0x72, 0x73, 0x61, 0x30, 0x81, 0x9f, 0x30, 0x0d, 0x06, 0x09, 0x2a,
    0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x81, 0x8d, 0x00, 0x30, 0x81, 0x89, 0x02, 0x81,
    0x81, 0x00, 0xb4, 0xbb, 0x49, 0x8f, 0x82, 0x79, 0x30, 0x3d, 0x98, 0x08, 0x36, 0x39, 0x9b, 0x36, 0xc6, 0x98, 0x8c,
    0x0c, 0x68, 0xde, 0x55, 0xe1, 0xbd, 0xb8, 0x26, 0xd3, 0x90, 0x1a, 0x24, 0x61, 0xea, 0xfd, 0x2d, 0xe4, 0x9a, 0x91,
    0xd0, 0x15, 0xab, 0xbc, 0x9a, 0x95, 0x13, 0x7a, 0xce, 0x6c, 0x1a, 0xf1, 0x9e, 0xaa, 0x6a, 0xf9, 0x8c, 0x7c, 0xed,
    0x43, 0x12, 0x09, 0x98, 0xe1, 0x87, 0xa8, 0x0e, 0xe0, 0xcc, 0xb0, 0x52, 0x4b, 0x1b, 0x01, 0x8c, 0x3e, 0x0b, 0x63,
    0x26, 0x4d, 0x44, 0x9a, 0x6d, 0x38, 0xe2, 0x2a, 0x5f, 0xda, 0x43, 0x08, 0x46, 0x74, 0x80, 0x30, 0x53, 0x0e, 0xf0,
    0x46, 0x1c, 0x8c, 0xa9, 0xd9, 0xef, 0xbf, 0xae, 0x8e, 0xa6, 0xd1, 0xd0, 0x3e, 0x2b, 0xd1, 0x93, 0xef, 0xf0, 0xab,
    0x9a, 0x80, 0x02, 0xc4, 0x74, 0x28, 0xa6, 0xd3, 0x5a, 0x8d, 0x88, 0xd7, 0x9f, 0x7f, 0x1e, 0x3f, 0x02, 0x03, 0x01,
    0x00, 0x01, 0xa3, 0x1a, 0x30, 0x18, 0x30, 0x09, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x04, 0x02, 0x30, 0x00, 0x30, 0x0b,
    0x06, 0x03, 0x55, 0x1d, 0x0f, 0x04, 0x04, 0x03, 0x02, 0x05, 0xa0, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
    0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x03, 0x81, 0x81, 0x00, 0x85, 0xaa, 0xd2, 0xa0, 0xe5, 0xb9, 0x27, 0x6b,
    0x90, 0x8c, 0x65, 0xf7, 0x3a, 0x72, 0x67, 0x17, 0x06, 0x18, 0xa5, 0x4c, 0x5f, 0x8a, 0x7b, 0x33, 0x7d, 0x2d, 0xf7,
    0xa5, 0x94, 0x36, 0x54, 0x17, 0xf2, 0xea, 0xe8, 0xf8, 0xa5, 0x8c, 0x8f, 0x81, 0x72, 0xf9, 0x31, 0x9c, 0xf3, 0x6b,
    0x7f, 0xd6, 0xc5, 0x5b, 0x80, 0xf2, 0x1a, 0x03, 0x01, 0x51, 0x56, 0x72, 0x60, 0x96, 0xfd, 0x33, 0x5e, 0x5e, 0x67,
    0xf2, 0xdb, 0xf1, 0x02, 0x70, 0x2e, 0x60, 0x8c, 0xca, 0xe6, 0xbe, 0xc1, 0xfc, 0x63, 0xa4, 0x2a, 0x99, 0xbe, 0x5c,
    0x3e, 0xb7, 0x10, 0x7c, 0x3c, 0x54, 0xe9, 0xb9, 0xeb, 0x2b, 0xd5, 0x20, 0x3b, 0x1c, 0x3b, 0x84, 0xe0, 0xa8, 0xb2,
    0xf7, 0x59, 0x40, 0x9b, 0xa3, 0xea, 0xc9, 0xd9, 0x1d, 0x40, 0x2d, 0xcc, 0x0c, 0xc8, 0xf8, 0x96, 0x12, 0x29, 0xac,
    0x91, 0x87, 0xb4, 0x2b, 0x4d, 0xe1, 0x00, 0x00,
};
static const uint8_t RFC8448_CV[136] = {
    0x0f, 0x00, 0x00, 0x84, 0x08, 0x04, 0x00, 0x80, 0x5a, 0x74, 0x7c, 0x5d, 0x88, 0xfa, 0x9b, 0xd2, 0xe5,
    0x5a, 0xb0, 0x85, 0xa6, 0x10, 0x15, 0xb7, 0x21, 0x1f, 0x82, 0x4c, 0xd4, 0x84, 0x14, 0x5a, 0xb3, 0xff,
    0x52, 0xf1, 0xfd, 0xa8, 0x47, 0x7b, 0x0b, 0x7a, 0xbc, 0x90, 0xdb, 0x78, 0xe2, 0xd3, 0x3a, 0x5c, 0x14,
    0x1a, 0x07, 0x86, 0x53, 0xfa, 0x6b, 0xef, 0x78, 0x0c, 0x5e, 0xa2, 0x48, 0xee, 0xaa, 0xa7, 0x85, 0xc4,
    0xf3, 0x94, 0xca, 0xb6, 0xd3, 0x0b, 0xbe, 0x8d, 0x48, 0x59, 0xee, 0x51, 0x1f, 0x60, 0x29, 0x57, 0xb1,
    0x54, 0x11, 0xac, 0x02, 0x76, 0x71, 0x45, 0x9e, 0x46, 0x44, 0x5c, 0x9e, 0xa5, 0x8c, 0x18, 0x1e, 0x81,
    0x8e, 0x95, 0xb8, 0xc3, 0xfb, 0x0b, 0xf3, 0x27, 0x84, 0x09, 0xd3, 0xbe, 0x15, 0x2a, 0x3d, 0xa5, 0x04,
    0x3e, 0x06, 0x3d, 0xda, 0x65, 0xcd, 0xf5, 0xae, 0xa2, 0x0d, 0x53, 0xdf, 0xac, 0xd4, 0x2f, 0x74, 0xf3,
};
static const uint8_t RFC8448_SFIN[36] = {
    0x14, 0x00, 0x00, 0x20, 0x9b, 0x9b, 0x14, 0x1d, 0x90, 0x63, 0x37, 0xfb, 0xd2, 0xcb, 0xdc, 0xe7, 0x1d, 0xf4,
    0xde, 0xda, 0x4a, 0xb4, 0x2c, 0x30, 0x95, 0x72, 0xcb, 0x7f, 0xff, 0xee, 0x54, 0x54, 0xb7, 0x8f, 0x07, 0x18,
};

static void hash_msgs(const uint8_t *const *msgs, const size_t *lens, size_t n, uint8_t out[32]) {
	hw_sha256_ctx c;
	hw_sha256_init(&c);
	for (size_t i = 0; i < n; i++) hw_sha256_update(&c, msgs[i], lens[i]);
	hw_sha256_final(&c, out);
}

// The derive-secret chain, fed the trace's shared secret and its own messages' transcript hashes,
// reproduces every secret and both Finished messages of the trace.
static void test_key_schedule_rfc8448(void) {
	const uint8_t *msgs[] = {RFC8448_CH, RFC8448_SH, RFC8448_EE, RFC8448_CERT, RFC8448_CV, RFC8448_SFIN};
	const size_t lens[] = {sizeof RFC8448_CH,   sizeof RFC8448_SH, sizeof RFC8448_EE,
	                       sizeof RFC8448_CERT, sizeof RFC8448_CV, sizeof RFC8448_SFIN};
	uint8_t th_sh[32], th_cv[32], th_sf[32];
	hash_msgs(msgs, lens, 2, th_sh);
	CHECK_HEX(th_sh, 32, "860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8");
	hash_msgs(msgs, lens, 5, th_cv);
	hash_msgs(msgs, lens, 6, th_sf);
	CHECK_HEX(th_sf, 32, "9608102a0f1ccc6db6250b7b7e417b1a000eaada3daae4777a7686c9ff83df13");

	uint8_t ecdhe[32], hs[32], c_hs[32], s_hs[32];
	hex("8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d", ecdhe, 32);
	hw_tls_schedule_handshake(ecdhe, th_sh, hs, c_hs, s_hs);
	CHECK_HEX(hs, 32, "1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac");
	CHECK_HEX(c_hs, 32, "b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21");
	CHECK_HEX(s_hs, 32, "b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38");

	uint8_t fk[32], fin[32];
	hw_tls_finished_key(s_hs, fk);
	CHECK_HEX(fk, 32, "008d3b66f816ea559f96b537e885c31fc068bf492c652f01f288a1d8cdc19fc8");
	hw_hmac_sha256(fk, 32, th_cv, 32, fin);
	CHECK_HEX(fin, 32, "9b9b141d906337fbd2cbdce71df4deda4ab42c309572cb7fffee5454b78f0718");
	CHECK(memcmp(fin, RFC8448_SFIN + 4, 32) == 0, "server Finished");

	uint8_t master[32], c_ap[32], s_ap[32];
	hw_tls_schedule_app(hs, th_sf, master, c_ap, s_ap);
	CHECK_HEX(master, 32, "18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919");
	CHECK_HEX(c_ap, 32, "9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5");
	CHECK_HEX(s_ap, 32, "a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643");

	hw_tls_finished_key(c_hs, fk);
	CHECK_HEX(fk, 32, "b80ad01015fb2f0bd65ff7d4da5d6bf83f84821d1f87fdc7d3c75b5a7b42d9c4");
	hw_hmac_sha256(fk, 32, th_sf, 32, fin);
	CHECK_HEX(fin, 32, "a8ec436d677634ae525ac1fcebe11a039ec17694fac6e98527b642f2edd5ce61");

	uint8_t empty[32], derived[32], early[32], zero[32] = {0};
	hw_sha256("", 0, empty);
	hw_hkdf_extract(NULL, 0, zero, 32, early);
	CHECK_HEX(early, 32, "33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a");
	hw_tls_derive_secret(early, "derived", empty, derived);
	CHECK_HEX(derived, 32, "6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba");
}

// The trace's own key pairs agree on its shared secret (X25519 as the server uses it).
static void test_rfc8448_ecdhe(void) {
	uint8_t s_priv[32], c_pub[32], out[32];
	hex("b1580eeadf6dd589b8ef4f2d5652578cc810e9980191ec8d058308cea216a21e", s_priv, 32);
	hex("99381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c", c_pub, 32);
	CHECK(hw_x25519(out, s_priv, c_pub) == 0, "x25519");
	CHECK_HEX(out, 32, "8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d");
}

// ---- in-memory endpoints -------------------------------------------------------------------

typedef struct {
	hw_tls *t;
	uint8_t *q[3]; // bytes emitted per level and not yet delivered
	size_t qn[3];
	uint8_t sec[3][2][32]; // [level][write]
	int have[3][2];
	int fail_secret; // the secret callback refuses
} side;

static int emit_cb(void *ud, hw_tls_level level, const uint8_t *data, size_t len) {
	side *s = ud;
	CHECK(level <= HW_TLS_APP && len > 0, "emit level %d len %zu", (int)level, len);
	uint8_t *p = realloc(s->q[level], s->qn[level] + len);
	CHECK(p != NULL, "realloc");
	memcpy(p + s->qn[level], data, len);
	s->q[level] = p;
	s->qn[level] += len;
	return 0;
}

static int secret_cb(void *ud, hw_tls_level level, int write, uint16_t cipher, const uint8_t secret[32]) {
	side *s = ud;
	CHECK(level == HW_TLS_HANDSHAKE || level == HW_TLS_APP, "secret at level %d", (int)level);
	CHECK(write == 0 || write == 1, "write %d", write);
	CHECK_EQ(cipher, HW_TLS_CIPHER_CHACHA20);
	CHECK(!s->have[level][write], "secret %d/%d installed twice", (int)level, write);
	memcpy(s->sec[level][write], secret, 32);
	s->have[level][write] = 1;
	return s->fail_secret ? -1 : 0;
}

static void side_clear(side *s) {
	hw_tls_free(s->t);
	for (int l = 0; l < 3; l++) free(s->q[l]);
	memset(s, 0, sizeof *s);
}

static uint8_t g_priv[HW_P256_PRIV_LEN];
static hw_der g_cert;
static uint8_t g_pin[32];
static const uint8_t CLIENT_TP[] = {0x01, 0x04, 0x80, 0x00, 0x75, 0x30, 0x04, 0x04, 0x80, 0x10, 0x00, 0x00};
static const uint8_t SERVER_TP[] = {0x00, 0x08, 1, 2, 3, 4, 5, 6, 7, 8, 0x0e, 0x01, 0x04};

static void fixture_cert(void) {
	uint8_t pub[HW_P256_PUB_LEN];
	CHECK(hw_p256_keygen(g_priv, pub) == 0, "p256 keygen");
	int64_t now = (int64_t)time(NULL);
	CHECK(hw_cert_selfsigned(g_priv, pub, "wt.example", now - 3600, now + 13 * 86400, &g_cert) == 0, "cert");
	hw_sha256(g_cert.der, g_cert.len, g_pin);
}

static void server_init(side *s, const char *const *alpn, size_t alpn_count) {
	memset(s, 0, sizeof *s);
	hw_tls_config cfg = {
	    .is_server = 1,
	    .chain = &g_cert,
	    .chain_len = 1,
	    .key = g_priv,
	    .alpn = alpn,
	    .alpn_count = alpn_count,
	    .transport_params = SERVER_TP,
	    .transport_params_len = sizeof SERVER_TP,
	};
	hw_tls_callbacks cb = {.ud = s, .emit = emit_cb, .secret = secret_cb};
	s->t = hw_tls_new(&cfg, &cb);
	CHECK(s->t != NULL, "server new");
}

static void client_init(side *s, const char *const *alpn, size_t alpn_count, const char *sni, const uint8_t *pin) {
	memset(s, 0, sizeof *s);
	hw_tls_config cfg = {
	    .alpn = alpn,
	    .alpn_count = alpn_count,
	    .transport_params = CLIENT_TP,
	    .transport_params_len = sizeof CLIENT_TP,
	    .server_name = sni,
	    .pin_sha256 = pin,
	};
	hw_tls_callbacks cb = {.ud = s, .emit = emit_cb, .secret = secret_cb};
	s->t = hw_tls_new(&cfg, &cb);
	CHECK(s->t != NULL, "client new");
}

static const char *const H3[] = {"h3"};

// Hands everything from has queued to `to`, level by level, step bytes per call (0: all at
// once). 1 when something moved, 0 when nothing was queued, -1 when the receiver failed.
static int deliver(side *from, side *to, size_t step) {
	int moved = 0;
	for (int l = 0; l < 3; l++) {
		size_t n = from->qn[l];
		if (!n) continue;
		uint8_t *buf = from->q[l];
		from->q[l] = NULL;
		from->qn[l] = 0;
		moved = 1;
		for (size_t off = 0; off < n;) {
			size_t k = step && step < n - off ? step : n - off;
			if (hw_tls_input(to->t, (hw_tls_level)l, buf + off, k) != 0) {
				free(buf);
				return -1;
			}
			off += k;
		}
		free(buf);
	}
	return moved;
}

static int pump(side *c, side *s, size_t step) {
	for (int i = 0; i < 16; i++) {
		int a = deliver(c, s, step);
		if (a < 0) return -1;
		int b = deliver(s, c, step);
		if (b < 0) return -1;
		if (!a && !b) return 0;
	}
	return -1;
}

// Each side's write secret is the other's read secret, at both levels, and they all differ.
static void check_secrets_pair(const side *c, const side *s) {
	for (int l = HW_TLS_HANDSHAKE; l <= HW_TLS_APP; l++) {
		for (int w = 0; w < 2; w++) {
			CHECK(c->have[l][w] && s->have[l][!w], "level %d write %d missing", l, w);
			CHECK(memcmp(c->sec[l][w], s->sec[l][!w], 32) == 0, "level %d write %d differs", l, w);
		}
		CHECK(memcmp(c->sec[l][0], c->sec[l][1], 32) != 0, "read == write at level %d", l);
	}
	CHECK(memcmp(c->sec[HW_TLS_HANDSHAKE][1], c->sec[HW_TLS_APP][1], 32) != 0, "handshake == app");
	CHECK(!c->have[HW_TLS_INITIAL][0] && !c->have[HW_TLS_INITIAL][1], "no Initial secrets from TLS");
}

static void check_negotiated(const side *c, const side *s, const char *alpn, const char *sni) {
	CHECK(hw_tls_done(c->t) && hw_tls_done(s->t), "done %d %d", hw_tls_done(c->t), hw_tls_done(s->t));
	CHECK_EQ(hw_tls_alert(c->t), 0);
	CHECK_EQ(hw_tls_alert(s->t), 0);
	check_secrets_pair(c, s);
	CHECK(hw_tls_alpn(c->t) && hw_tls_alpn(s->t), "alpn");
	CHECK_STR(hw_tls_alpn(c->t), alpn);
	CHECK_STR(hw_tls_alpn(s->t), alpn);
	size_t n;
	const uint8_t *tp = hw_tls_peer_transport_params(s->t, &n);
	CHECK(tp && n == sizeof CLIENT_TP && memcmp(tp, CLIENT_TP, n) == 0, "server got the client's TPs");
	tp = hw_tls_peer_transport_params(c->t, &n);
	CHECK(tp && n == sizeof SERVER_TP && memcmp(tp, SERVER_TP, n) == 0, "client got the server's TPs");
	if (sni) {
		CHECK(hw_tls_server_name(s->t) != NULL, "sni");
		CHECK_STR(hw_tls_server_name(s->t), sni);
	} else {
		CHECK(hw_tls_server_name(s->t) == NULL, "no sni");
	}
}

static void handshake_with(size_t step) {
	side c, s;
	server_init(&s, H3, 1);
	client_init(&c, H3, 1, "wt.example", g_pin);
	CHECK(hw_tls_peer_transport_params(c.t, NULL) == NULL && hw_tls_alpn(c.t) == NULL, "nothing known yet");
	CHECK_EQ(hw_tls_start(s.t), 0);
	CHECK(s.qn[0] == 0, "a server's start sends nothing");
	CHECK_EQ(hw_tls_start(c.t), 0);
	CHECK(c.qn[0] > 0 && c.qn[1] == 0, "ClientHello at Initial only");
	CHECK_EQ(deliver(&c, &s, step), 1);
	// The server's whole flight is out and its 1-RTT write key installed, but it is not done
	// until the client's Finished.
	CHECK(s.qn[0] > 0 && s.qn[1] > 0 && s.qn[2] == 0, "ServerHello at Initial, the rest at Handshake");
	CHECK(s.have[HW_TLS_HANDSHAKE][0] && s.have[HW_TLS_HANDSHAKE][1] && s.have[HW_TLS_APP][1], "server keys");
	CHECK(!hw_tls_done(s.t), "server done early");
	CHECK_EQ(deliver(&s, &c, step), 1);
	CHECK(hw_tls_done(c.t), "client done");
	CHECK(c.qn[0] == 0 && c.qn[1] > 0, "client Finished at Handshake");
	CHECK_EQ(pump(&c, &s, step), 0);
	check_negotiated(&c, &s, "h3", "wt.example");
	side_clear(&c);
	side_clear(&s);
}

static void test_handshake(void) {
	handshake_with(0);
}

static void test_handshake_bytewise(void) {
	handshake_with(1);
	handshake_with(7);
}

// The server picks its own first preference among what the client offers, without SNI.
static void test_alpn_preference(void) {
	static const char *const srv[] = {"h3", "h3-29"};
	static const char *const cli[] = {"x-other", "h3-29", "h3"};
	side c, s;
	server_init(&s, srv, 2);
	client_init(&c, cli, 3, NULL, NULL);
	CHECK_EQ(hw_tls_start(c.t), 0);
	CHECK_EQ(pump(&c, &s, 0), 0);
	check_negotiated(&c, &s, "h3", NULL);
	side_clear(&c);
	side_clear(&s);
}

// Offset of the first message of the given type in a level's bytes, or (size_t)-1.
static size_t find_msg(const uint8_t *p, size_t n, uint8_t type) {
	size_t off = 0;
	while (off + 4 <= n) {
		size_t len = (size_t)p[off + 1] << 16 | (size_t)p[off + 2] << 8 | p[off + 3];
		if (p[off] == type) return off;
		off += 4 + len;
	}
	return (size_t)-1;
}

// The extension of the given type in a ServerHello (whole message), or NULL.
static const uint8_t *sh_ext(const uint8_t *sh, size_t n, uint16_t type, size_t *len) {
	size_t off = 4 + 2 + 32;
	off += 1 + sh[off];
	off += 2 + 1 + 2;
	while (off + 4 <= n) {
		uint16_t t = (uint16_t)(sh[off] << 8 | sh[off + 1]);
		size_t l = (size_t)sh[off + 2] << 8 | sh[off + 3];
		if (t == type) {
			*len = l;
			return sh + off + 4;
		}
		off += 4 + l;
	}
	return NULL;
}

// A client that sends no share gets a HelloRetryRequest naming X25519, and both roles complete.
static void test_hello_retry(void) {
	for (size_t step = 0; step <= 1; step++) {
		side c, s;
		server_init(&s, H3, 1);
		client_init(&c, H3, 1, "wt.example", g_pin);
		hw_tls_test_omit_key_share(c.t);
		CHECK_EQ(hw_tls_start(c.t), 0);
		CHECK_EQ(deliver(&c, &s, step), 1);
		CHECK(s.qn[0] > 0 && s.qn[1] == 0 && !s.have[HW_TLS_HANDSHAKE][1], "only a HelloRetryRequest");
		uint8_t magic[32];
		hw_sha256("HelloRetryRequest", 17, magic);
		CHECK(s.q[0][0] == 2 && memcmp(s.q[0] + 6, magic, 32) == 0, "HelloRetryRequest random");
		size_t n;
		const uint8_t *ks = sh_ext(s.q[0], s.qn[0], 51, &n);
		CHECK(ks && n == 2 && ks[0] == 0x00 && ks[1] == 0x1d, "selected_group x25519");
		CHECK_EQ(pump(&c, &s, step), 0);
		check_negotiated(&c, &s, "h3", "wt.example");
		side_clear(&c);
		side_clear(&s);
	}
}

// A HelloRetryRequest that a client that did send an X25519 share gets is illegal_parameter, and
// a second one is unexpected_message.
static void test_hello_retry_client_refusals(void) {
	side c, s;
	server_init(&s, H3, 1);
	client_init(&c, H3, 1, NULL, NULL);
	hw_tls_test_omit_key_share(c.t);
	CHECK_EQ(hw_tls_start(c.t), 0);
	CHECK_EQ(deliver(&c, &s, 0), 1);
	uint8_t *hrr = malloc(s.qn[0]);
	size_t hrr_len = s.qn[0];
	CHECK(hrr != NULL, "malloc");
	memcpy(hrr, s.q[0], hrr_len);
	CHECK_EQ(hw_tls_input(c.t, HW_TLS_INITIAL, hrr, hrr_len), 0);
	CHECK_EQ(hw_tls_input(c.t, HW_TLS_INITIAL, hrr, hrr_len), -1);
	CHECK_EQ(hw_tls_alert(c.t), HW_TLS_ALERT_UNEXPECTED_MESSAGE);
	side_clear(&c);

	client_init(&c, H3, 1, NULL, NULL);
	CHECK_EQ(hw_tls_start(c.t), 0);
	CHECK_EQ(hw_tls_input(c.t, HW_TLS_INITIAL, hrr, hrr_len), -1);
	CHECK_EQ(hw_tls_alert(c.t), HW_TLS_ALERT_ILLEGAL_PARAMETER);
	free(hrr);
	side_clear(&c);
	side_clear(&s);
}

// ---- a Chrome-shaped ClientHello -----------------------------------------------------------

static uint32_t g_rng = 0x9e3779b9u;

static uint32_t rng_next(void) {
	uint32_t x = g_rng;
	x ^= x << 13;
	x ^= x >> 17;
	x ^= x << 5;
	return g_rng = x;
}

typedef struct {
	uint8_t p[8192];
	size_t n;
	size_t at[8];
	size_t lb[8];
	int depth;
} bld;

static void b_put(bld *b, const void *d, size_t n) {
	CHECK(b->n + n <= sizeof b->p, "fixture overflow");
	memcpy(b->p + b->n, d, n);
	b->n += n;
}

static void b_u8(bld *b, unsigned v) {
	uint8_t x = (uint8_t)v;
	b_put(b, &x, 1);
}

static void b_u16(bld *b, unsigned v) {
	b_u8(b, v >> 8);
	b_u8(b, v);
}

static void b_rand(bld *b, size_t n) {
	for (size_t i = 0; i < n; i++) b_u8(b, rng_next() >> 24);
}

static void b_open(bld *b, size_t lb) {
	CHECK(b->depth < 8, "fixture nesting");
	b->at[b->depth] = b->n;
	b->lb[b->depth++] = lb;
	static const uint8_t zero[3] = {0};
	b_put(b, zero, lb);
}

static void b_close(bld *b) {
	size_t at = b->at[--b->depth], lb = b->lb[b->depth];
	size_t len = b->n - at - lb;
	for (size_t i = 0; i < lb; i++) b->p[at + i] = (uint8_t)(len >> (8 * (lb - 1 - i)));
}

static void b_ext(bld *b, unsigned type) {
	b_u16(b, type);
	b_open(b, 2);
}

enum {
	F_NO_CHACHA = 1 << 0,
	F_NO_X25519 = 1 << 1,       // neither listed nor shared
	F_NO_X25519_SHARE = 1 << 2, // listed, no share
	F_NO_ALPN = 1 << 3,
	F_ALPN_H2 = 1 << 4,
	F_NO_TP = 1 << 5,
	F_NO_VERSIONS = 1 << 6,
	F_NO_ECDSA = 1 << 7,
	F_DUP_EXT = 1 << 8,
	F_SESSION_ID = 1 << 9, // a 32-byte legacy_session_id, as TCP clients send
	F_TWO_X25519 = 1 << 10,
	F_PSK_NOT_LAST = 1 << 11,
	F_BAD_SHARE_LEN = 1 << 12, // a 31-byte X25519 share
	F_LONG_SHARE = 1 << 13,    // a 33-byte one
	// The second ClientHello after a HelloRetryRequest as BoringSSL (Chrome) makes it: one X25519
	// share and no GREASE or hybrid one, other padding, the PSK's ticket age and binder
	// recomputed; everything else as in the first.
	F_RETRY = 1 << 14,
	F_EARLY_DATA = 1 << 15,
	F_PSK = 1 << 16, // a resumption attempt: pre_shared_key, last
	F_NO_PSK_MODES = 1 << 17,
	F_SUITES_ALT = 1 << 18, // without TLS_AES_256_GCM_SHA384
	F_ALPN_ALT = 1 << 19,   // "h3-29" offered after "h3"
	F_TP_ALT = 1 << 20,     // another initial_max_data
	F_SNI_ALT = 1 << 21,
	F_RANDOM_ALT = 1 << 22,
	F_SHARE_P256 = 1 << 23,      // a P-256 share where the X25519 one goes
	F_X25519_UNLISTED = 1 << 24, // an X25519 share, X25519 not in supported_groups
	F_COMP_TWO = 1 << 25,        // legacy_compression_methods {1, 0}
	F_COMP_ONE = 1 << 26,        // {1}
	F_COMP_EMPTY = 1 << 27,      // {}
	F_ECH_ALT = 1 << 28,         // the ECH payload sealed anew, as a real ECH client does on a retry
};

static unsigned grease(void) {
	return 0x0a0a + 0x1010 * (rng_next() >> 28);
}

#define CHROME_SNI     "www.example.org"
#define CHROME_SNI_ALT "www.example.net"

// A ClientHello as Chrome 150 sends one over QUIC, changed by flags. The same seed gives the same
// bytes, and every random field draws from the generator whatever the flags, so a second
// ClientHello after a HelloRetryRequest differs only where flags differ.
static size_t chrome_hello(uint8_t *out, unsigned flags, const uint8_t x25519_pub[32], uint32_t seed) {
	static bld b;
	memset(&b, 0, sizeof b);
	g_rng = seed;
	unsigned g1 = grease(), g2 = grease();
	if (g2 == g1) g2 ^= 0x1010;
	b_u8(&b, 1);
	b_open(&b, 3);
	b_u16(&b, 0x0303);
	b_rand(&b, 32);
	if (flags & F_RANDOM_ALT) b.p[b.n - 32] ^= 0x01;
	b_open(&b, 1);
	if (flags & F_SESSION_ID) b_rand(&b, 32);
	b_close(&b);
	b_open(&b, 2);
	b_u16(&b, grease());
	b_u16(&b, 0x1301);
	if (!(flags & F_SUITES_ALT)) b_u16(&b, 0x1302);
	if (!(flags & F_NO_CHACHA)) b_u16(&b, 0x1303);
	b_close(&b);
	if (flags & F_COMP_EMPTY) {
		b_u8(&b, 0);
	} else if (flags & F_COMP_TWO) {
		b_put(&b, "\x02\x01\x00", 3);
	} else if (flags & F_COMP_ONE) {
		b_put(&b, "\x01\x01", 2);
	} else {
		b_put(&b, "\x01\x00", 2);
	}
	b_open(&b, 2); // extensions

	b_ext(&b, g1); // GREASE, empty
	b_close(&b);
	b_ext(&b, 0x0000); // server_name
	b_open(&b, 2);
	b_u8(&b, 0);
	b_u16(&b, sizeof CHROME_SNI - 1);
	b_put(&b, flags & F_SNI_ALT ? CHROME_SNI_ALT : CHROME_SNI, sizeof CHROME_SNI - 1);
	b_close(&b);
	b_close(&b);
	b_ext(&b, 0x0005); // status_request
	b_put(&b, "\x01\x00\x00\x00\x00", 5);
	b_close(&b);
	b_ext(&b, 0x000a); // supported_groups
	b_open(&b, 2);
	b_u16(&b, grease());
	b_u16(&b, 0x11ec); // X25519MLKEM768
	if (!(flags & (F_NO_X25519 | F_X25519_UNLISTED))) b_u16(&b, 0x001d);
	b_u16(&b, 0x0017);
	b_u16(&b, 0x0018);
	b_close(&b);
	b_close(&b);
	b_ext(&b, 0x000d); // signature_algorithms
	b_open(&b, 2);
	if (!(flags & F_NO_ECDSA)) b_u16(&b, 0x0403);
	static const uint16_t sigs[] = {0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601};
	for (size_t i = 0; i < HW_ARRAY_LEN(sigs); i++) b_u16(&b, sigs[i]);
	b_close(&b);
	b_close(&b);
	if (!(flags & F_NO_ALPN)) {
		b_ext(&b, 0x0010);
		b_open(&b, 2);
		const char *p = flags & F_ALPN_H2 ? "h2" : "h3";
		b_u8(&b, 2);
		b_put(&b, p, 2);
		if (flags & F_ALPN_ALT) b_put(&b, "\x05h3-29", 6);
		b_close(&b);
		b_close(&b);
	}
	b_ext(&b, 0x0012); // signed_certificate_timestamp
	b_close(&b);
	if (flags & F_PSK_NOT_LAST) {
		b_ext(&b, 0x0029); // pre_shared_key, not last
		b_put(&b, "\x00\x07\x00\x01\x41\x00\x00\x00\x00\x00\x21\x20", 12);
		b_rand(&b, 32);
		b_close(&b);
	}
	if (!(flags & F_NO_VERSIONS)) {
		b_ext(&b, 0x002b); // supported_versions
		b_open(&b, 1);
		b_u16(&b, grease());
		b_u16(&b, 0x0304);
		b_close(&b);
		b_close(&b);
	}
	if (!(flags & F_NO_PSK_MODES)) {
		b_ext(&b, 0x002d); // psk_key_exchange_modes: psk_dhe_ke
		b_put(&b, "\x01\x01", 2);
		b_close(&b);
	}
	if (flags & F_EARLY_DATA) {
		b_ext(&b, 0x002a); // early_data, empty in a ClientHello
		b_close(&b);
	}
	b_ext(&b, 0x0033); // key_share
	b_open(&b, 2);
	unsigned share_grease = grease();
	static uint8_t hybrid[1184 + 32];
	for (size_t i = 0; i < sizeof hybrid; i++) hybrid[i] = (uint8_t)(rng_next() >> 24);
	if (!(flags & F_RETRY)) {
		b_u16(&b, share_grease);
		b_u16(&b, 1);
		b_u8(&b, 0);
		b_u16(&b, 0x11ec);
		b_u16(&b, sizeof hybrid);
		b_put(&b, hybrid, sizeof hybrid);
	}
	if (flags & F_SHARE_P256) {
		b_u16(&b, 0x0017);
		b_u16(&b, 65);
		b_u8(&b, 0x04);
		for (int i = 0; i < 64; i++) b_u8(&b, (unsigned)(i * 5 + 1));
	} else if (!(flags & (F_NO_X25519 | F_NO_X25519_SHARE))) {
		b_u16(&b, 0x001d);
		size_t n = flags & F_BAD_SHARE_LEN ? 31 : flags & F_LONG_SHARE ? 33 : 32;
		b_u16(&b, (unsigned)n);
		b_put(&b, x25519_pub, n < 32 ? n : 32);
		if (n > 32) b_u8(&b, 0);
		if (flags & F_TWO_X25519) {
			b_u16(&b, 0x001d);
			b_u16(&b, 32);
			b_put(&b, x25519_pub, 32);
		}
	}
	b_close(&b);
	b_close(&b);
	b_ext(&b, 0x001b); // compress_certificate: brotli
	b_put(&b, "\x02\x00\x02", 3);
	b_close(&b);
	b_ext(&b, 0x44cd); // application_settings (ALPS): h3
	b_put(&b, "\x00\x03\x02h3", 5);
	b_close(&b);
	b_ext(&b, 0xfe0d); // encrypted_client_hello, GREASE: outer, HKDF-SHA256, AES-128-GCM
	b_put(&b, "\x00\x00\x01\x00\x01", 5);
	b_rand(&b, 1); // config_id
	b_u16(&b, 32);
	b_rand(&b, 32); // enc
	b_u16(&b, 176);
	b_rand(&b, 176); // payload
	if (flags & F_ECH_ALT) b.p[b.n - 1] ^= 0xff;
	b_close(&b);
	if (!(flags & F_NO_TP)) {
		b_ext(&b, 0x0039); // quic_transport_parameters, with a GREASE parameter
		static const uint8_t tp[] = {
		    0x01, 0x04, 0x80, 0x00, 0x75, 0x30, 0x03, 0x02, 0x45, 0xc0, 0x04, 0x04, 0x80, 0xf0, 0x00, 0x00,
		    0x05, 0x04, 0x80, 0x60, 0x00, 0x00, 0x06, 0x04, 0x80, 0x60, 0x00, 0x00, 0x07, 0x04, 0x80, 0x60,
		    0x00, 0x00, 0x08, 0x02, 0x40, 0x64, 0x09, 0x02, 0x40, 0x67, 0x0e, 0x01, 0x04, 0x0f, 0x08, 0x5d,
		    0x41, 0x0e, 0x2c, 0x61, 0x9a, 0x31, 0x07, 0x20, 0x04, 0x80, 0x01, 0x00, 0x00, 0x80, 0x00, 0x47,
		    0x52, 0x04, 0x00, 0x00, 0x00, 0x01, 0xc6, 0x1b, 0x8a, 0x45, 0x2c, 0x00, 0x00, 0x00, 0x00, 0x00,
		};
		b_put(&b, tp, sizeof tp);
		if (flags & F_TP_ALT) b.p[b.n - sizeof tp + 15] ^= 0x01; // initial_max_data's last byte
		b_close(&b);
	}
	if (flags & F_DUP_EXT) {
		b_ext(&b, 0x0005); // status_request again
		b_put(&b, "\x01\x00\x00\x00\x00", 5);
		b_close(&b);
	}
	b_ext(&b, g2); // GREASE, one zero byte
	b_u8(&b, 0);
	b_close(&b);
	b_ext(&b, 0x0015); // padding
	static const uint8_t zeros[32] = {0};
	b_put(&b, zeros, flags & F_RETRY ? 24 : 16);
	b_close(&b);
	if (flags & F_PSK) {
		b_ext(&b, 0x0029); // pre_shared_key: one ticket and its binder
		b_open(&b, 2);
		b_open(&b, 2);
		b_rand(&b, 48);
		b_close(&b);
		uint32_t age = rng_next() + (flags & F_RETRY ? 1500u : 0u);
		b_u16(&b, age >> 16);
		b_u16(&b, age & 0xffff);
		b_close(&b);
		b_open(&b, 2);
		b_open(&b, 1);
		for (int i = 0; i < 32; i++) b_u8(&b, (rng_next() >> 24) ^ (flags & F_RETRY ? 0x5au : 0u));
		b_close(&b);
		b_close(&b);
		b_close(&b);
	}
	b_close(&b); // extensions
	b_close(&b); // body
	CHECK(b.depth == 0, "fixture nesting");
	memcpy(out, b.p, b.n);
	return b.n;
}

static void feed_server(side *s, const uint8_t *msg, size_t len, int want_rc, uint8_t want_alert) {
	int rc = hw_tls_input(s->t, HW_TLS_INITIAL, msg, len);
	CHECK(rc == want_rc, "rc %d, want %d (alert %u)", rc, want_rc, (unsigned)hw_tls_alert(s->t));
	CHECK_EQ(hw_tls_alert(s->t), want_alert);
}

// The test plays Chrome to the end: from the fixture's key and the server's messages it derives
// the handshake secrets itself, checks the server's against them and the server's Finished, and
// sends the client Finished.
static void chrome_complete(side *s, const uint8_t *transcript_head, size_t head_len, const uint8_t x_priv[32]) {
	size_t sh_len = s->qn[0];
	const uint8_t *sh = s->q[0];
	CHECK(sh_len > 4 && sh[0] == 2, "ServerHello");
	size_t n;
	const uint8_t *ks = sh_ext(sh, sh_len, 51, &n);
	CHECK(ks && n == 36 && ks[0] == 0 && ks[1] == 0x1d && ks[2] == 0 && ks[3] == 32, "server share x25519");
	const uint8_t *sv = sh_ext(sh, sh_len, 43, &n);
	CHECK(sv && n == 2 && sv[0] == 3 && sv[1] == 4, "TLS 1.3 selected");
	CHECK(sh[4 + 2 + 32 + 1 + sh[4 + 2 + 32]] == 0x13 && sh[4 + 2 + 32 + 2 + sh[4 + 2 + 32]] == 0x03, "chacha20");
	CHECK(sh_ext(sh, sh_len, 41, &n) == NULL, "no PSK selected");

	uint8_t ecdhe[32], th[32], hs[32], c_hs[32], s_hs[32];
	CHECK(hw_x25519(ecdhe, x_priv, ks + 4) == 0, "x25519");
	hw_sha256_ctx c;
	hw_sha256_init(&c);
	hw_sha256_update(&c, transcript_head, head_len);
	hw_sha256_update(&c, sh, sh_len);
	hw_sha256_ctx x = c;
	hw_sha256_final(&x, th);
	hw_tls_schedule_handshake(ecdhe, th, hs, c_hs, s_hs);
	CHECK(s->have[HW_TLS_HANDSHAKE][1] && memcmp(s->sec[HW_TLS_HANDSHAKE][1], s_hs, 32) == 0, "s hs traffic");
	CHECK(s->have[HW_TLS_HANDSHAKE][0] && memcmp(s->sec[HW_TLS_HANDSHAKE][0], c_hs, 32) == 0, "c hs traffic");

	// EncryptedExtensions, Certificate, CertificateVerify, Finished.
	const uint8_t *f = s->q[1];
	size_t fn = s->qn[1], off = 0;
	static const uint8_t types[] = {8, 11, 15, 20};
	for (size_t i = 0; i < 4; i++) {
		CHECK(off + 4 <= fn && f[off] == types[i], "message %zu is type %u", i, (unsigned)types[i]);
		size_t len = 4 + ((size_t)f[off + 1] << 16 | (size_t)f[off + 2] << 8 | f[off + 3]);
		CHECK(off + len <= fn, "message %zu length", i);
		if (types[i] == 8) {
			// Every extension the server put in EncryptedExtensions: ALPN and the transport
			// parameters, never early_data (0-RTT is refused by leaving it out).
			size_t e = off + 6;
			while (e + 4 <= off + len) {
				unsigned type = (unsigned)f[e] << 8 | f[e + 1];
				CHECK(type == 16 || type == 57, "EncryptedExtensions carries %u", type);
				e += 4 + ((size_t)f[e + 2] << 8 | f[e + 3]);
			}
			CHECK(e == off + len, "EncryptedExtensions framing");
		}
		if (types[i] == 20) {
			uint8_t fk[32], want[32];
			x = c;
			hw_sha256_final(&x, th);
			hw_tls_finished_key(s_hs, fk);
			hw_hmac_sha256(fk, 32, th, 32, want);
			CHECK(len == 36 && memcmp(f + off + 4, want, 32) == 0, "server Finished");
		}
		hw_sha256_update(&c, f + off, len);
		off += len;
	}
	CHECK(off == fn, "nothing after Finished");
	hw_sha256_final(&c, th);
	uint8_t master[32], c_ap[32], s_ap[32];
	hw_tls_schedule_app(hs, th, master, c_ap, s_ap);
	CHECK(s->have[HW_TLS_APP][1] && memcmp(s->sec[HW_TLS_APP][1], s_ap, 32) == 0, "s ap traffic");
	CHECK(s->have[HW_TLS_APP][0] && memcmp(s->sec[HW_TLS_APP][0], c_ap, 32) == 0, "c ap traffic");
	uint8_t fin[36] = {20, 0, 0, 32}, fk[32];
	hw_tls_finished_key(c_hs, fk);
	hw_hmac_sha256(fk, 32, th, 32, fin + 4);
	CHECK(!hw_tls_done(s->t), "not done before the client Finished");
	CHECK_EQ(hw_tls_input(s->t, HW_TLS_HANDSHAKE, fin, sizeof fin), 0);
	CHECK(hw_tls_done(s->t), "done");
	CHECK_STR(hw_tls_alpn(s->t), "h3");
	CHECK(hw_tls_server_name(s->t) != NULL, "sni");
	CHECK_STR(hw_tls_server_name(s->t), CHROME_SNI);
	const uint8_t *tp = hw_tls_peer_transport_params(s->t, &n);
	CHECK(tp && n == 80 && tp[0] == 0x01, "Chrome's TPs, %zu bytes", n);
}

static uint8_t g_hello[8192];

static void test_chrome_hello(void) {
	uint8_t priv[32], pub[32];
	CHECK(hw_x25519_keygen(priv, pub) == 0, "x25519 keygen");
	// As Chrome sends it; with a TCP-style session id; and resuming, with a ticket and 0-RTT that
	// a server without PSKs ignores: a full handshake, no PSK selected, no early_data accepted.
	static const unsigned variants[] = {0, F_SESSION_ID, F_EARLY_DATA | F_PSK};
	for (size_t v = 0; v < HW_ARRAY_LEN(variants); v++) {
		size_t n = chrome_hello(g_hello, variants[v], pub, 0x51ed270bu);
		CHECK(n > 1500, "a Chrome-sized hello: %zu", n);
		side s;
		server_init(&s, H3, 1);
		feed_server(&s, g_hello, n, 0, 0);
		// legacy_session_id is echoed, whatever it is.
		size_t sid = g_hello[4 + 2 + 32];
		CHECK(s.q[0][4 + 2 + 32] == sid && memcmp(s.q[0] + 4 + 2 + 32 + 1, g_hello + 4 + 2 + 32 + 1, sid) == 0,
		      "session id echoed");
		chrome_complete(&s, g_hello, n, priv);
		side_clear(&s);
	}
}

// A server fed first, a hello without an X25519 share, which gets a HelloRetryRequest, then
// second. Returns the HelloRetryRequest's length; it stays in s->q[0] and the transcript head
// (message_hash(first) || HelloRetryRequest || second) is in head.
static size_t retry_feed(side *s, const uint8_t *first, size_t n1, const uint8_t *second, size_t n2, int want_rc,
                         uint8_t want_alert, uint8_t *head, size_t *head_len) {
	server_init(s, H3, 1);
	feed_server(s, first, n1, 0, 0);
	CHECK(s->qn[0] > 0 && s->qn[1] == 0, "HelloRetryRequest only");
	uint8_t magic[32];
	hw_sha256("HelloRetryRequest", 17, magic);
	CHECK(memcmp(s->q[0] + 6, magic, 32) == 0, "HelloRetryRequest random");
	size_t hrr_len = s->qn[0], el;
	const uint8_t *ks = sh_ext(s->q[0], hrr_len, 51, &el);
	CHECK(ks && el == 2 && ks[0] == 0 && ks[1] == 0x1d, "selected_group x25519");
	if (head) {
		head[0] = 254;
		head[1] = head[2] = 0;
		head[3] = 32;
		hw_sha256(first, n1, head + 4);
		memcpy(head + 36, s->q[0], hrr_len);
		memcpy(head + 36 + hrr_len, second, n2);
		*head_len = 36 + hrr_len + n2;
	}
	free(s->q[0]);
	s->q[0] = NULL;
	s->qn[0] = 0;
	feed_server(s, second, n2, want_rc, want_alert);
	return hrr_len;
}

// Chrome listing X25519 with only its hybrid share: one HelloRetryRequest, a second hello in
// BoringSSL's shape (one X25519 share, other padding, early_data gone, the PSK binder
// recomputed, a GREASE ECH copied or a real one sealed anew), and the transcript continues from
// message_hash(ClientHello1).
static void test_chrome_hello_retry(void) {
	uint8_t priv[32], pub[32];
	CHECK(hw_x25519_keygen(priv, pub) == 0, "x25519 keygen");
	static const unsigned shapes[][2] = {
	    {F_NO_X25519_SHARE, F_RETRY},
	    {F_NO_X25519_SHARE | F_SESSION_ID, F_RETRY | F_SESSION_ID},
	    {F_NO_X25519_SHARE | F_EARLY_DATA | F_PSK, F_RETRY | F_PSK},
	    {F_NO_X25519_SHARE | F_PSK, F_RETRY}, // every PSK dropped
	    {F_NO_X25519_SHARE, F_RETRY | F_ECH_ALT},
	};
	static uint8_t ch1[8192], ch2[8192], head[8192 * 2];
	for (size_t i = 0; i < HW_ARRAY_LEN(shapes); i++) {
		size_t n1 = chrome_hello(ch1, shapes[i][0], pub, 77);
		size_t n2 = chrome_hello(ch2, shapes[i][1], pub, 77);
		side s;
		size_t head_len;
		retry_feed(&s, ch1, n1, ch2, n2, 0, 0, head, &head_len);
		chrome_complete(&s, head, head_len, priv);
		side_clear(&s);
	}

	// A second ClientHello still without the share is refused, not retried again.
	size_t n1 = chrome_hello(ch1, F_NO_X25519_SHARE, pub, 77);
	side s;
	retry_feed(&s, ch1, n1, ch1, n1, -1, HW_TLS_ALERT_ILLEGAL_PARAMETER, NULL, NULL);
	side_clear(&s);
}

// A second ClientHello that differs from the first in anything RFC 8446 section 4.1.2 does not
// let it change, or whose share is not one X25519 share, is illegal_parameter; nothing is sent
// for it and no keys are made.
static void test_hello_retry_changed(void) {
	uint8_t pub[32] = {9};
	static const struct {
		unsigned flags;
		const char *what;
	} cases[] = {
	    {F_RETRY | F_SUITES_ALT, "cipher suites"},
	    {F_RETRY | F_ALPN_ALT, "ALPN list"},
	    {F_RETRY | F_TP_ALT, "transport parameters"},
	    {F_RETRY | F_SNI_ALT, "SNI"},
	    {F_RETRY | F_RANDOM_ALT, "random"},
	    {F_RETRY | F_SESSION_ID, "session id"},
	    {F_RETRY | F_NO_TP, "transport parameters dropped"},
	    {F_RETRY | F_NO_ALPN, "ALPN dropped"},
	    {F_RETRY | F_NO_PSK_MODES, "an extension dropped"},
	    {F_RETRY | F_DUP_EXT, "an extension added"},
	    {F_RETRY | F_EARLY_DATA, "early_data kept"},
	    {F_RETRY | F_SHARE_P256, "a share for another group"},
	    {F_RETRY | F_NO_X25519_SHARE, "no share at all"},
	    {F_RETRY | F_TWO_X25519, "two X25519 shares"},
	    {0, "the first hello's shares and an X25519 one"},
	};
	static uint8_t ch1[8192], ch2[8192];
	size_t n1 = chrome_hello(ch1, F_NO_X25519_SHARE, pub, 4321);
	for (size_t i = 0; i < HW_ARRAY_LEN(cases); i++) {
		size_t n2 = chrome_hello(ch2, cases[i].flags, pub, 4321);
		side s;
		retry_feed(&s, ch1, n1, ch2, n2, -1, HW_TLS_ALERT_ILLEGAL_PARAMETER, NULL, NULL);
		CHECK(s.qn[0] == 0 && s.qn[1] == 0, "%s: nothing sent", cases[i].what);
		CHECK(!s.have[HW_TLS_HANDSHAKE][0] && !s.have[HW_TLS_HANDSHAKE][1], "%s: no keys", cases[i].what);
		side_clear(&s);
	}
}

// Each ClientHello that is refused and the alert it is refused with.
static void test_server_refusals(void) {
	static const struct {
		unsigned flags;
		uint8_t alert;
	} cases[] = {
	    {F_NO_CHACHA, HW_TLS_ALERT_HANDSHAKE_FAILURE},
	    {F_NO_X25519, HW_TLS_ALERT_HANDSHAKE_FAILURE},
	    {F_NO_ECDSA, HW_TLS_ALERT_HANDSHAKE_FAILURE},
	    {F_NO_ALPN, HW_TLS_ALERT_NO_APP_PROTOCOL},
	    {F_ALPN_H2, HW_TLS_ALERT_NO_APP_PROTOCOL},
	    {F_NO_TP, HW_TLS_ALERT_MISSING_EXTENSION},
	    {F_NO_VERSIONS, HW_TLS_ALERT_PROTOCOL_VERSION},
	    {F_DUP_EXT, HW_TLS_ALERT_ILLEGAL_PARAMETER},
	    {F_TWO_X25519, HW_TLS_ALERT_ILLEGAL_PARAMETER},
	    {F_PSK_NOT_LAST, HW_TLS_ALERT_ILLEGAL_PARAMETER},
	    {F_BAD_SHARE_LEN, HW_TLS_ALERT_ILLEGAL_PARAMETER},
	    {F_LONG_SHARE, HW_TLS_ALERT_ILLEGAL_PARAMETER},
	    {F_X25519_UNLISTED, HW_TLS_ALERT_ILLEGAL_PARAMETER},
	    {F_PSK | F_NO_PSK_MODES, HW_TLS_ALERT_MISSING_EXTENSION},
	    {F_COMP_TWO, HW_TLS_ALERT_ILLEGAL_PARAMETER},
	    {F_COMP_ONE, HW_TLS_ALERT_ILLEGAL_PARAMETER},
	    {F_COMP_EMPTY, HW_TLS_ALERT_DECODE_ERROR},
	    {F_COMP_TWO | F_NO_VERSIONS, HW_TLS_ALERT_PROTOCOL_VERSION},
	    {F_PSK | F_PSK_NOT_LAST, HW_TLS_ALERT_ILLEGAL_PARAMETER},
	};
	uint8_t pub[32] = {9};
	for (size_t i = 0; i < HW_ARRAY_LEN(cases); i++) {
		size_t n = chrome_hello(g_hello, cases[i].flags, pub, 1234);
		side s;
		server_init(&s, H3, 1);
		feed_server(&s, g_hello, n, -1, cases[i].alert);
		CHECK(s.qn[0] == 0 && s.qn[1] == 0, "case %zu: nothing sent", i);
		CHECK(!s.have[HW_TLS_HANDSHAKE][0], "case %zu: no keys", i);
		// Nothing more is taken once failed.
		CHECK_EQ(hw_tls_input(s.t, HW_TLS_INITIAL, g_hello, 4), -1);
		CHECK_EQ(hw_tls_alert(s.t), cases[i].alert);
		side_clear(&s);
	}

	// RFC 8448's hello is a fine TLS 1.3 hello, but not a QUIC one: it has no ALPN.
	side s;
	server_init(&s, H3, 1);
	feed_server(&s, RFC8448_CH, sizeof RFC8448_CH, -1, HW_TLS_ALERT_NO_APP_PROTOCOL);
	side_clear(&s);

	// A small-order X25519 point.
	uint8_t zero[32] = {0};
	size_t n = chrome_hello(g_hello, 0, zero, 1234);
	server_init(&s, H3, 1);
	feed_server(&s, g_hello, n, -1, HW_TLS_ALERT_ILLEGAL_PARAMETER);
	side_clear(&s);

	// The wrong message, the wrong level, a message too long to reassemble.
	static const uint8_t fin[36] = {20, 0, 0, 32};
	server_init(&s, H3, 1);
	feed_server(&s, fin, sizeof fin, -1, HW_TLS_ALERT_UNEXPECTED_MESSAGE);
	side_clear(&s);
	n = chrome_hello(g_hello, 0, pub, 1234);
	server_init(&s, H3, 1);
	CHECK_EQ(hw_tls_input(s.t, HW_TLS_HANDSHAKE, g_hello, n), -1);
	CHECK_EQ(hw_tls_alert(s.t), HW_TLS_ALERT_UNEXPECTED_MESSAGE);
	side_clear(&s);
	static const uint8_t huge[4] = {1, 0x01, 0x00, 0x00};
	server_init(&s, H3, 1);
	feed_server(&s, huge, sizeof huge, -1, HW_TLS_ALERT_DECODE_ERROR);
	side_clear(&s);
	// A hello followed by more bytes at Initial (the keys changed after it).
	server_init(&s, H3, 1);
	memcpy(g_hello + n, fin, sizeof fin);
	feed_server(&s, g_hello, n + sizeof fin, -1, HW_TLS_ALERT_UNEXPECTED_MESSAGE);
	side_clear(&s);
}

static void test_alpn_mismatch(void) {
	static const char *const h2[] = {"h2"};
	side c, s;
	server_init(&s, H3, 1);
	client_init(&c, h2, 1, NULL, NULL);
	CHECK_EQ(hw_tls_start(c.t), 0);
	CHECK_EQ(pump(&c, &s, 0), -1);
	CHECK_EQ(hw_tls_alert(s.t), HW_TLS_ALERT_NO_APP_PROTOCOL);
	CHECK(!hw_tls_done(s.t) && !hw_tls_done(c.t), "not done");
	side_clear(&c);
	side_clear(&s);
}

// Runs a handshake up to the server's flight, lets tamper change it, and delivers it to the
// client. Returns the client's input result.
static int client_flight(side *c, side *s, const uint8_t *pin, void (*tamper)(side *s)) {
	server_init(s, H3, 1);
	client_init(c, H3, 1, "wt.example", pin);
	CHECK_EQ(hw_tls_start(c->t), 0);
	CHECK_EQ(deliver(c, s, 0), 1);
	if (tamper) tamper(s);
	return deliver(s, c, 0) < 0 ? -1 : 0;
}

static void flip_in(side *s, uint8_t type, size_t at) {
	size_t off = find_msg(s->q[1], s->qn[1], type);
	CHECK(off != (size_t)-1, "message %u", (unsigned)type);
	s->q[1][off + at] ^= 0x01;
}

static void tamper_cv(side *s) {
	flip_in(s, 15, 4 + 2 + 2 + 10); // a byte of r
}

static void tamper_server_fin(side *s) {
	flip_in(s, 20, 4 + 31);
}

static void tamper_ee_alpn(side *s) {
	// EncryptedExtensions starts with ALPN: 08 len3 | extlen2 | 00 10 | len2 | listlen2 | 02 'h' '3'
	CHECK(s->q[1][0] == 8 && s->q[1][6] == 0x00 && s->q[1][7] == 0x10, "ALPN first");
	s->q[1][13] = '2';
}

static void tamper_cert_ctx(side *s) {
	size_t off = find_msg(s->q[1], s->qn[1], 11);
	CHECK(off != (size_t)-1, "Certificate");
	s->q[1][off + 4] = 1; // a non-empty context, which overruns the list length
}

static void tamper_sh_ext(side *s) {
	size_t n;
	uint8_t *sv = (uint8_t *)sh_ext(s->q[0], s->qn[0], 43, &n);
	CHECK(sv != NULL, "supported_versions");
	sv[-3] = 42; // early_data, which the client never offered
}

static void test_client_refusals(void) {
	side c, s;
	uint8_t wrong[32];
	memcpy(wrong, g_pin, 32);
	wrong[0] ^= 0x80;
	CHECK_EQ(client_flight(&c, &s, wrong, NULL), -1);
	CHECK_EQ(hw_tls_alert(c.t), HW_TLS_ALERT_BAD_CERTIFICATE);
	CHECK(!c.have[HW_TLS_APP][1], "no 1-RTT keys");
	side_clear(&c);
	side_clear(&s);

	CHECK_EQ(client_flight(&c, &s, g_pin, tamper_cv), -1);
	CHECK_EQ(hw_tls_alert(c.t), HW_TLS_ALERT_DECRYPT_ERROR);
	side_clear(&c);
	side_clear(&s);

	CHECK_EQ(client_flight(&c, &s, g_pin, tamper_server_fin), -1);
	CHECK_EQ(hw_tls_alert(c.t), HW_TLS_ALERT_DECRYPT_ERROR);
	CHECK(!hw_tls_done(c.t) && c.qn[1] == 0, "no client Finished");
	side_clear(&c);
	side_clear(&s);

	CHECK_EQ(client_flight(&c, &s, g_pin, tamper_ee_alpn), -1);
	CHECK_EQ(hw_tls_alert(c.t), HW_TLS_ALERT_ILLEGAL_PARAMETER);
	side_clear(&c);
	side_clear(&s);

	CHECK_EQ(client_flight(&c, &s, g_pin, tamper_cert_ctx), -1);
	CHECK(hw_tls_alert(c.t) == HW_TLS_ALERT_DECODE_ERROR || hw_tls_alert(c.t) == HW_TLS_ALERT_ILLEGAL_PARAMETER,
	      "alert %u", (unsigned)hw_tls_alert(c.t));
	side_clear(&c);
	side_clear(&s);

	CHECK_EQ(client_flight(&c, &s, g_pin, tamper_sh_ext), -1);
	CHECK_EQ(hw_tls_alert(c.t), HW_TLS_ALERT_UNSUPPORTED_EXT);
	CHECK(!c.have[HW_TLS_HANDSHAKE][0], "no keys from a refused ServerHello");
	side_clear(&c);
	side_clear(&s);

	// Without a pin any leaf is taken (tests only), but its signature still has to verify.
	CHECK_EQ(client_flight(&c, &s, NULL, NULL), 0);
	CHECK(hw_tls_done(c.t), "done without a pin");
	side_clear(&c);
	side_clear(&s);
}

// The server holds the client's Finished to the transcript too.
static void test_tampered_client_finished(void) {
	side c, s;
	CHECK_EQ(client_flight(&c, &s, g_pin, NULL), 0);
	CHECK(hw_tls_done(c.t) && c.qn[1] == 36, "client Finished queued");
	c.q[1][20] ^= 0x40;
	CHECK_EQ(deliver(&c, &s, 0), -1);
	CHECK_EQ(hw_tls_alert(s.t), HW_TLS_ALERT_DECRYPT_ERROR);
	CHECK(!hw_tls_done(s.t), "not done");
	side_clear(&c);
	side_clear(&s);
}

// After the handshake: a NewSessionTicket is ignored by the client, a KeyUpdate is
// unexpected_message (QUIC forbids it), and so is anything at all to the server.
static void test_post_handshake(void) {
	side c, s;
	server_init(&s, H3, 1);
	client_init(&c, H3, 1, NULL, g_pin);
	CHECK_EQ(hw_tls_start(c.t), 0);
	CHECK_EQ(pump(&c, &s, 0), 0);
	CHECK(hw_tls_done(c.t) && hw_tls_done(s.t), "done");
	static const uint8_t nst[] = {4, 0, 0, 14, 0, 0, 0x1c, 0x20, 1, 2, 3, 4, 0, 0, 1, 7, 0, 0};
	CHECK_EQ(hw_tls_input(c.t, HW_TLS_APP, nst, 5), 0);
	CHECK_EQ(hw_tls_input(c.t, HW_TLS_APP, nst + 5, sizeof nst - 5), 0);
	CHECK(hw_tls_done(c.t) && hw_tls_alert(c.t) == 0, "ticket ignored");
	static const uint8_t key_update[] = {24, 0, 0, 1, 0};
	CHECK_EQ(hw_tls_input(c.t, HW_TLS_APP, key_update, sizeof key_update), -1);
	CHECK_EQ(hw_tls_alert(c.t), HW_TLS_ALERT_UNEXPECTED_MESSAGE);
	CHECK(!hw_tls_done(c.t), "a failed handshake is not done");
	CHECK_EQ(hw_tls_input(s.t, HW_TLS_APP, nst, sizeof nst), -1);
	CHECK_EQ(hw_tls_alert(s.t), HW_TLS_ALERT_UNEXPECTED_MESSAGE);
	side_clear(&c);
	side_clear(&s);

	// Handshake bytes at a level the client is past.
	server_init(&s, H3, 1);
	client_init(&c, H3, 1, NULL, g_pin);
	CHECK_EQ(hw_tls_start(c.t), 0);
	CHECK_EQ(pump(&c, &s, 0), 0);
	CHECK_EQ(hw_tls_input(c.t, HW_TLS_HANDSHAKE, nst, 1), -1);
	CHECK_EQ(hw_tls_alert(c.t), HW_TLS_ALERT_UNEXPECTED_MESSAGE);
	side_clear(&c);
	side_clear(&s);

	// Input to a client that has not started.
	client_init(&c, H3, 1, NULL, NULL);
	CHECK_EQ(hw_tls_input(c.t, HW_TLS_INITIAL, nst, sizeof nst), -1);
	CHECK_EQ(hw_tls_alert(c.t), HW_TLS_ALERT_UNEXPECTED_MESSAGE);
	side_clear(&c);
}

// A refusing callback aborts with internal_error.
static void test_callback_failure(void) {
	side c, s;
	server_init(&s, H3, 1);
	client_init(&c, H3, 1, NULL, NULL);
	s.fail_secret = 1;
	CHECK_EQ(hw_tls_start(c.t), 0);
	CHECK_EQ(deliver(&c, &s, 0), -1);
	CHECK_EQ(hw_tls_alert(s.t), HW_TLS_ALERT_INTERNAL_ERROR);
	side_clear(&c);
	side_clear(&s);
}

static void test_config_refusals(void) {
	hw_tls_callbacks cb = {.emit = emit_cb};
	hw_tls_config cfg = {.is_server = 1, .alpn = H3, .alpn_count = 1};
	CHECK(hw_tls_new(&cfg, &cb) == NULL, "server without a chain");
	cfg.chain = &g_cert;
	cfg.chain_len = 1;
	CHECK(hw_tls_new(&cfg, &cb) == NULL, "server without a key");
	cfg.key = g_priv;
	cfg.alpn_count = 0;
	CHECK(hw_tls_new(&cfg, &cb) == NULL, "no ALPN");
	static const char *const empty[] = {""};
	cfg.alpn = empty;
	cfg.alpn_count = 1;
	CHECK(hw_tls_new(&cfg, &cb) == NULL, "an empty ALPN name");
	cfg.alpn = H3;
	hw_tls_callbacks none = {0};
	CHECK(hw_tls_new(&cfg, &none) == NULL, "no emit");
	hw_tls *t = hw_tls_new(&cfg, &cb);
	CHECK(t != NULL, "valid");
	hw_tls_free(t);
	hw_tls_free(NULL);
}

// ---- one extension at a time ---------------------------------------------------------------

static size_t unhex_sp(const char *s, uint8_t *out, size_t cap) {
	size_t n = 0;
	for (; *s; s++) {
		if (*s == ' ') continue;
		CHECK(s[1] && n < cap, "hex %s", s);
		out[n++] = (uint8_t)(nibble(s[0]) << 4 | nibble(s[1]));
		s++;
	}
	return n;
}

static uint8_t g_mini_pub[32];

#define MINI_OMIT ((const char *)1) // mini_hello: leave the extension out

// A small ClientHello our server accepts, extension by extension, except that the extension of
// the given type gets body (hex) instead of its own, is left out for MINI_OMIT, or is added last
// when the hello has none of that type. extra, when not NULL, is one more whole extension (hex),
// after all of them.
static size_t mini_hello(uint8_t *out, size_t cap, unsigned type, const char *body, const char *extra) {
	static const struct {
		unsigned type;
		const char *hex; // NULL: the X25519 share of g_mini_pub
	} base[] = {
	    {0, "0007 00 0004 77742e78"},
	    {10, "0002 001d"},
	    {13, "0002 0403"},
	    {43, "02 0304"},
	    {16, "0003 02 6833"},
	    {51, NULL},
	    {57, "0104 80007530 0404 80100000"},
	};
	static bld b;
	memset(&b, 0, sizeof b);
	b_u8(&b, 1);
	b_open(&b, 3);
	b_u16(&b, 0x0303);
	for (int i = 0; i < 32; i++) b_u8(&b, (unsigned)i);
	b_u8(&b, 0);
	b_put(&b, "\x00\x02\x13\x03\x01\x00", 6);
	b_open(&b, 2);
	int done = 0;
	uint8_t tmp[1024];
	for (size_t i = 0; i <= HW_ARRAY_LEN(base); i++) {
		unsigned t;
		const char *hex;
		if (i < HW_ARRAY_LEN(base)) {
			t = base[i].type;
			hex = base[i].hex;
			if (t == type) {
				done = 1;
				if (body == MINI_OMIT) continue;
				hex = body;
			}
		} else {
			if (done || body == MINI_OMIT) break;
			t = type;
			hex = body;
		}
		b_ext(&b, t);
		if (hex) {
			size_t n = unhex_sp(hex, tmp, sizeof tmp);
			b_put(&b, tmp, n);
		} else {
			b_put(&b, "\x00\x24\x00\x1d\x00\x20", 6);
			b_put(&b, g_mini_pub, 32);
		}
		b_close(&b);
	}
	if (extra) b_put(&b, tmp, unhex_sp(extra, tmp, sizeof tmp));
	b_close(&b);
	b_close(&b);
	CHECK(b.depth == 0 && b.n <= cap, "fixture");
	memcpy(out, b.p, b.n);
	return b.n;
}

// Each extension's inner lengths, its refusals and what is ignored. Alert 0: the hello is taken
// (answered with a ServerHello or a HelloRetryRequest).
static void test_extension_bodies(void) {
	uint8_t priv[32];
	CHECK(hw_x25519_keygen(priv, g_mini_pub) == 0, "keygen");
	static const char psk_ok[] =
	    "0007 0001 41 00000000 0021 20 abababababababababababababababababababababababababababababababab";
	static const char psk_short_binder[] = "0007 0001 41 00000000 0001 00";
	static const struct {
		const char *body;
		unsigned type;
		uint8_t alert;
	} cases[] = {
	    {MINI_OMIT, 0xffff, 0}, // the base hello itself
	    // supported_versions
	    {"", 43, HW_TLS_ALERT_DECODE_ERROR},
	    {"00", 43, HW_TLS_ALERT_DECODE_ERROR},
	    {"01 03", 43, HW_TLS_ALERT_DECODE_ERROR},
	    {"03 030403", 43, HW_TLS_ALERT_DECODE_ERROR},
	    {"02 0304 00", 43, HW_TLS_ALERT_DECODE_ERROR},
	    {"03 0304", 43, HW_TLS_ALERT_DECODE_ERROR},
	    {"02 0303", 43, HW_TLS_ALERT_PROTOCOL_VERSION},
	    {"04 7a7a 0304", 43, 0},
	    {MINI_OMIT, 43, HW_TLS_ALERT_PROTOCOL_VERSION},
	    // signature_algorithms
	    {"0000", 13, HW_TLS_ALERT_DECODE_ERROR},
	    {"0001 04", 13, HW_TLS_ALERT_DECODE_ERROR},
	    {"0003 040300", 13, HW_TLS_ALERT_DECODE_ERROR},
	    {"0002 0403 00", 13, HW_TLS_ALERT_DECODE_ERROR},
	    {"0002 0804", 13, HW_TLS_ALERT_HANDSHAKE_FAILURE},
	    {"0004 0a0a 0403", 13, 0},
	    {MINI_OMIT, 13, HW_TLS_ALERT_MISSING_EXTENSION},
	    // supported_groups
	    {"0000", 10, HW_TLS_ALERT_DECODE_ERROR},
	    {"0003 001d00", 10, HW_TLS_ALERT_DECODE_ERROR},
	    {"0002 0017", 10, HW_TLS_ALERT_ILLEGAL_PARAMETER}, // an X25519 share, X25519 not listed
	    {"0004 2a2a 001d", 10, 0},
	    {MINI_OMIT, 10, HW_TLS_ALERT_MISSING_EXTENSION},
	    // application_layer_protocol_negotiation
	    {"0000", 16, HW_TLS_ALERT_DECODE_ERROR},
	    {"0001 00", 16, HW_TLS_ALERT_DECODE_ERROR},
	    {"0003 00 6833", 16, HW_TLS_ALERT_DECODE_ERROR},
	    {"0003 03 6833", 16, HW_TLS_ALERT_DECODE_ERROR},
	    {"0004 02 6833 00", 16, HW_TLS_ALERT_DECODE_ERROR},
	    {"0003 02 6833 00", 16, HW_TLS_ALERT_DECODE_ERROR},
	    {"0003 02 6832", 16, HW_TLS_ALERT_NO_APP_PROTOCOL},
	    {"0006 02 6832 02 6833", 16, 0},
	    {MINI_OMIT, 16, HW_TLS_ALERT_NO_APP_PROTOCOL},
	    // server_name
	    {"", 0, HW_TLS_ALERT_DECODE_ERROR},
	    {"0000", 0, HW_TLS_ALERT_DECODE_ERROR},
	    {"0003 00 0000", 0, HW_TLS_ALERT_DECODE_ERROR},
	    {"0005 00 0003 6162", 0, HW_TLS_ALERT_DECODE_ERROR},
	    {"000a 00 0002 6162 00 0002 6364", 0, HW_TLS_ALERT_ILLEGAL_PARAMETER}, // two host_names
	    {"0005 00 0002 6100", 0, HW_TLS_ALERT_ILLEGAL_PARAMETER},
	    {"0005 00 0002 610a", 0, HW_TLS_ALERT_ILLEGAL_PARAMETER},
	    {"0005 00 0002 6120", 0, HW_TLS_ALERT_ILLEGAL_PARAMETER},
	    {"0005 00 0002 61ff", 0, HW_TLS_ALERT_ILLEGAL_PARAMETER},
	    {"0005 01 0002 6162", 0, 0}, // a name type this does not know
	    {"000a 01 0002 0000 00 0002 6162", 0, 0},
	    {MINI_OMIT, 0, 0},
	    // key_share
	    {"", 51, HW_TLS_ALERT_DECODE_ERROR},
	    {"0001 00", 51, HW_TLS_ALERT_DECODE_ERROR},
	    {"0004 001d 0000", 51, HW_TLS_ALERT_DECODE_ERROR},
	    {"0004 0017 0001", 51, HW_TLS_ALERT_DECODE_ERROR},
	    {"0005 001d 0001 00", 51, HW_TLS_ALERT_ILLEGAL_PARAMETER},
	    {"0000", 51, 0},                        // no share: a HelloRetryRequest
	    {"0005 0a0a 0001 00", 51, 0},           // GREASE only: the same
	    {"000a 0017 0006 040102030405", 51, 0}, // another group's, any length
	    {MINI_OMIT, 51, HW_TLS_ALERT_MISSING_EXTENSION},
	    // early_data, psk_key_exchange_modes, pre_shared_key, cookie, padding
	    {"00", 42, HW_TLS_ALERT_DECODE_ERROR},
	    {"", 42, 0},
	    {"", 45, HW_TLS_ALERT_DECODE_ERROR},
	    {"00", 45, HW_TLS_ALERT_DECODE_ERROR},
	    {"02 01", 45, HW_TLS_ALERT_DECODE_ERROR},
	    {"01 01", 45, 0},
	    {"", 41, HW_TLS_ALERT_DECODE_ERROR},
	    {psk_short_binder, 41, HW_TLS_ALERT_DECODE_ERROR},
	    {psk_ok, 41, HW_TLS_ALERT_MISSING_EXTENSION}, // without psk_key_exchange_modes
	    {"0002 abcd", 44, 0},
	    {"000000000000", 21, 0},
	    // quic_transport_parameters
	    {MINI_OMIT, 57, HW_TLS_ALERT_MISSING_EXTENSION},
	};
	static uint8_t m[4096];
	for (size_t i = 0; i < HW_ARRAY_LEN(cases); i++) {
		size_t n = mini_hello(m, sizeof m, cases[i].type, cases[i].body, NULL);
		side s;
		server_init(&s, H3, 1);
		int rc = hw_tls_input(s.t, HW_TLS_INITIAL, m, n);
		CHECK(rc == (cases[i].alert ? -1 : 0) && hw_tls_alert(s.t) == cases[i].alert,
		      "case %zu (type %u, %s): rc %d alert %u, want %u", i, cases[i].type,
		      cases[i].body == MINI_OMIT ? "left out" : cases[i].body, rc, (unsigned)hw_tls_alert(s.t),
		      (unsigned)cases[i].alert);
		if (rc) CHECK(s.qn[0] == 0 && s.qn[1] == 0, "case %zu: nothing sent", i);
		side_clear(&s);
	}

	// A pre_shared_key with its modes is ignored: a full handshake, and no PSK selected.
	static char psk_ext[160];
	snprintf(psk_ext, sizeof psk_ext, "0029 002c %s", psk_ok);
	size_t n = mini_hello(m, sizeof m, 45, "01 01", psk_ext);
	side s;
	server_init(&s, H3, 1);
	feed_server(&s, m, n, 0, 0);
	CHECK(s.qn[0] > 0 && s.qn[1] > 0, "a full handshake");
	size_t el;
	CHECK(sh_ext(s.q[0], s.qn[0], 41, &el) == NULL, "no PSK selected");
	side_clear(&s);
	// The same, not last.
	n = mini_hello(m, sizeof m, 41, psk_ok, "002d 0002 01 01");
	server_init(&s, H3, 1);
	feed_server(&s, m, n, -1, HW_TLS_ALERT_ILLEGAL_PARAMETER);
	side_clear(&s);

	// A host_name of 255 bytes is taken, one of 256 is not.
	for (size_t len = 255; len <= 256; len++) {
		static char sni[2 * 300 + 32];
		size_t o = (size_t)snprintf(sni, sizeof sni, "%04zx 00 %04zx ", len + 3, len);
		for (size_t i = 0; i < len; i++) o += (size_t)snprintf(sni + o, sizeof sni - o, "61");
		n = mini_hello(m, sizeof m, 0, sni, NULL);
		server_init(&s, H3, 1);
		feed_server(&s, m, n, len == 255 ? 0 : -1, len == 255 ? 0 : HW_TLS_ALERT_ILLEGAL_PARAMETER);
		if (len == 255) CHECK(hw_tls_server_name(s.t) && strlen(hw_tls_server_name(s.t)) == 255, "long SNI");
		side_clear(&s);
	}
}

// The message being reassembled holds what has arrived, not what its header claims, and nothing
// once the handshake is done.
static void test_reassembly_memory(void) {
	side s;
	server_init(&s, H3, 1);
	static const uint8_t hdr[4] = {1, 0x00, 0xff, 0xfc}; // a ClientHello of 65532 bytes
	feed_server(&s, hdr, sizeof hdr, 0, 0);
	CHECK(hw_tls_test_rx_cap(s.t) <= 256, "a header costs %zu bytes", hw_tls_test_rx_cap(s.t));
	static uint8_t body[4096];
	memset(body, 0x41, sizeof body);
	feed_server(&s, body, sizeof body, 0, 0);
	CHECK(hw_tls_test_rx_cap(s.t) <= 2 * (sizeof body + 4), "4 KiB in costs %zu", hw_tls_test_rx_cap(s.t));
	side_clear(&s);

	side c;
	server_init(&s, H3, 1);
	client_init(&c, H3, 1, "wt.example", g_pin);
	CHECK_EQ(hw_tls_start(c.t), 0);
	CHECK_EQ(pump(&c, &s, 3), 0);
	CHECK(hw_tls_done(c.t) && hw_tls_done(s.t), "done");
	CHECK_EQ(hw_tls_test_rx_cap(s.t), 0);
	CHECK_EQ(hw_tls_test_rx_cap(c.t), 0);
	side_clear(&c);
	side_clear(&s);
}

// ---- robustness ----------------------------------------------------------------------------

// One fresh server per input; it may accept, wait or refuse, but a refusal names an alert and
// nothing is sent after one.
// When set, each fresh server is first fed this hello (one that gets a HelloRetryRequest), so the
// input is a second ClientHello.
static const uint8_t *g_fuzz_first;
static size_t g_fuzz_first_len;

static int fuzz_server_once(const uint8_t *msg, size_t len) {
	side s;
	server_init(&s, H3, 1);
	if (g_fuzz_first) {
		CHECK_EQ(hw_tls_input(s.t, HW_TLS_INITIAL, g_fuzz_first, g_fuzz_first_len), 0);
		CHECK(s.qn[0] > 0 && s.qn[1] == 0, "a HelloRetryRequest");
		free(s.q[0]);
		s.q[0] = NULL;
		s.qn[0] = 0;
	}
	int rc = hw_tls_input(s.t, HW_TLS_INITIAL, msg, len);
	if (rc != 0) {
		CHECK(hw_tls_alert(s.t) != 0, "refused without an alert");
		CHECK(s.qn[1] == 0, "a refused hello got a flight");
	}
	side_clear(&s);
	return rc;
}

static void fuzz_hello(const uint8_t *base, size_t n, uint32_t seed, int rounds, int *refused) {
	static uint8_t m[8192];
	CHECK(n > 16 && n <= sizeof m, "base of %zu bytes", n);
	// Every prefix as it is (the server waits), and every truncation with the header's length
	// patched to it (the parse runs out at every byte).
	for (size_t cut = 0; cut <= n; cut++) {
		memcpy(m, base, cut);
		CHECK(fuzz_server_once(m, cut) == 0 || cut == n, "a prefix of %zu bytes was refused", cut);
		if (cut < 4) continue;
		size_t body = cut - 4;
		m[1] = (uint8_t)(body >> 16);
		m[2] = (uint8_t)(body >> 8);
		m[3] = (uint8_t)body;
		*refused += fuzz_server_once(m, cut) != 0;
	}
	g_rng = seed;
	for (int i = 0; i < rounds; i++) {
		memcpy(m, base, n);
		size_t len = n;
		int edits = 1 + (int)(rng_next() % 4);
		for (int e = 0; e < edits; e++) {
			uint32_t r = rng_next();
			if (len <= 16) break;
			size_t at = 4 + r % (len - 4);
			switch (r >> 30) {
			case 0:
				m[at] ^= (uint8_t)(1u << (rng_next() & 7));
				break;
			case 1:
				m[at] = (uint8_t)rng_next();
				break;
			case 2:
				m[at] = (r & 0x100) ? 0xff : 0x00;
				break;
			default:
				// Delete a short run and patch the message length.
				if (len > 16) {
					size_t k = 1 + rng_next() % 8;
					if (at + k > len) k = len - at;
					memmove(m + at, m + at + k, len - at - k);
					len -= k;
				}
				break;
			}
		}
		if (rng_next() & 1) {
			size_t body = len - 4;
			m[1] = (uint8_t)(body >> 16);
			m[2] = (uint8_t)(body >> 8);
			m[3] = (uint8_t)body;
		}
		*refused += fuzz_server_once(m, len) != 0;
	}
}

static void test_fuzz_client_hello(void) {
	uint8_t pub[32];
	uint8_t priv[32];
	CHECK(hw_x25519_keygen(priv, pub) == 0, "keygen");
	static uint8_t base[8192];
	int refused = 0;
	size_t n = chrome_hello(base, 0, pub, 99);
	fuzz_hello(base, n, 0xc0ffee, 700, &refused);
	// Our own client's hello, which is denser in structure.
	side c;
	client_init(&c, H3, 1, "wt.example", NULL);
	CHECK_EQ(hw_tls_start(c.t), 0);
	n = c.qn[0];
	memcpy(base, c.q[0], n);
	side_clear(&c);
	fuzz_hello(base, n, 0xbadc0de, 700, &refused);
	CHECK(refused > 1000, "only %d refused", refused);
}

// Mutated second ClientHellos after a HelloRetryRequest, from a fixed seed: mostly refused for
// differing from the first, never a crash or a read past the message.
static void test_fuzz_second_hello(void) {
	uint8_t pub[32], priv[32];
	CHECK(hw_x25519_keygen(priv, pub) == 0, "keygen");
	static uint8_t ch1[8192], ch2[8192];
	size_t n1 = chrome_hello(ch1, F_NO_X25519_SHARE | F_EARLY_DATA | F_PSK, pub, 2024);
	size_t n2 = chrome_hello(ch2, F_RETRY | F_PSK, pub, 2024);
	g_fuzz_first = ch1;
	g_fuzz_first_len = n1;
	int refused = 0;
	fuzz_hello(ch2, n2, 0x5ec0, 500, &refused);
	g_fuzz_first = NULL;
	CHECK(refused > 800, "only %d refused", refused);
}

// Mutated server flights to fresh clients: refused (or, rarely, still valid), never a crash.
static void test_fuzz_server_flight(void) {
	g_rng = 0x5eed;
	int refused = 0;
	for (int i = 0; i < 120; i++) {
		side c, s;
		server_init(&s, H3, 1);
		client_init(&c, H3, 1, NULL, NULL);
		CHECK_EQ(hw_tls_start(c.t), 0);
		CHECK_EQ(deliver(&c, &s, 0), 1);
		int level = (int)(rng_next() & 1);
		size_t len = s.qn[level];
		size_t at = rng_next() % len;
		uint32_t how = rng_next();
		if (how & 1) {
			s.q[level][at] ^= (uint8_t)(1u << (how >> 1 & 7));
		} else {
			s.qn[level] = at; // cut short: the client waits or is refused
		}
		int rc = deliver(&s, &c, (how >> 4 & 1) ? 1 : 0);
		if (rc < 0) {
			refused++;
			CHECK(hw_tls_alert(c.t) != 0, "refused without an alert");
			CHECK(!hw_tls_done(c.t), "refused but done");
		}
		side_clear(&c);
		side_clear(&s);
	}
	CHECK(refused > 30, "only %d refused", refused);
}

int main(void) {
	RUN(test_key_schedule_rfc8448);
	RUN(test_rfc8448_ecdhe);
	fixture_cert();
	RUN(test_config_refusals);
	RUN(test_handshake);
	RUN(test_handshake_bytewise);
	RUN(test_alpn_preference);
	RUN(test_hello_retry);
	RUN(test_hello_retry_client_refusals);
	RUN(test_chrome_hello);
	RUN(test_chrome_hello_retry);
	RUN(test_hello_retry_changed);
	RUN(test_server_refusals);
	RUN(test_extension_bodies);
	RUN(test_reassembly_memory);
	RUN(test_alpn_mismatch);
	RUN(test_client_refusals);
	RUN(test_tampered_client_finished);
	RUN(test_post_handshake);
	RUN(test_callback_failure);
	RUN(test_fuzz_client_hello);
	RUN(test_fuzz_second_hello);
	RUN(test_fuzz_server_flight);
	hw_der_free(&g_cert);
	return 0;
}
