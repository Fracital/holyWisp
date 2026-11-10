#include "holywisp/base64.h"
#include "holywisp/sha1.h"
#include "holywisp/ws.h"

#include "test.h"

static void hex(const uint8_t *d, size_t n, char *out) {
	for (size_t i = 0; i < n; i++) snprintf(out + i * 2, 3, "%02x", d[i]);
}

static void check_sha1(const char *msg, const char *want) {
	uint8_t d[HW_SHA1_LEN];
	char got[HW_SHA1_LEN * 2 + 1];
	hw_sha1(msg, strlen(msg), d);
	hex(d, sizeof(d), got);
	CHECK_STR(got, want);
}

static void test_sha1_vectors(void) {
	check_sha1("", "da39a3ee5e6b4b0d3255bfef95601890afd80709");
	check_sha1("abc", "a9993e364706816aba3e25717850c26c9cd0d89d");
	// 56 bytes: the padding spills into a second block.
	check_sha1("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "84983e441c3bd26ebaae4aa1f95129e5e54670f1");
	check_sha1("The quick brown fox jumps over the lazy dog", "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12");
	// 1000 x 'a' crosses many blocks.
	char big[1001];
	memset(big, 'a', 1000);
	big[1000] = '\0';
	check_sha1(big, "291e9a6c66994949b57ba5e650361e98fc36b1ba");
}

static void test_base64(void) {
	static const struct {
		const char *in;
		const char *out;
	} cases[] = {
	    {"", ""},
	    {"f", "Zg=="},
	    {"fo", "Zm8="},
	    {"foo", "Zm9v"},
	    {"foob", "Zm9vYg=="},
	    {"fooba", "Zm9vYmE="},
	    {"foobar", "Zm9vYmFy"},
	};
	for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		char out[64];
		size_t n = hw_base64_encode((const uint8_t *)cases[i].in, strlen(cases[i].in), out, sizeof(out));
		CHECK_EQ(n, strlen(cases[i].out));
		CHECK_STR(out, cases[i].out);
	}
	char small[4];
	CHECK_EQ(hw_base64_encode((const uint8_t *)"foo", 3, small, sizeof(small)), 0);
	uint8_t bin[] = {0x00, 0xff, 0x80, 0x7f};
	char out[HW_BASE64_LEN(4)];
	hw_base64_encode(bin, 4, out, sizeof(out));
	CHECK_STR(out, "AP+Afw==");
}

static void test_ws_accept_key(void) {
	// RFC 6455 section 1.3 example.
	char out[HW_WS_ACCEPT_LEN + 1];
	hw_ws_accept_key("dGhlIHNhbXBsZSBub25jZQ==", out);
	CHECK_STR(out, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
}

int main(void) {
	RUN(test_sha1_vectors);
	RUN(test_base64);
	RUN(test_ws_accept_key);
	return 0;
}
