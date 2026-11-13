/*
 * The WARP tunnel choice for UDP streams (holywisp/warp.h) against the edge router's own answers
 * (tests/warp_vectors.h, generated from edge-router.py), and the state file's reader.
 */
#include "holywisp/blake2b.h"
#include "holywisp/warp.h"

#include "test.h"
#include "warp_vectors.h"

#include <stdio.h>
#include <string.h>

#define COUNT(a) (sizeof(a) / sizeof((a)[0]))

static void hex(const uint8_t *d, size_t n, char *out) {
	for (size_t i = 0; i < n; i++) snprintf(out + 2 * i, 3, "%02x", d[i]);
}

static void test_blake2b(void) {
	// RFC 7693 appendix A, and Python's hashlib for the empty input, block edges and the lengths
	// the tunnel score does not use.
	static const struct {
		const char *in;
		size_t repeat;
		size_t outlen;
		const char *want;
	} v[] = {
	    {"abc", 1, 64,
	     "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf"
	     "1925ab92386edd4009923"},
	    {"", 0, 64,
	     "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448"
	     "b755d56f701afe9be2ce"},
	    {"a", 128, 8, "f06643fe9c7e18da"},
	    {"a", 129, 8, "e462535bb0c5a299"},
	    {"x", 1000, 32, "ab75119ede14ef06ebf31f745fb655ed006cccfe8054c635308a557f7c9beaba"},
	    {"", 0, 1, "2e"},
	};
	for (size_t i = 0; i < COUNT(v); i++) {
		uint8_t buf[1000];
		size_t len = 0;
		for (size_t r = 0; r < v[i].repeat; r++) {
			memcpy(buf + len, v[i].in, strlen(v[i].in));
			len += strlen(v[i].in);
		}
		uint8_t d[HW_BLAKE2B_MAX];
		char got[2 * HW_BLAKE2B_MAX + 1];
		hw_blake2b(buf, len, d, v[i].outlen);
		hex(d, v[i].outlen, got);
		CHECK_STR(got, v[i].want);
	}
}

static void test_site_key_vectors(void) {
	for (size_t i = 0; i < COUNT(WARP_SITE_VECTORS); i++) {
		char key[256];
		CHECK_EQ(hw_warp_site_key(WARP_SITE_VECTORS[i].host, key, sizeof(key)), 0);
		CHECK(strcmp(key, WARP_SITE_VECTORS[i].key) == 0, "site of \"%s\": \"%s\", the router says \"%s\"",
		      WARP_SITE_VECTORS[i].host, key, WARP_SITE_VECTORS[i].key);
	}
	char small[10];
	CHECK_EQ(hw_warp_site_key("www.example.com", small, sizeof(small)), -1);
	CHECK_STR(small, "");
	CHECK_EQ(hw_warp_site_key("a.b.example", small, sizeof(small)), 0); // "b.example" and its NUL, exactly
	CHECK_STR(small, "b.example");
}

static void test_score_vectors(void) {
	for (size_t i = 0; i < COUNT(WARP_SCORE_VECTORS); i++) {
		uint64_t got = hw_warp_score(WARP_SCORE_VECTORS[i].key, WARP_SCORE_VECTORS[i].name);
		CHECK(got == WARP_SCORE_VECTORS[i].score, "score of \"%s\" for %s: %016llx, the router says %016llx",
		      WARP_SCORE_VECTORS[i].key, WARP_SCORE_VECTORS[i].name, (unsigned long long)got,
		      (unsigned long long)WARP_SCORE_VECTORS[i].score);
	}
}

static void fill(hw_warp_tunnel *list, int *n, const char *const *names) {
	*n = 0;
	for (; names[*n]; (*n)++) {
		snprintf(list[*n].name, sizeof(list[*n].name), "%s", names[*n]);
		list[*n].mark = 0x7701 + (uint32_t)*n;
	}
}

static void test_pick_vectors(void) {
	for (size_t i = 0; i < COUNT(WARP_PICK_VECTORS); i++) {
		hw_warp_state st;
		memset(&st, 0, sizeof(st));
		fill(st.v4, &st.n4, WARP_TUNNEL_SETS[WARP_PICK_VECTORS[i].set]);
		const hw_warp_tunnel *t = hw_warp_pick(&st, 0, WARP_PICK_VECTORS[i].key);
		CHECK(t && strcmp(t->name, WARP_PICK_VECTORS[i].name) == 0, "set %d key \"%s\": %s, the router says %s",
		      WARP_PICK_VECTORS[i].set, WARP_PICK_VECTORS[i].key, t ? t->name : "none", WARP_PICK_VECTORS[i].name);
		// The same tunnels healthy for IPv6 only: IPv4 has none, and IPv6 picks the same one.
		memcpy(st.v6, st.v4, sizeof(st.v4));
		st.n6 = st.n4;
		st.n4 = 0;
		CHECK(hw_warp_pick(&st, 0, WARP_PICK_VECTORS[i].key) == NULL, "no IPv4 tunnel, yet one was picked");
		t = hw_warp_pick(&st, 1, WARP_PICK_VECTORS[i].key);
		CHECK(t && strcmp(t->name, WARP_PICK_VECTORS[i].name) == 0, "IPv6 picked another tunnel");
	}
}

static void test_state_parse(void) {
	hw_warp_state st;
	char err[128];
	const char *full = "{\"v4\": [{\"name\": \"warp0\", \"mark\": 30465}, {\"mark\": 30466, \"name\": \"warp1\"}],\n"
	                   " \"v6\": [{\"name\": \"warp1\", \"mark\": 30466, \"up_since\": 1731369600.5}],\n"
	                   " \"updated\": \"2026-11-13T00:19:41Z\", \"extra\": {\"a\": [1, true, null, \"x\\\"y\"]}}";
	CHECK_EQ(hw_warp_state_parse(full, strlen(full), &st, err, sizeof(err)), 0);
	CHECK_EQ(st.n4, 2);
	CHECK_EQ(st.n6, 1);
	CHECK_STR(st.v4[0].name, "warp0");
	CHECK_EQ(st.v4[0].mark, 30465);
	CHECK_STR(st.v4[1].name, "warp1");
	CHECK_EQ(st.v4[1].mark, 30466);
	CHECK_STR(st.v6[0].name, "warp1");

	// No family at all, or an empty one: no healthy tunnel there, and that is not an error.
	const char *empty[] = {"{}", " {\"v4\": []} ", "{\"v6\": [], \"v4\": []}"};
	for (size_t i = 0; i < COUNT(empty); i++) {
		CHECK_EQ(hw_warp_state_parse(empty[i], strlen(empty[i]), &st, err, sizeof(err)), 0);
		CHECK_EQ(st.n4 + st.n6, 0);
	}

	// Everything else that is not exactly the shape is refused whole, never half read.
	const char *bad[] = {
	    "",
	    "[]",
	    "{",
	    "{\"v4\": [{\"name\": \"warp0\", \"mark\": 30465}]",                                    // unterminated
	    "{\"v4\": [{\"name\": \"warp0\", \"mark\": 30465}]} x",                                 // trailing bytes
	    "{\"v4\": {\"name\": \"warp0\", \"mark\": 30465}}",                                     // not a list
	    "{\"v4\": [{\"name\": \"warp0\"}]}",                                                    // no mark
	    "{\"v4\": [{\"mark\": 30465}]}",                                                        // no name
	    "{\"v4\": [{\"name\": \"warp0\", \"mark\": 0}]}",                                       // mark 0
	    "{\"v4\": [{\"name\": \"warp0\", \"mark\": 4294967296}]}",                              // over 32 bits
	    "{\"v4\": [{\"name\": \"warp0\", \"mark\": -1}]}",                                      // negative
	    "{\"v4\": [{\"name\": \"warp0\", \"mark\": 1.5}]}",                                     // fraction
	    "{\"v4\": [{\"name\": \"warp0\", \"mark\": 3e4}]}",                                     // exponent
	    "{\"v4\": [{\"name\": \"warp0\", \"mark\": \"30465\"}]}",                               // a string
	    "{\"v4\": [{\"name\": \"\", \"mark\": 1}]}",                                            // empty name
	    "{\"v4\": [{\"name\": \"warp0123456789ab\", \"mark\": 1}]}",                            // 16 characters
	    "{\"v4\": [{\"name\": \"wa rp\", \"mark\": 1}]}",                                       // a space
	    "{\"v4\": [{\"name\": \"warp\\u0030\", \"mark\": 1}]}",                                 // an escape
	    "{\"v4\": [{\"name\": \"a\", \"mark\": 1}, {\"name\": \"a\", \"mark\": 2}]}",           // name twice
	    "{\"v4\": [{\"name\": \"a\", \"mark\": 1}, {\"name\": \"b\", \"mark\": 1}]}",           // mark twice
	    "{\"v4\": [{\"name\": \"a\", \"mark\": 1},]}",                                          // trailing comma
	    "{\"x\": [[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[1]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]}", // too deep
	};
	for (size_t i = 0; i < COUNT(bad); i++) {
		st.n4 = 7;
		CHECK(hw_warp_state_parse(bad[i], strlen(bad[i]), &st, err, sizeof(err)) == -1, "accepted: %s", bad[i]);
		CHECK(st.n4 == 0 && st.n6 == 0, "a refused file left tunnels behind: %s", bad[i]);
		CHECK(err[0] != '\0', "no reason for: %s", bad[i]);
	}

	// Seventeen tunnels in one family is more than the configuration can name.
	char many[2048];
	size_t n = (size_t)snprintf(many, sizeof(many), "{\"v4\": [");
	for (int i = 0; i < HW_WARP_MAX_TUNNELS + 1; i++) {
		n += (size_t)snprintf(many + n, sizeof(many) - n, "%s{\"name\": \"w%d\", \"mark\": %d}", i ? ", " : "", i,
		                      i + 1);
	}
	n += (size_t)snprintf(many + n, sizeof(many) - n, "]}");
	CHECK_EQ(hw_warp_state_parse(many, n, &st, err, sizeof(err)), -1);
}

static void test_state_restrict(void) {
	hw_warp_state st;
	char err[64];
	const char *json = "{\"v4\": [{\"name\": \"warp0\", \"mark\": 30465}, {\"name\": \"rogue\", \"mark\": 1},"
	                   " {\"name\": \"warp2\", \"mark\": 30467}], \"v6\": [{\"name\": \"rogue\", \"mark\": 1}]}";
	CHECK_EQ(hw_warp_state_parse(json, strlen(json), &st, err, sizeof(err)), 0);
	uint32_t marks[] = {0x7701, 0x7702, 0x7703, 0x7704};
	CHECK_EQ(hw_warp_state_restrict(&st, marks, 4), 2);
	CHECK_EQ(st.n4, 2);
	CHECK_STR(st.v4[0].name, "warp0");
	CHECK_STR(st.v4[1].name, "warp2");
	CHECK_EQ(st.n6, 0);
}

static void test_marks_parse(void) {
	uint32_t m[HW_WARP_MAX_TUNNELS];
	CHECK_EQ(hw_warp_marks_parse("0x7701,0x7702,0x7703,0x7704", m, HW_WARP_MAX_TUNNELS), 4);
	CHECK_EQ(m[0], 0x7701);
	CHECK_EQ(m[3], 0x7704);
	CHECK_EQ(hw_warp_marks_parse(" 30465 , 0xFFFFFFFF", m, HW_WARP_MAX_TUNNELS), 2);
	CHECK_EQ(m[0], 30465);
	CHECK_EQ(m[1], 0xFFFFFFFFu);
	const char *bad[] = {"",      ",",   "0x7701,", ",0x7701", "0", "0x100000000", "-1", "0x7701,0x7701",
	                     "warp0", "1 2", "0x"};
	for (size_t i = 0; i < COUNT(bad); i++) {
		CHECK(hw_warp_marks_parse(bad[i], m, HW_WARP_MAX_TUNNELS) == -1, "accepted marks \"%s\"", bad[i]);
	}
	CHECK_EQ(hw_warp_marks_parse("1,2,3", m, 2), -1);
}

// hw_warp_client_key against Python's hashlib.blake2b(secret + b"\0" + bytes, digest_size=8).
static void test_client_key(void) {
	const uint8_t *sec = (const uint8_t *)"holywisp-test-secret";
	size_t sl = strlen((const char *)sec);
	char k[HW_WARP_CLIENT_KEY_LEN + 1];
	CHECK_EQ(hw_warp_client_key(sec, sl, "203.0.113.7", k), 0);
	CHECK_STR(k, "3ca6515e64f358b3");
	CHECK_EQ(hw_warp_client_key(sec, sl, "::ffff:203.0.113.7", k), 0); // mapped is the IPv4 it wraps
	CHECK_STR(k, "3ca6515e64f358b3");
	CHECK_EQ(hw_warp_client_key(sec, sl, "2001:db8:1:2::1", k), 0);
	CHECK_STR(k, "5ced8b8e9d0c7f9a");
	CHECK_EQ(hw_warp_client_key(sec, sl, "2001:db8:1:2:aaaa::9", k), 0); // the same /64
	CHECK_STR(k, "5ced8b8e9d0c7f9a");
	CHECK_EQ(hw_warp_client_key(sec, sl, "2001:db8:1:3::1", k), 0); // the next one
	CHECK_STR(k, "acf973f3b2861e7e");
	const uint8_t *other = (const uint8_t *)"another-secret-here";
	CHECK_EQ(hw_warp_client_key(other, strlen((const char *)other), "203.0.113.7", k), 0);
	CHECK_STR(k, "bc722f6082eba200");
	const char *bad[] = {"", "localhost", "203.0.113", "unix", "1.2.3.4:80"};
	for (size_t i = 0; i < COUNT(bad); i++) {
		CHECK(hw_warp_client_key(sec, sl, bad[i], k) == -1, "a key for \"%s\"", bad[i]);
		CHECK_STR(k, "");
	}
	CHECK(hw_warp_client_key(sec, sl, NULL, k) == -1, "a key for NULL");
}

static void test_stream_key(void) {
	char k[40];
	CHECK_EQ(hw_warp_stream_key("", "example.com", k, sizeof(k)), 0);
	CHECK_STR(k, "example.com");
	CHECK_EQ(hw_warp_stream_key(NULL, "1.1.1.1", k, sizeof(k)), 0);
	CHECK_STR(k, "1.1.1.1");
	CHECK_EQ(hw_warp_stream_key("3ca6515e64f358b3", "example.com", k, sizeof(k)), 0);
	CHECK_STR(k, "3ca6515e64f358b3/example.com");
	CHECK_EQ(hw_warp_stream_key("3ca6515e64f358b3", "a-site-that-is-too-long.com", k, sizeof(k)), -1);
	CHECK_STR(k, "");
	// The client's key moves the pick off the site's own: over many clients a site spreads over
	// every tunnel, and one client keeps one tunnel per site.
	hw_warp_state st;
	memset(&st, 0, sizeof(st));
	const char *names[] = {"warp0", "warp1", "warp2", "warp3"};
	for (int i = 0; i < 4; i++) {
		snprintf(st.v4[i].name, sizeof(st.v4[i].name), "%s", names[i]);
		st.v4[i].mark = 0x7701u + (uint32_t)i;
	}
	st.n4 = 4;
	int seen[4] = {0};
	for (int c = 0; c < 64; c++) {
		char ip[32], ck[HW_WARP_CLIENT_KEY_LEN + 1];
		snprintf(ip, sizeof(ip), "198.51.100.%d", c);
		CHECK_EQ(hw_warp_client_key((const uint8_t *)"s", 1, ip, ck), 0);
		CHECK_EQ(hw_warp_stream_key(ck, "googlevideo.com", k, sizeof(k)), 0);
		const hw_warp_tunnel *t = hw_warp_pick(&st, 0, k);
		CHECK(t != NULL, "a tunnel");
		seen[t->mark - 0x7701]++;
		CHECK(t == hw_warp_pick(&st, 0, k), "the same tunnel again");
	}
	for (int i = 0; i < 4; i++) CHECK(seen[i] > 0, "%s never picked over 64 clients", names[i]);
}

int main(void) {
	RUN(test_blake2b);
	RUN(test_site_key_vectors);
	RUN(test_score_vectors);
	RUN(test_pick_vectors);
	RUN(test_state_parse);
	RUN(test_state_restrict);
	RUN(test_marks_parse);
	RUN(test_client_key);
	RUN(test_stream_key);
	return 0;
}
