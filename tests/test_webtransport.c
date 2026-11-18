/*
 * tests/test_webtransport.c - HTTP/3, QPACK, WebTransport draft-02 and the Wisp framing
 * (holywisp/webtransport.h, src/quic/h3.h).
 *
 * The first half tests the stateless pieces with vectors (RFC 7541 appendix C, a request block
 * built field by field as Chrome encodes it, checked once against quic-go's QPACK decoder). The
 * second half runs hw_wt against a QUIC stand-in: the hw_quic_* calls hw_wt makes are defined
 * here (streams with credit that only hw_quic_stream_consumed grants, STOP_SENDING answered by
 * RESET_STREAM unless a test says otherwise, datagrams, close) as two in-memory endpoints joined
 * by one event queue, so a client and a server hw_wt, or raw bytes as Chrome sends them, run
 * against each other deterministically. Because they are defined here, the linker never takes
 * libhw_quic's quic.c; it takes only quic_wire.c, for the varints, which defines none of them.
 * The session on real QUIC connections is test_wt_quic's.
 *
 * The last part attacks hw_wt as a hostile client would: unknown and WebTransport streams that
 * are never finished, endless GREASE frames and capsules, a Wisp length that is then trickled,
 * datagrams for sessions that do not exist; each is bounded and refused with its error.
 */
#include "holywisp/buf.h"
#include "holywisp/hw.h"
#include "holywisp/webtransport.h"
#include "holywisp/wisp.h"

#include "quic/h3.h"
#include "quic/quic_wire.h"
#include "test.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static size_t unhex(const char *h, uint8_t *out, size_t cap) {
	size_t n = 0;
	int hi = -1;
	for (; *h; h++) {
		int v;
		if (*h >= '0' && *h <= '9') {
			v = *h - '0';
		} else if (*h >= 'a' && *h <= 'f') {
			v = *h - 'a' + 10;
		} else {
			continue; // spaces between bytes
		}
		if (hi < 0) {
			hi = v;
		} else {
			CHECK(n < cap, "hex too long");
			out[n++] = (uint8_t)(hi << 4 | v);
			hi = -1;
		}
	}
	CHECK(hi < 0, "odd hex");
	return n;
}

// A field section as Chrome 152 to 157 encode it (static table, literals, Huffman when shorter):
// :scheme https, :method CONNECT, :authority wisp.example.com:4433, :path /wisp/?v=2,
// :protocol webtransport, sec-webtransport-http3-draft02: 1, origin https://app.example.com,
// wt-available-protocols "wisp-v2", "wisp-v1".
static const char CHROME_BLOCK[] = "0000 d7 cf"
                                   "50 90 f06456b97c8e9ae82ae43d371a69967f"
                                   "51 88 63c1915b1fe77805"
                                   "2f00 b95d8749c87a3f 89 f058d360ea4567b13f"
                                   "2f0e 4148b782c69b07522b3d895a74a6b65692c1ca900b 01 31"
                                   "5f4b 91 9d29ad17186075d6b97c8e9ae82ae43d3f"
                                   "2f09 f09587dc66a071d055abb0e9390f423f 91 fe7c1915addc5fcfd29fcf8322b5bb87f9";

// Chrome's SETTINGS on its control stream (type 00): QPACK_MAX_TABLE_CAPACITY 65536,
// MAX_FIELD_SECTION_SIZE 16384, QPACK_BLOCKED_STREAMS 100, H3_DATAGRAM 1, the draft-04 one 1,
// ENABLE_WEBTRANSPORT 1, a GREASE setting; then a GREASE frame of two bytes.
static const char CHROME_SETTINGS[] = "00 04 1f 0180010000 0680004000 074064 3301 80ffd27701 ab60374201 40fa 92345678"
                                      "407e 02 abcd";

// ---- Huffman ----------------------------------------------------------------------------------

static void test_huffman_vectors(void) {
	// RFC 7541 C.4.1 to C.4.3 and C.6.1.
	static const char *const vec[][2] = {
	    {"www.example.com", "f1e3c2e5f23a6ba0ab90f4ff"},
	    {"no-cache", "a8eb10649cbf"},
	    {"custom-key", "25a849e95ba97d7f"},
	    {"custom-value", "25a849e95bb8e8b4bf"},
	    {"302", "6402"},
	    {"private", "aec3771a4b"},
	    {"Mon, 21 Oct 2013 20:13:21 GMT", "d07abe941054d444a8200595040b8166e082a62d1bff"},
	    {"https://www.example.com", "9d29ad171863c78f0b97c8e9ae82ae43d3"},
	};
	for (size_t i = 0; i < HW_ARRAY_LEN(vec); i++) {
		const uint8_t *s = (const uint8_t *)vec[i][0];
		size_t sl = strlen(vec[i][0]);
		uint8_t want[64], got[64], dec[64];
		size_t wl = unhex(vec[i][1], want, sizeof(want));
		CHECK_EQ(hw_huffman_len(s, sl), wl);
		CHECK_EQ(hw_huffman_encode(s, sl, got, sizeof(got)), wl);
		CHECK(memcmp(got, want, wl) == 0, "%s encodes", vec[i][0]);
		CHECK_EQ(hw_huffman_decode(want, wl, dec, sizeof(dec)), (long long)sl);
		CHECK(memcmp(dec, s, sl) == 0, "%s decodes", vec[i][0]);
		CHECK_EQ(hw_huffman_decode(want, wl, dec, sl - 1), -2);
		CHECK_EQ(hw_huffman_encode(s, sl, got, wl - 1), 0);
	}
	uint8_t dec[16];
	uint8_t b[8];
	// Eight bits of padding, padding that is not all ones, and EOS itself.
	CHECK_EQ(hw_huffman_decode(b, unhex("ff", b, sizeof(b)), dec, sizeof(dec)), -1);
	CHECK_EQ(hw_huffman_decode(b, unhex("0f", b, sizeof(b)), dec, sizeof(dec)), 1); // "1"
	CHECK_EQ(dec[0], '1');
	CHECK_EQ(hw_huffman_decode(b, unhex("0e", b, sizeof(b)), dec, sizeof(dec)), -1);
	CHECK_EQ(hw_huffman_decode(b, unhex("ffffffff", b, sizeof(b)), dec, sizeof(dec)), -1);
	CHECK_EQ(hw_huffman_decode(b, unhex("0fffffffff", b, sizeof(b)), dec, sizeof(dec)), -1);
	CHECK_EQ(hw_huffman_decode(b, 0, dec, sizeof(dec)), 0);
}

static void test_huffman_roundtrip(void) {
	uint8_t all[256], enc[1024], dec[256];
	for (int i = 0; i < 256; i++) all[i] = (uint8_t)i;
	size_t el = hw_huffman_encode(all, sizeof(all), enc, sizeof(enc));
	CHECK(el > 0, "every octet encodes");
	CHECK_EQ(hw_huffman_decode(enc, el, dec, sizeof(dec)), 256);
	CHECK(memcmp(all, dec, 256) == 0, "every octet round-trips");
	uint32_t seed = 12345;
	for (int round = 0; round < 2000; round++) {
		uint8_t s[64];
		size_t n = (size_t)(round % 64);
		for (size_t i = 0; i < n; i++) {
			seed = seed * 1103515245u + 12345u;
			s[i] = (uint8_t)(round & 1 ? seed >> 24 : 0x20 + (seed >> 24) % 95);
		}
		el = hw_huffman_encode(s, n, enc, sizeof(enc));
		CHECK_EQ(el, hw_huffman_len(s, n));
		CHECK_EQ(hw_huffman_decode(enc, el, dec, sizeof(dec)), (long long)n);
		CHECK(n == 0 || memcmp(s, dec, n) == 0, "round %d", round);
	}
}

// ---- QPACK ------------------------------------------------------------------------------------

static void test_qpack_static(void) {
	CHECK_STR(hw_qpack_static_name(0), ":authority");
	CHECK_STR(hw_qpack_static_value(1), "/");
	CHECK_STR(hw_qpack_static_value(15), "CONNECT");
	CHECK_STR(hw_qpack_static_value(23), "https");
	CHECK_STR(hw_qpack_static_value(25), "200");
	CHECK_STR(hw_qpack_static_value(27), "404");
	CHECK_STR(hw_qpack_static_name(31), "accept-encoding");
	CHECK_STR(hw_qpack_static_value(68), "403");
	CHECK_STR(hw_qpack_static_name(90), "origin");
	CHECK_STR(hw_qpack_static_name(95), "user-agent");
	CHECK_STR(hw_qpack_static_value(98), "sameorigin");
	CHECK(hw_qpack_static_name(99) == NULL, "past the end");
}

typedef struct {
	char arena[HW_H3_FIELD_SECTION_MAX];
	hw_qpack_field f[64];
} decoded;

static int decode_hex(const char *hex, decoded *d) {
	uint8_t b[2048];
	size_t n = unhex(hex, b, sizeof(b));
	return hw_qpack_decode(b, n, d->arena, sizeof(d->arena), d->f, HW_ARRAY_LEN(d->f));
}

static void test_qpack_chrome_request(void) {
	static const char *const want[][2] = {
	    {":scheme", "https"},
	    {":method", "CONNECT"},
	    {":authority", "wisp.example.com:4433"},
	    {":path", "/wisp/?v=2"},
	    {":protocol", "webtransport"},
	    {"sec-webtransport-http3-draft02", "1"},
	    {"origin", "https://app.example.com"},
	    {"wt-available-protocols", "\"wisp-v2\", \"wisp-v1\""},
	};
	static decoded d;
	int n = decode_hex(CHROME_BLOCK, &d);
	CHECK_EQ(n, HW_ARRAY_LEN(want));
	for (int i = 0; i < n; i++) {
		CHECK_STR(d.f[i].name, want[i][0]);
		CHECK_STR(d.f[i].value, want[i][1]);
		CHECK_EQ(d.f[i].name_len, strlen(want[i][0]));
		CHECK_EQ(d.f[i].value_len, strlen(want[i][1]));
	}
	char join[256];
	hw_h3_request r;
	CHECK_EQ(hw_h3_request_parse(d.f, (size_t)n, join, sizeof(join), &r), 0);
	CHECK_STR(r.method, "CONNECT");
	CHECK_STR(r.scheme, "https");
	CHECK_STR(r.authority, "wisp.example.com:4433");
	CHECK_STR(r.path, "/wisp/?v=2");
	CHECK_STR(r.protocol, "webtransport");
	CHECK_STR(r.origin, "https://app.example.com");
	CHECK_STR(r.protocols, "\"wisp-v2\", \"wisp-v1\"");
	CHECK_STR(r.draft02, "1");
	// The encoder makes Chrome's choices, so it makes Chrome's bytes.
	uint8_t want_b[512], got[512];
	size_t wl = unhex(CHROME_BLOCK, want_b, sizeof(want_b));
	size_t gl = hw_qpack_prefix_put(got, sizeof(got));
	for (size_t i = 0; i < HW_ARRAY_LEN(want); i++) {
		gl += hw_qpack_field_put(got + gl, sizeof(got) - gl, want[i][0], strlen(want[i][0]), want[i][1],
		                         strlen(want[i][1]));
	}
	CHECK_EQ(gl, wl);
	CHECK(memcmp(got, want_b, wl) == 0, "encoder matches Chrome");
}

static void test_qpack_refusals(void) {
	static decoded d;
	static const char *const invalid[] = {
	    "0100",                 // Required Insert Count 1: the dynamic table
	    "0000 80",              // indexed, dynamic
	    "0000 ff24",            // static index 99
	    "0000 10",              // indexed with post-base index
	    "0000 00",              // literal with post-base name reference
	    "0000 4000",            // literal with dynamic name reference
	    "0000 5105 2f",         // value longer than the block
	    "0000 2305 61",         // literal name longer than the block
	    "0000 510100",          // a NUL in a value
	    "0000 21 00 00",        // a NUL in a name
	    "0000 ffffffffffff01",  // an index integer that never ends in range
	    "0000 51 81 0e",        // Huffman padding that is not EOS
	    "0000 51 84 ffffffff",  // EOS in a Huffman string
	    "00",                   // no Delta Base
	    "",                     // nothing at all
	    "0000 51 ff ffffffff7f" // a string length past the cap
	};
	for (size_t i = 0; i < HW_ARRAY_LEN(invalid); i++) {
		CHECK(decode_hex(invalid[i], &d) == HW_ERR_INVALID, "case %zu", i);
	}
	CHECK_EQ(decode_hex("0000", &d), 0); // an empty section is valid
	CHECK_EQ(decode_hex("0080", &d), 0); // Delta Base with the sign bit: ignored without a dynamic table
	char hex[600] = "0000";
	for (int i = 0; i < 65; i++) snprintf(hex + 4 + 2 * i, sizeof(hex) - 4 - 2 * i, "c1");
	CHECK_EQ(decode_hex(hex, &d), HW_ERR_TOOBIG);
	uint8_t b[512];
	size_t n = unhex(CHROME_BLOCK, b, sizeof(b));
	CHECK_EQ(hw_qpack_decode(b, n, d.arena, 32, d.f, 64), HW_ERR_TOOBIG);
	CHECK_EQ(hw_qpack_decode(b, n, d.arena, sizeof(d.arena), d.f, 3), HW_ERR_TOOBIG);
}

// Every truncation and many corruptions of a block: an answer, never a crash (ASan watches).
static void test_qpack_hostile(void) {
	uint8_t b[512];
	size_t n = unhex(CHROME_BLOCK, b, sizeof(b));
	static decoded d;
	for (size_t len = 0; len < n; len++) {
		uint8_t *copy = malloc(len ? len : 1); // exact size, so a read past it is caught
		memcpy(copy, b, len);
		int r = hw_qpack_decode(copy, len, d.arena, sizeof(d.arena), d.f, 64);
		CHECK(r < 8, "a truncated block at %zu decoded whole", len);
		free(copy);
	}
	for (size_t i = 0; i < n; i++) {
		for (int bit = 0; bit < 8; bit++) {
			uint8_t *copy = malloc(n);
			memcpy(copy, b, n);
			copy[i] ^= (uint8_t)(1u << bit);
			(void)hw_qpack_decode(copy, n, d.arena, sizeof(d.arena), d.f, 64);
			free(copy);
		}
	}
	uint32_t seed = 99;
	for (int round = 0; round < 20000; round++) {
		size_t len = (size_t)(round % 40);
		uint8_t *g = malloc(len ? len : 1);
		for (size_t i = 0; i < len; i++) {
			seed = seed * 1664525u + 1013904223u;
			g[i] = (uint8_t)(seed >> 24);
		}
		if (len >= 2 && round % 3) g[0] = g[1] = 0;
		int r = hw_qpack_decode(g, len, d.arena, sizeof(d.arena), d.f, 64);
		for (int i = 0; i < r; i++) CHECK(strlen(d.f[i].name) == d.f[i].name_len, "lengths agree");
		free(g);
	}
	CHECK(1, "survived");
}

static void test_qpack_encode(void) {
	static const struct {
		const char *name, *value, *hex;
	} vec[] = {
	    {":status", "200", "d9"},   {":status", "404", "db"},
	    {":status", "403", "ff05"}, {":status", "429", "5f09 03 343239"},
	    {"origin", "", "ff1b"},     {"wt-protocol", "\"wisp-v2\"", "2f01 f095abb0e9390f47 88 fe7c1915addc5fcf"},
	    {"x", "", "2178 00"},
	};
	for (size_t i = 0; i < HW_ARRAY_LEN(vec); i++) {
		uint8_t want[64], got[64];
		size_t wl = unhex(vec[i].hex, want, sizeof(want));
		size_t gl = hw_qpack_field_put(got, sizeof(got), vec[i].name, strlen(vec[i].name), vec[i].value,
		                               strlen(vec[i].value));
		CHECK_EQ(gl, wl);
		CHECK(memcmp(got, want, wl) == 0, "%s: %s", vec[i].name, vec[i].value);
		CHECK_EQ(hw_qpack_field_put(got, wl - 1, vec[i].name, strlen(vec[i].name), vec[i].value, strlen(vec[i].value)),
		         0);
		// And back.
		uint8_t block[80] = {0, 0};
		memcpy(block + 2, want, wl);
		static decoded d;
		CHECK_EQ(hw_qpack_decode(block, wl + 2, d.arena, sizeof(d.arena), d.f, 64), 1);
		CHECK_STR(d.f[0].name, vec[i].name);
		CHECK_STR(d.f[0].value, vec[i].value);
	}
	// A long value takes continuation bytes in its length.
	char big[300];
	memset(big, 'z', sizeof(big) - 1);
	big[sizeof(big) - 1] = '\0';
	uint8_t block[400] = {0, 0};
	size_t n = 2 + hw_qpack_field_put(block + 2, sizeof(block) - 2, "x-long", 6, big, strlen(big));
	static decoded d;
	CHECK_EQ(hw_qpack_decode(block, n, d.arena, sizeof(d.arena), d.f, 64), 1);
	CHECK_STR(d.f[0].value, big);
}

// ---- Frames, settings, prefixes, capsules -----------------------------------------------------

static void test_settings(void) {
	uint8_t f[128];
	size_t n = hw_h3_settings_frame(f, sizeof(f), 0);
	uint8_t want[64];
	size_t wl = unhex("04 20 0100 0680004000 0700 0801 3301 80ffd27701 ab60374201 c0000000c671706a01", want,
	                  sizeof(want));
	CHECK_EQ(n, wl);
	CHECK(memcmp(f, want, wl) == 0, "server SETTINGS bytes");
	CHECK_EQ(hw_h3_settings_frame(f, wl - 1, 0), 0);
	hw_h3_settings s;
	CHECK_EQ(hw_h3_settings_parse(f + 2, n - 2, &s), 0);
	CHECK_EQ(s.qpack_max_table_capacity, 0);
	CHECK_EQ(s.max_field_section_size, HW_H3_FIELD_SECTION_MAX);
	CHECK_EQ(s.enable_connect_protocol, 1);
	CHECK_EQ(s.h3_datagram, 1);
	CHECK_EQ(s.enable_webtransport, 1);
	CHECK_EQ(s.wt_max_sessions, 1);
	// Ours as a client, and then Chrome's: both have what a WebTransport server looks for.
	n = hw_h3_settings_frame(f, sizeof(f), 1);
	uint64_t type, len;
	size_t a = hw_qw_varint_get(f, n, &type);
	size_t b = hw_qw_varint_get(f + a, n - a, &len);
	CHECK_EQ(type, HW_H3_FRAME_SETTINGS);
	CHECK_EQ(hw_h3_settings_parse(f + a + b, (size_t)len, &s), 0);
	CHECK(s.h3_datagram && s.enable_webtransport && !s.enable_connect_protocol, "client settings");
	uint64_t grease;
	CHECK(hw_qw_varint_get(f + a + b + len, n - a - b - len, &grease) > 0 && hw_h3_is_grease(grease), "GREASE frame");
	uint8_t c[64];
	size_t cl = unhex(CHROME_SETTINGS, c, sizeof(c));
	CHECK(cl > 3, "Chrome settings");
	CHECK_EQ(hw_h3_settings_parse(c + 3, c[2], &s), 0);
	CHECK_EQ(s.qpack_max_table_capacity, 65536);
	CHECK_EQ(s.qpack_blocked_streams, 100);
	CHECK_EQ(s.max_field_section_size, 16384);
	CHECK(s.h3_datagram && s.enable_webtransport, "Chrome's settings");
	// Absent: unlimited. Refusals.
	CHECK_EQ(hw_h3_settings_parse(c, 0, &s), 0);
	CHECK(s.max_field_section_size == UINT64_MAX, "absent field section size");
	static const struct {
		const char *hex;
		uint64_t err;
	} bad[] = {
	    {"0200", HW_H3_SETTINGS_ERROR},      // HTTP/2's ENABLE_PUSH
	    {"0300", HW_H3_SETTINGS_ERROR},      // MAX_CONCURRENT_STREAMS
	    {"0400", HW_H3_SETTINGS_ERROR},      // INITIAL_WINDOW_SIZE
	    {"0500", HW_H3_SETTINGS_ERROR},      // MAX_FRAME_SIZE
	    {"0100 0100", HW_H3_SETTINGS_ERROR}, // twice
	    {"3302", HW_H3_SETTINGS_ERROR},      // H3_DATAGRAM is 0 or 1
	    {"0802", HW_H3_SETTINGS_ERROR},      // so is ENABLE_CONNECT_PROTOCOL
	    {"01", HW_H3_FRAME_ERROR},           // truncated
	    {"0140", HW_H3_FRAME_ERROR},
	};
	for (size_t i = 0; i < HW_ARRAY_LEN(bad); i++) {
		uint8_t p[16];
		size_t pl = unhex(bad[i].hex, p, sizeof(p));
		CHECK(hw_h3_settings_parse(p, pl, &s) == bad[i].err, "case %zu", i);
	}
	uint8_t g[16];
	size_t gl = unhex("40fa 01 3300 40fa 02", g, sizeof(g)); // GREASE, even twice, is ignored
	CHECK_EQ(hw_h3_settings_parse(g, gl, &s), 0);
	CHECK_EQ(s.h3_datagram, 0);
	CHECK(hw_h3_is_grease(0x21) && hw_h3_is_grease(0x40) && !hw_h3_is_grease(0x41), "GREASE ids");
}

// A run of frames read back with every split of the input, and byte by byte.
typedef struct {
	uint64_t type[8];
	uint8_t body[8][400];
	size_t len[8];
	size_t n;
} frames_seen;

static void frames_feed(hw_h3_tlv *r, frames_seen *fs, const uint8_t *p, size_t len) {
	for (;;) {
		hw_h3_tlv_ev ev;
		size_t used = hw_h3_tlv_step(r, p, len, &ev);
		p += used;
		len -= used;
		if (ev.kind == HW_H3_TLV_NEED) break;
		if (ev.kind == HW_H3_TLV_START) {
			CHECK(fs->n < 8, "too many frames");
			fs->type[fs->n] = ev.type;
			fs->len[fs->n] = 0;
			fs->n++;
			continue;
		}
		CHECK(fs->len[fs->n - 1] + ev.n <= 400, "body too long");
		if (ev.n) memcpy(fs->body[fs->n - 1] + fs->len[fs->n - 1], ev.data, ev.n);
		fs->len[fs->n - 1] += ev.n;
	}
	CHECK_EQ(len, 0);
}

static void test_tlv_splits(void) {
	uint8_t s[512];
	size_t n = 0;
	n += hw_h3_frame_header_put(s + n, sizeof(s) - n, HW_H3_FRAME_HEADERS, 3);
	for (const char *c = "abc"; *c; c++) s[n++] = (uint8_t)*c;
	n += hw_h3_frame_header_put(s + n, sizeof(s) - n, HW_H3_FRAME_DATA, 0);
	n += hw_h3_frame_header_put(s + n, sizeof(s) - n, 0x1f * 1000 + 0x21, 300);
	for (int i = 0; i < 300; i++) s[n++] = (uint8_t)i;
	n += hw_h3_frame_header_put(s + n, sizeof(s) - n, HW_H3_FRAME_DATA, 5);
	for (const char *c = "hello"; *c; c++) s[n++] = (uint8_t)*c;
	for (size_t split = 0; split <= n; split++) {
		hw_h3_tlv r;
		hw_h3_tlv_init(&r);
		static frames_seen fs;
		memset(&fs, 0, sizeof(fs));
		frames_feed(&r, &fs, s, split);
		frames_feed(&r, &fs, s + split, n - split);
		CHECK_EQ(fs.n, 4);
		CHECK(!hw_h3_tlv_mid(&r), "ends between frames");
		CHECK_EQ(fs.type[0], HW_H3_FRAME_HEADERS);
		CHECK(fs.len[0] == 3 && memcmp(fs.body[0], "abc", 3) == 0, "split %zu", split);
		CHECK_EQ(fs.len[1], 0);
		CHECK_EQ(fs.type[2], 0x1f * 1000 + 0x21);
		CHECK_EQ(fs.len[2], 300);
		CHECK_EQ(fs.body[2][299], (uint8_t)299);
		CHECK(fs.len[3] == 5 && memcmp(fs.body[3], "hello", 5) == 0, "split %zu", split);
	}
	hw_h3_tlv r;
	hw_h3_tlv_init(&r);
	static frames_seen fs;
	memset(&fs, 0, sizeof(fs));
	int mids = 0;
	for (size_t i = 0; i < n; i++) {
		frames_feed(&r, &fs, s + i, 1);
		mids += hw_h3_tlv_mid(&r);
	}
	CHECK_EQ(mids, (int)n - 4); // false only at the four frame ends
	CHECK(!hw_h3_tlv_mid(&r), "ends between frames");
	CHECK_EQ(fs.n, 4);
	CHECK_EQ(fs.len[2], 300);
}

static void test_stream_kind(void) {
	static const struct {
		const char *hex;
		int bidi, done, kind;
		uint64_t session;
		size_t prefix;
	} vec[] = {
	    {"00 04", 0, 1, HW_H3_SK_CONTROL, 0, 1},
	    {"01", 0, 1, HW_H3_SK_PUSH, 0, 1},
	    {"02", 0, 1, HW_H3_SK_QPACK_ENC, 0, 1},
	    {"03", 0, 1, HW_H3_SK_QPACK_DEC, 0, 1},
	    {"4054 00 ff", 0, 1, HW_H3_SK_WT_UNI, 0, 3},
	    {"4054 4004", 0, 1, HW_H3_SK_WT_UNI, 4, 4},
	    {"4054", 0, 0, 0, 0, 0},
	    {"40", 0, 0, 0, 0, 0},
	    {"", 0, 0, 0, 0, 0},
	    {"4021", 0, 1, HW_H3_SK_UNKNOWN, 0, 2},
	    {"4041 00 aa", 1, 1, HW_H3_SK_WT_BIDI, 0, 3},
	    {"4041", 1, 0, 0, 0, 0},
	    {"01 05", 1, 1, HW_H3_SK_REQUEST, 0, 0},
	    {"41 00", 1, 1, HW_H3_SK_REQUEST, 0, 0}, // 41 00 is the varint 256, not 0x41
	    {"40", 1, 0, 0, 0, 0},
	};
	for (size_t i = 0; i < HW_ARRAY_LEN(vec); i++) {
		uint8_t b[16];
		size_t n = unhex(vec[i].hex, b, sizeof(b));
		hw_h3_stream_kind k;
		int r = hw_h3_stream_kind_parse(b, n, vec[i].bidi, &k);
		CHECK(r == vec[i].done, "case %zu", i);
		if (!r) continue;
		CHECK(k.kind == vec[i].kind, "case %zu kind %d", i, k.kind);
		CHECK(k.session == vec[i].session, "case %zu", i);
		CHECK(k.prefix == vec[i].prefix, "case %zu", i);
	}
}

static void test_capsule(void) {
	uint8_t f[HW_H3_CLOSE_REASON_MAX + 32];
	size_t n = hw_h3_close_capsule_frame(f, sizeof(f), 42, "bye");
	uint8_t want[32];
	size_t wl = unhex("00 0a 6843 07 0000002a 627965", want, sizeof(want));
	CHECK_EQ(n, wl);
	CHECK(memcmp(f, want, wl) == 0, "close capsule bytes");
	uint32_t code;
	char reason[HW_H3_CLOSE_REASON_MAX + 1];
	CHECK_EQ(hw_h3_close_capsule_parse(f + 5, 7, &code, reason, sizeof(reason)), 0);
	CHECK_EQ(code, 42);
	CHECK_STR(reason, "bye");
	CHECK_EQ(hw_h3_close_capsule_parse(f + 5, 3, &code, reason, sizeof(reason)), -1);
	char longr[2000];
	memset(longr, 'r', sizeof(longr) - 1);
	longr[sizeof(longr) - 1] = '\0';
	n = hw_h3_close_capsule_frame(f, sizeof(f), 0xffffffffu, longr);
	CHECK(n > 0, "a long reason is cut");
	hw_h3_tlv r;
	hw_h3_tlv_init(&r);
	hw_h3_tlv_ev ev;
	size_t used = hw_h3_tlv_step(&r, f, n, &ev);
	CHECK_EQ(ev.kind, HW_H3_TLV_START);
	CHECK_EQ(ev.len, n - used);
	hw_h3_tlv c;
	hw_h3_tlv_init(&c);
	size_t cu = hw_h3_tlv_step(&c, f + used, n - used, &ev);
	CHECK_EQ(ev.type, HW_H3_CAPSULE_CLOSE_SESSION);
	CHECK_EQ(ev.len, 4 + HW_H3_CLOSE_REASON_MAX);
	CHECK_EQ(hw_h3_close_capsule_parse(f + used + cu, (size_t)ev.len, &code, reason, sizeof(reason)), 0);
	CHECK_EQ(code, 0xffffffffu);
	CHECK_EQ(strlen(reason), HW_H3_CLOSE_REASON_MAX);
	uint8_t over[HW_H3_CLOSE_REASON_MAX + 5] = {0};
	CHECK_EQ(hw_h3_close_capsule_parse(over, sizeof(over), &code, reason, sizeof(reason)), -1);
	CHECK_EQ(hw_h3_close_capsule_frame(f, 8, 1, "x"), 0);
}

// ---- Requests ---------------------------------------------------------------------------------

static int request_check(const char *const (*fields)[2], size_t n, hw_h3_request *r) {
	static hw_qpack_field f[16];
	for (size_t i = 0; i < n; i++) {
		f[i].name = fields[i][0];
		f[i].value = fields[i][1];
		f[i].name_len = strlen(fields[i][0]);
		f[i].value_len = strlen(fields[i][1]);
	}
	static char join[128];
	return hw_h3_request_parse(f, n, join, sizeof(join), r);
}

#define REQ(...)                                                \
	do {                                                        \
		static const char *const fields_[][2] = __VA_ARGS__;    \
		rc = request_check(fields_, HW_ARRAY_LEN(fields_), &r); \
	} while (0)

static void test_request_validation(void) {
	hw_h3_request r;
	int rc;
	REQ({{":method", "GET"}, {":scheme", "https"}, {":path", "/"}, {":authority", "a"}});
	CHECK_EQ(rc, 0);
	CHECK(!r.protocol, "GET");
	REQ({{":method", "CONNECT"}, {":authority", "a:1"}});
	CHECK_EQ(rc, 0); // a plain CONNECT
	REQ({{":method", "CONNECT"}, {":authority", "a:1"}, {":path", "/"}});
	CHECK_EQ(rc, -1); // plain CONNECT with a path
	REQ({{":method", "CONNECT"}, {":protocol", "webtransport"}, {":authority", "a"}, {":path", "/"}});
	CHECK_EQ(rc, -1); // extended CONNECT without :scheme
	REQ({{":method", "CONNECT"}, {":protocol", "webtransport"}, {":scheme", "https"}, {":path", "/"}});
	CHECK_EQ(rc, -1); // without :authority
	REQ({{":method", "GET"}, {":protocol", "webtransport"}, {":scheme", "https"}, {":path", "/"}});
	CHECK_EQ(rc, -1); // :protocol on a GET
	REQ({{":method", "GET"}, {":scheme", "https"}, {":path", "/"}, {":method", "GET"}});
	CHECK_EQ(rc, -1); // a pseudo-header twice
	REQ({{":method", "GET"}, {"origin", "x"}, {":scheme", "https"}, {":path", "/"}});
	CHECK_EQ(rc, -1); // a pseudo-header after a regular field
	REQ({{":method", "GET"}, {":scheme", "https"}, {":path", "/"}, {":status", "200"}});
	CHECK_EQ(rc, -1); // a response pseudo-header
	REQ({{":method", "GET"}, {":scheme", "https"}, {":path", "/"}, {"Origin", "x"}});
	CHECK_EQ(rc, -1); // upper case
	REQ({{":method", "GET"}, {":scheme", "https"}, {":path", "/"}, {"a b", "x"}});
	CHECK_EQ(rc, -1); // not a token
	REQ({{":method", "GET"}, {":scheme", "https"}, {":path", "/"}, {"connection", "close"}});
	CHECK_EQ(rc, -1);
	REQ({{":method", "GET"}, {":scheme", "https"}, {":path", "/"}, {"te", "gzip"}});
	CHECK_EQ(rc, -1);
	REQ({{":method", "GET"}, {":scheme", "https"}, {":path", "/"}, {"te", "trailers"}});
	CHECK_EQ(rc, 0);
	REQ({{":method", "GET"}, {":scheme", "https"}, {":path", "/"}, {"x", "a\r\nb"}});
	CHECK_EQ(rc, -1);
	REQ({{":method", "GET"}, {":scheme", "https"}, {":path", ""}});
	CHECK_EQ(rc, -1);
	REQ({{":scheme", "https"}, {":path", "/"}});
	CHECK_EQ(rc, -1); // no method
	REQ({{":method", "CONNECT"},
	     {":protocol", "webtransport"},
	     {":scheme", "https"},
	     {":path", "/"},
	     {":authority", "a"},
	     {"wt-available-protocols", "\"a\""},
	     {"origin", "https://o"},
	     {"origin", "https://second"},
	     {"wt-available-protocols", "\"b\""}});
	CHECK_EQ(rc, 0);
	CHECK_STR(r.protocols, "\"a\", \"b\"");
	CHECK_STR(r.origin, "https://o");

	hw_qpack_field f[3] = {{":status", "200", 7, 3}, {"wt-protocol", "\"x\"", 11, 3}, {"server", "y", 6, 1}};
	int st;
	const char *proto;
	CHECK_EQ(hw_h3_response_parse(f, 3, &st, &proto), 0);
	CHECK_EQ(st, 200);
	CHECK_STR(proto, "\"x\"");
	hw_qpack_field g[2] = {{":status", "20", 7, 2}, {":status", "200", 7, 3}};
	CHECK_EQ(hw_h3_response_parse(g, 1, &st, &proto), -1);
	CHECK_EQ(hw_h3_response_parse(g + 1, 1, &st, &proto), 0);
	CHECK_EQ(hw_h3_response_parse(g, 0, &st, &proto), -1);
	hw_qpack_field h[2] = {{":status", "200", 7, 3}, {":status", "200", 7, 3}};
	CHECK_EQ(hw_h3_response_parse(h, 2, &st, &proto), -1);
}

static void test_protocol_first(void) {
	char out[32];
	CHECK_EQ(hw_wt_protocol_first("\"wisp-v2\", \"wisp-v1\"", out, sizeof(out)), 0);
	CHECK_STR(out, "wisp-v2");
	CHECK_EQ(hw_wt_protocol_first("  tok/1;q=1, b", out, sizeof(out)), 0);
	CHECK_STR(out, "tok/1");
	CHECK_EQ(hw_wt_protocol_first("\"a\\\"b\\\\\"", out, sizeof(out)), 0);
	CHECK_STR(out, "a\"b\\");
	CHECK_EQ(hw_wt_protocol_first("\"unterminated", out, sizeof(out)), -1);
	CHECK_EQ(hw_wt_protocol_first("\"bad\\n\"", out, sizeof(out)), -1);
	CHECK_EQ(hw_wt_protocol_first("1abc", out, sizeof(out)), -1);
	CHECK_EQ(hw_wt_protocol_first("", out, sizeof(out)), -1);
	CHECK_EQ(hw_wt_protocol_first("\"waytoolongforthisbuffer-waytoolong\"", out, 8), -1);
}

// ---- The Wisp framing -------------------------------------------------------------------------

typedef struct {
	uint8_t data[8][128];
	size_t len[8];
	size_t n;
} packets_seen;

static void lp_feed(hw_h3_lp *r, packets_seen *ps, const uint8_t *p, size_t len) {
	while (len) {
		size_t used;
		const uint8_t *pkt;
		size_t pl;
		int rc = hw_h3_lp_next(r, p, len, &used, &pkt, &pl);
		CHECK(rc >= 0, "lp error %d", rc);
		CHECK(used > 0 && used <= len, "progress");
		p += used;
		len -= used;
		if (rc == 1) {
			CHECK(ps->n < 8 && pl <= 128, "packet");
			if (pl) memcpy(ps->data[ps->n], pkt, pl);
			ps->len[ps->n++] = pl;
		}
	}
}

static void test_lp_splits(void) {
	static const size_t sizes[] = {5, 0, 37, 1, 9};
	uint8_t s[256];
	size_t n = 0;
	for (size_t i = 0; i < HW_ARRAY_LEN(sizes); i++) {
		hw_put_le32(s + n, (uint32_t)sizes[i]);
		n += 4;
		for (size_t j = 0; j < sizes[i]; j++) s[n++] = (uint8_t)(i * 16 + j);
	}
	for (size_t a = 0; a <= n; a++) {
		for (size_t b = a; b <= n; b++) {
			hw_h3_lp r;
			hw_h3_lp_init(&r, 37);
			static packets_seen ps;
			memset(&ps, 0, sizeof(ps));
			lp_feed(&r, &ps, s, a);
			lp_feed(&r, &ps, s + a, b - a);
			lp_feed(&r, &ps, s + b, n - b);
			CHECK(!hw_h3_lp_mid(&r), "ends between packets");
			CHECK_EQ(ps.n, HW_ARRAY_LEN(sizes));
			for (size_t i = 0; i < ps.n; i++) {
				CHECK(ps.len[i] == sizes[i], "split %zu/%zu packet %zu", a, b, i);
				for (size_t j = 0; j < sizes[i]; j++) CHECK_EQ(ps.data[i][j], (uint8_t)(i * 16 + j));
			}
			hw_h3_lp_clear(&r);
		}
	}
	// A length past max_packet is refused as soon as its four bytes are in.
	hw_h3_lp r;
	hw_h3_lp_init(&r, 36);
	size_t used;
	const uint8_t *pkt;
	size_t pl;
	int rc = 0;
	size_t off = 0;
	for (; off < n; off += used) {
		rc = hw_h3_lp_next(&r, s + off, 1, &used, &pkt, &pl);
		if (rc < 0) break;
	}
	CHECK_EQ(rc, HW_ERR_TOOBIG);
	CHECK_EQ(off, 4 + 5 + 4 + 3); // the third length's last byte
	hw_h3_lp_clear(&r);
	// A large packet, one byte at a time.
	hw_h3_lp_init(&r, 100000);
	uint8_t *big = malloc(70004);
	hw_put_le32(big, 70000);
	for (size_t i = 0; i < 70000; i++) big[4 + i] = (uint8_t)(i * 7);
	int got = 0;
	for (size_t i = 0; i < 70004; i++) {
		rc = hw_h3_lp_next(&r, big + i, 1, &used, &pkt, &pl);
		CHECK_EQ(used, 1);
		if (rc == 1) {
			CHECK_EQ(i, 70003);
			CHECK_EQ(pl, 70000);
			CHECK(pkt[69999] == (uint8_t)(69999 * 7), "content");
			got = 1;
		}
	}
	CHECK(got, "the large packet");
	free(big);
	hw_h3_lp_clear(&r);
}

// ---- A QUIC stand-in ------------------------------------------------------------------------

#define MOCK_STREAMS 512
enum {
	EV_DATA,
	EV_RESET,
	EV_STOP,
	EV_WRITABLE,
	EV_DGRAM,
	EV_CLOSED
};

typedef struct {
	int used;
	uint64_t id;
	// Receiving at this end: the credit granted the peer, and what it used.
	size_t granted, received, consumed;
	hw_buf rx; // a raw end's record of what arrived
	int rx_fin;
	int64_t rx_reset, stop_got;
	// Sending from this end.
	size_t sent;
	int blocked, fin_sent, reset_sent, stopped;
	int64_t stop_sent;
} mock_stream;

struct hw_quic_conn {
	int is_server;
	struct hw_quic_conn *peer;
	hw_wt *w; // NULL: a raw end, whose arrivals are recorded
	uint64_t next_bidi, next_uni;
	int uni_left;
	mock_stream st[MOCK_STREAMS];
	size_t window;
	size_t dgram_max;
	int closed;
	uint64_t close_code;
	int saw_close;
	uint8_t dgram[2048];
	size_t dgram_len;
	int dgrams;
	size_t queued;   // what hw_quic_queued reports
	int ignore_stop; // a hostile peer: STOP_SENDING is not answered with RESET_STREAM
	// A raw end's arrivals in order, for what must reach a peer before what.
	struct {
		int type;
		uint64_t id;
		int fin;
	} log[256];
	size_t nlog;
};

typedef struct {
	int type;
	hw_quic_conn *to;
	uint64_t id;
	uint8_t *data;
	size_t len;
	int fin;
	uint64_t code;
} mock_ev;

static mock_ev *g_evs;
static size_t g_ev_head, g_ev_len, g_ev_cap;

static void ev_push(int type, hw_quic_conn *to, uint64_t id, const uint8_t *d, size_t n, int fin, uint64_t code) {
	if (g_ev_len == g_ev_cap) {
		g_ev_cap = g_ev_cap ? 2 * g_ev_cap : 256;
		mock_ev *grown = realloc(g_evs, g_ev_cap * sizeof(*g_evs));
		CHECK(grown != NULL, "oom");
		g_evs = grown;
	}
	mock_ev *e = &g_evs[g_ev_len++];
	e->type = type;
	e->to = to;
	e->id = id;
	e->data = NULL;
	if (n) {
		e->data = malloc(n);
		memcpy(e->data, d, n);
	}
	e->len = n;
	e->fin = fin;
	e->code = code;
}

static mock_stream *mock_st(hw_quic_conn *q, uint64_t id) {
	for (size_t i = 0; i < MOCK_STREAMS; i++) {
		if (q->st[i].used && q->st[i].id == id) return &q->st[i];
	}
	for (size_t i = 0; i < MOCK_STREAMS; i++) {
		if (!q->st[i].used) {
			mock_stream *s = &q->st[i];
			memset(s, 0, sizeof(*s));
			s->used = 1;
			s->id = id;
			s->granted = q->window;
			s->rx_reset = s->stop_got = s->stop_sent = -1;
			hw_buf_init(&s->rx);
			return s;
		}
	}
	CHECK(0, "mock out of streams");
	return NULL;
}

// Events still queued when a test ends belong to connections that are gone.
static void ev_drop_all(void) {
	for (size_t i = g_ev_head; i < g_ev_len; i++) free(g_evs[i].data);
	g_ev_head = g_ev_len = 0;
}

static void mock_pair(hw_quic_conn *c, hw_quic_conn *s, size_t window) {
	ev_drop_all();
	memset(c, 0, sizeof(*c));
	memset(s, 0, sizeof(*s));
	c->peer = s;
	s->peer = c;
	s->is_server = 1;
	c->next_bidi = 0;
	c->next_uni = 2;
	s->next_bidi = 1;
	s->next_uni = 3;
	c->uni_left = s->uni_left = 100;
	c->window = s->window = window;
	c->dgram_max = s->dgram_max = 1200;
}

static void mock_free(hw_quic_conn *q) {
	for (size_t i = 0; i < MOCK_STREAMS; i++) hw_buf_free(&q->st[i].rx);
}

static void ev_deliver(mock_ev *e) {
	hw_quic_conn *t = e->to;
	if (t->closed) return;
	if (!t->w && t->nlog < HW_ARRAY_LEN(t->log) && (e->type == EV_CLOSED || !t->peer->closed)) {
		t->log[t->nlog].type = e->type;
		t->log[t->nlog].id = e->id;
		t->log[t->nlog].fin = e->fin;
		t->nlog++;
	}
	if (e->type == EV_CLOSED) {
		if (!t->saw_close) {
			t->saw_close = 1;
			if (t->w) hw_wt_on_closed(t->w);
		}
		return;
	}
	if (t->peer->closed) return;
	mock_stream *s = e->type == EV_DGRAM ? NULL : mock_st(t, e->id);
	switch (e->type) {
	case EV_DATA:
		CHECK(!s->rx_fin && s->rx_reset < 0, "data after the end of stream %llu", (unsigned long long)e->id);
		s->received += e->len;
		CHECK(s->received <= s->granted, "the peer sent past its credit");
		if (e->fin) s->rx_fin = 1;
		if (t->w) {
			hw_wt_on_stream_data(t->w, e->id, e->data, e->len, e->fin);
		} else if (e->len) {
			hw_buf_append(&s->rx, e->data, e->len);
		}
		break;
	case EV_RESET:
		if (s->rx_reset >= 0 || s->rx_fin) break;
		s->rx_reset = (int64_t)e->code;
		if (t->w) hw_wt_on_stream_reset(t->w, e->id, e->code);
		break;
	case EV_STOP:
		s->stop_got = (int64_t)e->code;
		if (s->stopped) break;
		s->stopped = 1;
		// QUIC answers STOP_SENDING with RESET_STREAM before the application hears of it.
		if (!s->fin_sent && !s->reset_sent && !t->ignore_stop) {
			s->reset_sent = 1;
			ev_push(EV_RESET, t->peer, e->id, NULL, 0, 0, e->code);
		}
		if (t->w) hw_wt_on_stream_stop(t->w, e->id, e->code);
		break;
	case EV_WRITABLE:
		if (t->w) hw_wt_on_stream_writable(t->w, e->id);
		break;
	case EV_DGRAM:
		if (t->w) {
			hw_wt_on_datagram(t->w, e->data, e->len);
		} else {
			memcpy(t->dgram, e->data, e->len);
			t->dgram_len = e->len;
			t->dgrams++;
		}
		break;
	default:
		break;
	}
}

static void pump(void) {
	size_t steps = 0;
	while (g_ev_head < g_ev_len) {
		CHECK(++steps < 1000000, "the events never end");
		mock_ev e = g_evs[g_ev_head++];
		ev_deliver(&e);
		free(e.data);
	}
	g_ev_head = g_ev_len = 0;
}

int64_t hw_quic_stream_open(hw_quic_conn *q, int bidi) {
	if (q->closed) return -1;
	if (!bidi && q->uni_left-- <= 0) return -1;
	uint64_t *next = bidi ? &q->next_bidi : &q->next_uni;
	uint64_t id = *next;
	*next += 4;
	mock_st(q, id);
	return (int64_t)id;
}

int64_t hw_quic_stream_write(hw_quic_conn *q, uint64_t id, const uint8_t *data, size_t len, int fin) {
	if (q->closed) return -1;
	int ours = (int)(id & 1) == q->is_server;
	if ((id & 2) && !ours) return -1;
	mock_stream *s = mock_st(q, id);
	if (s->reset_sent || s->stopped) return -1;
	CHECK(!s->fin_sent, "write after FIN on %llu", (unsigned long long)id);
	mock_stream *ps = mock_st(q->peer, id);
	size_t room = ps->granted - s->sent;
	size_t take = len < room ? len : room;
	if (take < len) s->blocked = 1;
	int fin_taken = fin && take == len;
	if (take || fin_taken) ev_push(EV_DATA, q->peer, id, data, take, fin_taken, 0);
	s->sent += take;
	if (fin_taken) s->fin_sent = 1;
	return (int64_t)take;
}

void hw_quic_stream_consumed(hw_quic_conn *q, uint64_t id, size_t n) {
	mock_stream *s = mock_st(q, id);
	s->consumed += n;
	CHECK(s->consumed <= s->received, "credit for bytes never received on %llu", (unsigned long long)id);
	s->granted += n;
	mock_stream *ps = mock_st(q->peer, id);
	if (ps->blocked) {
		ps->blocked = 0;
		ev_push(EV_WRITABLE, q->peer, id, NULL, 0, 0, 0);
	}
}

void hw_quic_stream_reset(hw_quic_conn *q, uint64_t id, uint64_t app_error) {
	mock_stream *s = mock_st(q, id);
	if (s->reset_sent || s->fin_sent) return;
	s->reset_sent = 1;
	ev_push(EV_RESET, q->peer, id, NULL, 0, 0, app_error);
}

void hw_quic_stream_stop(hw_quic_conn *q, uint64_t id, uint64_t app_error) {
	mock_stream *s = mock_st(q, id);
	s->stop_sent = (int64_t)app_error;
	ev_push(EV_STOP, q->peer, id, NULL, 0, 0, app_error);
}

int hw_quic_datagram_send(hw_quic_conn *q, const uint8_t *data, size_t len) {
	if (q->closed || len > q->dgram_max) return -1;
	ev_push(EV_DGRAM, q->peer, 0, data, len, 0, 0);
	return 0;
}

size_t hw_quic_datagram_max(const hw_quic_conn *q) {
	return q->dgram_max;
}

void hw_quic_close(hw_quic_conn *q, uint64_t app_error, const char *reason) {
	(void)reason;
	if (q->closed) return;
	q->closed = 1;
	q->close_code = app_error;
	ev_push(EV_CLOSED, q->peer, 0, NULL, 0, 0, 0);
}

size_t hw_quic_queued(const hw_quic_conn *q) {
	return q->queued;
}

// ---- Endpoints --------------------------------------------------------------------------------

#define EP_PKTS 256

typedef struct {
	hw_wt *w;
	hw_quic_conn *q;
	int requests;
	char authority[128], path[128], origin[128], protocols[128];
	int has_origin, has_protocols;
	int answer;
	const char *answer_protocol;
	int packets;
	uint8_t *pkt[EP_PKTS];
	size_t pkt_len[EP_PKTS];
	int pkt_dgram[EP_PKTS];
	int writable;
	int closed;
	uint32_t close_code;
	char close_reason[HW_H3_CLOSE_REASON_MAX + 1];
	int pause_at; // pause once this many packets have arrived
	int echo;     // send each packet back as it came
} endpoint;

static int ep_request(void *ud, const hw_wt_request *req, const char **protocol_out) {
	endpoint *e = ud;
	e->requests++;
	snprintf(e->authority, sizeof(e->authority), "%s", req->authority);
	snprintf(e->path, sizeof(e->path), "%s", req->path);
	e->has_origin = req->origin != NULL;
	if (req->origin) snprintf(e->origin, sizeof(e->origin), "%s", req->origin);
	e->has_protocols = req->protocols != NULL;
	if (req->protocols) snprintf(e->protocols, sizeof(e->protocols), "%s", req->protocols);
	*protocol_out = e->answer_protocol;
	return e->answer;
}

static void ep_packet(void *ud, const uint8_t *data, size_t len, int datagram) {
	endpoint *e = ud;
	CHECK(e->packets < EP_PKTS, "too many packets");
	e->pkt[e->packets] = malloc(len ? len : 1);
	if (len) memcpy(e->pkt[e->packets], data, len);
	e->pkt_len[e->packets] = len;
	e->pkt_dgram[e->packets] = datagram;
	e->packets++;
	if (e->echo) CHECK_EQ(hw_wt_send(e->w, data, len, datagram), 0);
	if (e->pause_at && e->packets == e->pause_at) hw_wt_pause(e->w, 1);
}

static void ep_writable(void *ud) {
	endpoint *e = ud;
	e->writable++;
}

static void ep_closed(void *ud, uint32_t code, const char *reason) {
	endpoint *e = ud;
	e->closed++;
	e->close_code = code;
	snprintf(e->close_reason, sizeof(e->close_reason), "%s", reason);
}

static void ep_init(endpoint *e, hw_quic_conn *q, int client, size_t max_packet, size_t send_max) {
	memset(e, 0, sizeof(*e));
	e->q = q;
	e->answer = 200;
	hw_wt_config cfg = {0};
	cfg.max_packet = max_packet;
	cfg.send_max = send_max;
	cfg.is_client = client;
	cfg.authority = "wisp.example.com:4433";
	cfg.path = "/wisp/?v=2";
	cfg.origin = "https://app.example.com";
	cfg.protocols = "\"wisp-v2\", \"wisp-v1\"";
	hw_wt_callbacks cb = {e, ep_request, ep_packet, ep_writable, ep_closed};
	e->w = hw_wt_new(q, &cfg, &cb);
	CHECK(e->w != NULL, "hw_wt_new");
	q->w = e->w;
}

static void ep_free(endpoint *e) {
	for (int i = 0; i < e->packets; i++) free(e->pkt[i]);
	hw_wt_free(e->w);
}

// A Wisp-shaped packet: type, stream id, then n bytes of a pattern.
static size_t make_packet(uint8_t *out, uint8_t type, uint32_t stream, size_t n, uint8_t seed) {
	hw_wisp_write_header(out, type, stream);
	for (size_t i = 0; i < n; i++) out[HW_WISP_HEADER_LEN + i] = (uint8_t)(seed + i * 31);
	return HW_WISP_HEADER_LEN + n;
}

static void session_open(endpoint *cl, endpoint *sv) {
	hw_wt_on_established(sv->w);
	hw_wt_on_established(cl->w);
	pump();
	CHECK(hw_wt_ready(cl->w) && hw_wt_ready(sv->w), "the session opened");
}

static void test_session(void) {
	hw_quic_conn qc, qs;
	mock_pair(&qc, &qs, 65536);
	static endpoint cl, sv;
	ep_init(&cl, &qc, 1, 1 << 20, 0);
	ep_init(&sv, &qs, 0, 1 << 20, 0);
	sv.answer_protocol = "wisp-v2";
	CHECK(!hw_wt_ready(cl.w) && hw_wt_send(cl.w, (const uint8_t *)"x", 1, 0) == -1, "not before the session");
	session_open(&cl, &sv);
	CHECK_EQ(sv.requests, 1);
	CHECK_STR(sv.authority, "wisp.example.com:4433");
	CHECK_STR(sv.path, "/wisp/?v=2");
	CHECK(sv.has_origin, "origin");
	CHECK_STR(sv.origin, "https://app.example.com");
	CHECK_STR(sv.protocols, "\"wisp-v2\", \"wisp-v1\"");
	CHECK_EQ(hw_wt_status(cl.w), 200);
	CHECK_STR(hw_wt_protocol(cl.w), "wisp-v2");
	CHECK_STR(hw_wt_protocol(sv.w), "wisp-v2");
	CHECK_EQ(cl.writable, 1); // ready is announced
	CHECK_EQ(sv.writable, 1);
	CHECK_EQ(hw_wt_datagram_max(sv.w), 1199);
	// Packets both ways on the stream, some larger than the stream window.
	static uint8_t p[300000];
	static const size_t sizes[] = {5, 100, 1500, 70000, 200000, 9};
	for (size_t i = 0; i < HW_ARRAY_LEN(sizes); i++) {
		size_t n = make_packet(p, HW_WISP_DATA, (uint32_t)i + 1, sizes[i] - 5, (uint8_t)i);
		CHECK_EQ(hw_wt_send(cl.w, p, n, 0), 0);
		CHECK_EQ(hw_wt_send(sv.w, p, n, 0), 0);
	}
	pump();
	CHECK_EQ(sv.packets, HW_ARRAY_LEN(sizes));
	CHECK_EQ(cl.packets, HW_ARRAY_LEN(sizes));
	for (size_t i = 0; i < HW_ARRAY_LEN(sizes); i++) {
		size_t n = make_packet(p, HW_WISP_DATA, (uint32_t)i + 1, sizes[i] - 5, (uint8_t)i);
		CHECK(sv.pkt_len[i] == n && memcmp(sv.pkt[i], p, n) == 0 && !sv.pkt_dgram[i], "to the server %zu", i);
		CHECK(cl.pkt_len[i] == n && memcmp(cl.pkt[i], p, n) == 0 && !cl.pkt_dgram[i], "to the client %zu", i);
	}
	CHECK_EQ(hw_wt_queued(cl.w), 0);
	// Datagrams: whole packets, and one too large goes on the stream.
	size_t n = make_packet(p, HW_WISP_DATA, 7, 1000, 3);
	CHECK_EQ(hw_wt_send(cl.w, p, n, 1), 0);
	CHECK_EQ(hw_wt_send(sv.w, p, n, 1), 0);
	size_t big = make_packet(p + 2000, HW_WISP_DATA, 7, 1300, 4);
	CHECK_EQ(hw_wt_send(cl.w, p + 2000, big, 1), 0);
	pump();
	CHECK_EQ(sv.packets, 8);
	CHECK(sv.pkt_dgram[6] && sv.pkt_len[6] == n && memcmp(sv.pkt[6], p, n) == 0, "datagram to the server");
	CHECK(!sv.pkt_dgram[7] && sv.pkt_len[7] == big && memcmp(sv.pkt[7], p + 2000, big) == 0, "too large: stream");
	CHECK_EQ(cl.packets, 7);
	CHECK(cl.pkt_dgram[6] && cl.pkt_len[6] == n, "datagram to the client");
	// A datagram for another session and one with no prefix.
	ev_push(EV_DGRAM, &qs, 0, (const uint8_t *)"\x01xxxxx", 6, 0, 0);
	pump();
	CHECK_EQ(sv.packets, 8);
	CHECK(!qs.closed, "another session's datagram is dropped");
	ev_push(EV_DGRAM, &qs, 0, (const uint8_t *)"", 0, 0, 0);
	ev_push(EV_DGRAM, &qs, 0, (const uint8_t *)"\x40", 1, 0, 0);
	pump();
	CHECK(qs.closed && qs.close_code == HW_H3_DATAGRAM_ERROR, "a datagram with no quarter stream id");
	CHECK_EQ(sv.closed, 1);
	CHECK_EQ(cl.closed, 1); // the client learns of the connection's end
	ep_free(&cl);
	ep_free(&sv);
	mock_free(&qc);
	mock_free(&qs);
}

static void test_session_close(void) {
	for (int who = 0; who < 2; who++) {
		hw_quic_conn qc, qs;
		mock_pair(&qc, &qs, 65536);
		static endpoint cl, sv;
		ep_init(&cl, &qc, 1, 4096, 0);
		ep_init(&sv, &qs, 0, 4096, 0);
		session_open(&cl, &sv);
		endpoint *closer = who ? &sv : &cl, *other = who ? &cl : &sv;
		uint8_t p[16];
		size_t n = make_packet(p, HW_WISP_CLOSE, 1, 1, 2);
		CHECK_EQ(hw_wt_send(closer->w, p, n, 0), 0); // sent before the close: it still arrives
		hw_wt_close(closer->w, who ? 7 : 42, who ? "server" : "bye");
		CHECK(!hw_wt_ready(closer->w) && hw_wt_send(closer->w, p, n, 0) == -1, "closed");
		CHECK(!closer->q->closed, "the connection waits for the answer");
		pump();
		CHECK_EQ(other->packets, 1);
		CHECK_EQ(other->closed, 1);
		CHECK_EQ(other->close_code, who ? 7 : 42);
		CHECK_STR(other->close_reason, who ? "server" : "bye");
		CHECK_EQ(closer->closed, 0); // its own close is not reported back
		CHECK(closer->q->closed && closer->q->close_code == HW_H3_NO_ERROR, "closed after the answer");
		CHECK(!hw_wt_ready(other->w), "the other side's session is over");
		ep_free(&cl);
		ep_free(&sv);
		mock_free(&qc);
		mock_free(&qs);
	}
}

// Pause stops the credit: the sender ends up blocked, then resumes when the receiver does.
static void test_session_pause(void) {
	hw_quic_conn qc, qs;
	mock_pair(&qc, &qs, 4096);
	static endpoint cl, sv;
	ep_init(&cl, &qc, 1, 1 << 16, 20000);
	ep_init(&sv, &qs, 0, 1 << 16, 0);
	session_open(&cl, &sv);
	sv.pause_at = 3;
	static uint8_t p[2000];
	size_t n = make_packet(p, HW_WISP_DATA, 1, 995, 9);
	int sent = 0, refused = 0;
	for (int i = 0; i < 100; i++) {
		int r = hw_wt_send(cl.w, p, n, 0);
		CHECK(r >= 0, "send");
		if (r == 1) {
			refused = 1;
			break;
		}
		sent++;
		pump();
	}
	CHECK(refused, "the client is pushed back");
	CHECK_EQ(sv.packets, 3);
	CHECK(hw_wt_queued(cl.w) >= 20000, "the client holds its queue");
	mock_stream *ws = mock_st(&qs, 4);
	CHECK(ws->received == ws->granted, "the client used all its credit");
	size_t consumed = ws->consumed;
	pump();
	CHECK_EQ(ws->consumed, consumed); // nothing more is credited while paused
	CHECK_EQ(sv.packets, 3);
	// Datagrams arriving while paused are dropped.
	CHECK_EQ(hw_wt_send(cl.w, p, 100, 1), 0);
	pump();
	CHECK_EQ(sv.packets, 3);
	int writable = cl.writable;
	hw_wt_pause(sv.w, 0);
	pump();
	CHECK_EQ(sv.packets, sent);
	CHECK(cl.writable > writable, "the client hears it may send again");
	CHECK_EQ(hw_wt_queued(cl.w), 0);
	CHECK_EQ(hw_wt_send(cl.w, p, n, 0), 0);
	pump();
	CHECK_EQ(sv.packets, sent + 1);
	for (int i = 0; i < sv.packets; i++) CHECK(sv.pkt_len[i] == n && memcmp(sv.pkt[i], p, n) == 0, "packet %d", i);
	ep_free(&cl);
	ep_free(&sv);
	mock_free(&qc);
	mock_free(&qs);
}

static void test_session_refused(void) {
	hw_quic_conn qc, qs;
	mock_pair(&qc, &qs, 65536);
	static endpoint cl, sv;
	ep_init(&cl, &qc, 1, 4096, 0);
	ep_init(&sv, &qs, 0, 4096, 0);
	sv.answer = 403;
	hw_wt_on_established(sv.w);
	hw_wt_on_established(cl.w);
	pump();
	CHECK_EQ(sv.requests, 1);
	CHECK_EQ(hw_wt_status(cl.w), 403);
	CHECK(!hw_wt_ready(cl.w) && !hw_wt_ready(sv.w), "no session");
	CHECK_EQ(cl.closed, 1);
	CHECK_EQ(sv.closed, 0); // there was no session to end
	CHECK(mock_st(&qs, 0)->fin_sent, "the server ends the response");
	CHECK(!qc.closed && !qs.closed, "the connection is the caller's to close");
	hw_wt_close(sv.w, 0, "refused");
	CHECK(qs.closed, "closed at once without a session");
	ep_free(&cl);
	ep_free(&sv);
	mock_free(&qc);
	mock_free(&qs);
}

// A packet over max_packet ends the connection.
static void test_session_oversize(void) {
	hw_quic_conn qc, qs;
	mock_pair(&qc, &qs, 65536);
	static endpoint cl, sv;
	ep_init(&cl, &qc, 1, 1 << 16, 0);
	ep_init(&sv, &qs, 0, 1000, 0);
	session_open(&cl, &sv);
	static uint8_t p[1100];
	size_t n = make_packet(p, HW_WISP_DATA, 1, 995, 1);
	CHECK_EQ(hw_wt_send(cl.w, p, n, 0), 0);
	n = make_packet(p, HW_WISP_DATA, 1, 996, 1);
	CHECK_EQ(hw_wt_send(cl.w, p, n, 0), 0);
	pump();
	CHECK_EQ(sv.packets, 1);
	CHECK(qs.closed && qs.close_code == HW_H3_MESSAGE_ERROR, "closed with H3_MESSAGE_ERROR");
	CHECK_EQ(sv.closed, 1);
	ep_free(&cl);
	ep_free(&sv);
	mock_free(&qc);
	mock_free(&qs);
}

// ---- A raw client: Chrome's bytes ------------------------------------------------------------

static void raw_write(hw_quic_conn *q, uint64_t id, const char *hex, int fin) {
	static uint8_t b[4096];
	size_t n = unhex(hex, b, sizeof(b));
	CHECK_EQ(hw_quic_stream_write(q, id, b, n, fin), (int64_t)(n));
}

static void raw_headers(hw_quic_conn *q, uint64_t id, const char *block_hex, int fin) {
	uint8_t b[2048], f[2100];
	size_t n = unhex(block_hex, b, sizeof(b));
	size_t h = hw_h3_frame_header_put(f, sizeof(f), HW_H3_FRAME_HEADERS, n);
	memcpy(f + h, b, n);
	CHECK_EQ(hw_quic_stream_write(q, id, f, h + n, fin), (int64_t)(h + n));
}

// The response a raw client got on a stream: the first HEADERS frame, decoded.
static int raw_response(hw_quic_conn *q, uint64_t id, decoded *d) {
	mock_stream *s = mock_st(q, id);
	const uint8_t *p = hw_buf_head(&s->rx);
	size_t n = hw_buf_avail(&s->rx);
	uint64_t type, len;
	size_t a = hw_qw_varint_get(p, n, &type);
	if (!a || type != HW_H3_FRAME_HEADERS) return -1;
	size_t b = hw_qw_varint_get(p + a, n - a, &len);
	if (!b || a + b + len > n) return -1;
	return hw_qpack_decode(p + a + b, (size_t)len, d->arena, sizeof(d->arena), d->f, 64);
}

static void raw_setup(hw_quic_conn *qc, hw_quic_conn *qs, endpoint *sv, int with_settings) {
	mock_pair(qc, qs, 65536);
	ep_init(sv, qs, 0, 4096, 0);
	hw_wt_on_established(sv->w);
	if (with_settings) raw_write(qc, 2, CHROME_SETTINGS, 0);
	pump();
}

static void raw_free(hw_quic_conn *qc, hw_quic_conn *qs, endpoint *sv) {
	ep_free(sv);
	mock_free(qc);
	mock_free(qs);
}

static void test_chrome_session(void) {
	hw_quic_conn qc, qs;
	static endpoint sv;
	raw_setup(&qc, &qs, &sv, 1);
	sv.answer_protocol = "\"wisp-v2\"";
	// What the server opened: its control stream with SETTINGS, and the two QPACK streams.
	uint8_t want[64];
	size_t wl = unhex("00 04 20 0100 0680004000 0700 0801 3301 80ffd27701 ab60374201 c0000000c671706a01", want,
	                  sizeof(want));
	mock_stream *c3 = mock_st(&qc, 3);
	CHECK(hw_buf_avail(&c3->rx) == wl && memcmp(hw_buf_head(&c3->rx), want, wl) == 0, "server control stream");
	CHECK(hw_buf_avail(&mock_st(&qc, 7)->rx) == 1 && hw_buf_head(&mock_st(&qc, 7)->rx)[0] == 0x02, "encoder");
	CHECK(hw_buf_avail(&mock_st(&qc, 11)->rx) == 1 && hw_buf_head(&mock_st(&qc, 11)->rx)[0] == 0x03, "decoder");
	// The request, then a DATA frame with one GREASE capsule.
	raw_headers(&qc, 0, CHROME_BLOCK, 0);
	raw_write(&qc, 0, "00 03 4040 00", 0);
	pump();
	CHECK_EQ(sv.requests, 1);
	CHECK_STR(sv.authority, "wisp.example.com:4433");
	CHECK_STR(sv.protocols, "\"wisp-v2\", \"wisp-v1\"");
	static decoded d;
	CHECK_EQ(raw_response(&qc, 0, &d), 3);
	CHECK_STR(d.f[0].name, ":status");
	CHECK_STR(d.f[0].value, "200");
	CHECK_STR(d.f[1].name, "sec-webtransport-http3-draft");
	CHECK_STR(d.f[1].value, "draft02");
	CHECK_STR(d.f[2].name, "wt-protocol");
	CHECK_STR(d.f[2].value, "\"wisp-v2\"");
	CHECK_EQ(hw_buf_head(&mock_st(&qc, 0)->rx)[2], 0x00); // the field section prefix
	CHECK_EQ(hw_buf_head(&mock_st(&qc, 0)->rx)[4], 0xd9); // :status 200, static index 25
	CHECK(!mock_st(&qc, 0)->rx_fin, "the CONNECT stream stays open");
	CHECK(!hw_wt_ready(sv.w), "not until the Wisp stream");
	// The Wisp stream: 40 41, session 0, then a length-prefixed packet, split mid-length.
	raw_write(&qc, 4, "4041 00 0600", 0);
	pump();
	CHECK(hw_wt_ready(sv.w), "the Wisp stream opened the session");
	CHECK_EQ(sv.writable, 1);
	raw_write(&qc, 4, "0000 04 01000000 02", 0);
	pump();
	CHECK_EQ(sv.packets, 1);
	CHECK(sv.pkt_len[0] == 6 && sv.pkt[0][0] == HW_WISP_CLOSE && sv.pkt[0][5] == 0x02 && !sv.pkt_dgram[0], "packet");
	// A datagram from the page, and one from the server.
	ev_push(EV_DGRAM, &qs, 0, (const uint8_t *)"\x00\x02\x05\x00\x00\x00hi", 8, 0, 0);
	pump();
	CHECK(sv.packets == 2 && sv.pkt_dgram[1] && sv.pkt_len[1] == 7, "datagram in");
	uint8_t p[16];
	size_t n = make_packet(p, HW_WISP_DATA, 5, 2, 0);
	CHECK_EQ(hw_wt_send(sv.w, p, n, 1), 0);
	CHECK_EQ(hw_wt_send(sv.w, p, n, 0), 0);
	pump();
	CHECK(qc.dgrams == 1 && qc.dgram_len == n + 1 && qc.dgram[0] == 0 && memcmp(qc.dgram + 1, p, n) == 0, "out");
	mock_stream *c4 = mock_st(&qc, 4);
	CHECK_EQ(hw_buf_avail(&c4->rx), 4 + n);
	CHECK_EQ(hw_le32(hw_buf_head(&c4->rx)), n);
	CHECK(memcmp(hw_buf_head(&c4->rx) + 4, p, n) == 0, "stream out");
	// A second session on the same connection, other WebTransport streams, a GREASE stream.
	raw_headers(&qc, 8, CHROME_BLOCK, 0);
	raw_write(&qc, 12, "4041 00 aaaa", 0);
	raw_write(&qc, 6, "4054 00 bbbb", 0);
	raw_write(&qc, 10, "407e cccc", 0);
	raw_write(&qc, 16, "4041 04 dddd", 0);
	pump();
	CHECK_EQ(sv.requests, 1);
	CHECK_EQ(raw_response(&qc, 8, &d), 1);
	CHECK_STR(d.f[0].value, "429");
	CHECK(mock_st(&qc, 8)->rx_fin && mock_st(&qc, 8)->stop_got == HW_H3_NO_ERROR, "429, FIN and STOP_SENDING");
	CHECK(mock_st(&qc, 12)->stop_got == HW_WT_BUFFERED_STREAM_REJECTED, "a second Wisp stream is stopped");
	CHECK(mock_st(&qc, 12)->rx_reset == HW_WT_BUFFERED_STREAM_REJECTED, "and reset");
	CHECK(mock_st(&qc, 16)->stop_got == HW_WT_BUFFERED_STREAM_REJECTED, "another session's stream");
	CHECK(mock_st(&qc, 6)->stop_got == HW_WT_BUFFERED_STREAM_REJECTED, "a unidirectional WebTransport stream");
	CHECK(mock_st(&qc, 10)->stop_got == HW_H3_STREAM_CREATION_ERROR, "a GREASE stream");
	CHECK(!qs.closed && hw_wt_ready(sv.w), "none of it ends the session");
	// The page's close({closeCode: 42, reason: 'bye'}): the capsule, then FIN.
	raw_write(&qc, 0, "00 0a 6843 07 0000002a 627965", 1);
	pump();
	CHECK_EQ(sv.closed, 1);
	CHECK_EQ(sv.close_code, 42);
	CHECK_STR(sv.close_reason, "bye");
	CHECK(mock_st(&qc, 0)->rx_fin, "the server answers with FIN");
	CHECK(mock_st(&qc, 4)->rx_reset == HW_WT_SESSION_GONE, "the Wisp stream is reset");
	CHECK(!hw_wt_ready(sv.w), "closed");
	raw_free(&qc, &qs, &sv);
}

static void test_chrome_other_requests(void) {
	hw_quic_conn qc, qs;
	static endpoint sv;
	static decoded d;
	// GET / gets a 404 with FIN, then the session still opens.
	raw_setup(&qc, &qs, &sv, 1);
	raw_headers(&qc, 0, "0000 d1 d7 c1 50 01 61", 0);
	pump();
	CHECK_EQ(raw_response(&qc, 0, &d), 1);
	CHECK_STR(d.f[0].value, "404");
	CHECK(mock_st(&qc, 0)->rx_fin && mock_st(&qc, 0)->stop_got == HW_H3_NO_ERROR, "404 and FIN");
	CHECK_EQ(sv.requests, 0);
	// A CONNECT for another protocol, a plain CONNECT.
	raw_headers(&qc, 4, "0000 d7 cf 50 01 61 c1 2f00 b95d8749c87a3f 02 7773", 0);
	raw_headers(&qc, 8, "0000 cf 50 03 613a31", 0);
	pump();
	CHECK_EQ(raw_response(&qc, 4, &d), 1);
	CHECK_STR(d.f[0].value, "405");
	CHECK_EQ(raw_response(&qc, 8, &d), 1);
	CHECK_STR(d.f[0].value, "405");
	// A malformed request (upper case name) is reset with H3_MESSAGE_ERROR.
	raw_headers(&qc, 12, "0000 d1 d7 c1 50 01 61 21 4f 01 78", 0);
	pump();
	CHECK(mock_st(&qc, 12)->rx_reset == HW_H3_MESSAGE_ERROR, "malformed: reset");
	CHECK(mock_st(&qc, 12)->stop_got == HW_H3_MESSAGE_ERROR, "malformed: stopped");
	// A FIN with no HEADERS at all.
	raw_write(&qc, 16, "", 1);
	pump();
	CHECK(mock_st(&qc, 16)->rx_reset == HW_H3_MESSAGE_ERROR, "no HEADERS");
	CHECK(!qs.closed, "none of these ends the connection");
	raw_headers(&qc, 20, CHROME_BLOCK, 0);
	pump();
	CHECK_EQ(sv.requests, 1);
	raw_free(&qc, &qs, &sv);

	// The request before the SETTINGS: answered once they arrive.
	raw_setup(&qc, &qs, &sv, 0);
	raw_headers(&qc, 0, CHROME_BLOCK, 0);
	pump();
	CHECK_EQ(sv.requests, 0);
	raw_write(&qc, 2, CHROME_SETTINGS, 0);
	pump();
	CHECK_EQ(sv.requests, 1);
	CHECK_EQ(raw_response(&qc, 0, &d), 2);
	raw_free(&qc, &qs, &sv);

	// A refused session (403): the response, FIN, and no second chance.
	raw_setup(&qc, &qs, &sv, 1);
	sv.answer = 403;
	raw_headers(&qc, 0, CHROME_BLOCK, 0);
	pump();
	CHECK_EQ(raw_response(&qc, 0, &d), 1);
	CHECK_STR(d.f[0].value, "403");
	CHECK(mock_st(&qc, 0)->rx_fin, "403 ends the stream");
	sv.answer = 200;
	raw_headers(&qc, 4, CHROME_BLOCK, 0);
	pump();
	CHECK_EQ(sv.requests, 1);
	CHECK_EQ(raw_response(&qc, 4, &d), 1);
	CHECK_STR(d.f[0].value, "429");
	raw_free(&qc, &qs, &sv);
}

// Connection errors, each from a fresh connection: what the peer sent, and the code it ends with.
static void test_chrome_errors(void) {
	static const struct {
		uint64_t stream;
		const char *hex;
		int fin;
		int settings_first;
		uint64_t code;
	} vec[] = {
	    {2, "00 07 01 00", 0, 0, HW_H3_MISSING_SETTINGS},          // GOAWAY before SETTINGS
	    {2, "00 4021 00", 0, 0, HW_H3_MISSING_SETTINGS},           // even a GREASE frame
	    {2, "00 04 02 0200", 0, 0, HW_H3_SETTINGS_ERROR},          // HTTP/2's ENABLE_PUSH
	    {2, "00 04 01 01", 0, 0, HW_H3_FRAME_ERROR},               // truncated
	    {2, "00 04 5100 00", 0, 0, HW_H3_EXCESSIVE_LOAD},          // 4352 bytes of SETTINGS
	    {6, "00 04 00", 0, 1, HW_H3_STREAM_CREATION_ERROR},        // a second control stream
	    {6, "02", 0, 1, 0},                                        // the encoder stream: fine
	    {2, "00 04 00", 1, 0, HW_H3_CLOSED_CRITICAL_STREAM},       // control stream FIN
	    {2, "00 04 00 00 00", 0, 0, HW_H3_FRAME_UNEXPECTED},       // DATA on the control stream
	    {2, "00 04 00 04 00", 0, 0, HW_H3_FRAME_UNEXPECTED},       // a second SETTINGS
	    {2, "00 04 00 02 00", 0, 0, HW_H3_FRAME_UNEXPECTED},       // HTTP/2's PRIORITY
	    {2, "00 04 00 01 02 d1 d7", 0, 0, HW_H3_FRAME_UNEXPECTED}, // HEADERS on the control stream
	    {2, "00 04 00 05 01 00", 0, 0, HW_H3_FRAME_UNEXPECTED},    // PUSH_PROMISE there
	    {0, "05 01 00", 0, 1, HW_H3_FRAME_UNEXPECTED},             // PUSH_PROMISE from a client
	    {0, "07 01 00", 0, 1, HW_H3_FRAME_UNEXPECTED},             // GOAWAY on a request stream
	    {2, "00 04 00 07 01 00 4021 02 abcd 0d 01 00", 0, 0, 0},   // GOAWAY, GREASE, MAX_PUSH_ID
	    {6, "01 00", 0, 1, HW_H3_STREAM_CREATION_ERROR},           // a push stream from a client
	    {0, "00 01 00", 0, 1, HW_H3_FRAME_UNEXPECTED},             // DATA before HEADERS
	    {0, "04 00", 0, 1, HW_H3_FRAME_UNEXPECTED},                // SETTINGS on a request stream
	    {0, "01 80004001", 0, 1, HW_H3_EXCESSIVE_LOAD},            // a header block over 16 KiB
	    {0, "01 03 0100 00", 0, 1, HW_QPACK_DECOMPRESSION_FAILED}, // the dynamic table
	    {0, "01 02 00", 1, 1, HW_H3_FRAME_ERROR},                  // FIN inside a frame
	};
	for (size_t i = 0; i < HW_ARRAY_LEN(vec); i++) {
		hw_quic_conn qc, qs;
		static endpoint sv;
		raw_setup(&qc, &qs, &sv, vec[i].settings_first);
		raw_write(&qc, vec[i].stream, vec[i].hex, vec[i].fin);
		pump();
		if (vec[i].code) {
			CHECK(qs.closed && qs.close_code == vec[i].code, "case %zu: closed %d with 0x%llx", i, qs.closed,
			      (unsigned long long)qs.close_code);
		} else {
			CHECK(!qs.closed, "case %zu: not closed (0x%llx)", i, (unsigned long long)qs.close_code);
		}
		raw_free(&qc, &qs, &sv);
	}
	// Too many streams at once, and a header block that never ends.
	hw_quic_conn qc, qs;
	static endpoint sv;
	raw_setup(&qc, &qs, &sv, 1);
	for (uint64_t i = 0; i < 70 && !qs.closed; i++) {
		raw_write(&qc, 4 * i, "01 10 0000", 0);
		pump();
	}
	CHECK(qs.closed && qs.close_code == HW_H3_EXCESSIVE_LOAD, "streams bounded");
	raw_free(&qc, &qs, &sv);
	raw_setup(&qc, &qs, &sv, 1);
	for (uint64_t i = 0; i < 6 && !qs.closed; i++) {
		static uint8_t f[16000];
		size_t h = hw_h3_frame_header_put(f, sizeof(f), HW_H3_FRAME_HEADERS, HW_H3_FIELD_SECTION_MAX);
		memset(f + h, 0, sizeof(f) - h);
		CHECK_EQ(hw_quic_stream_write(&qc, 4 * i, f, sizeof(f), 0), (int64_t)(sizeof(f)));
		pump();
	}
	CHECK(qs.closed && qs.close_code == HW_H3_EXCESSIVE_LOAD, "header bytes bounded across streams");
	raw_free(&qc, &qs, &sv);
	// A close capsule that is too long, a capsule over 64 KiB.
	static const char *const caps[] = {"00 4409 6843 4405 00000000", "00 07 4040 80010001"};
	static const uint64_t cap_code[] = {HW_H3_MESSAGE_ERROR, HW_H3_EXCESSIVE_LOAD};
	for (size_t i = 0; i < 2; i++) {
		raw_setup(&qc, &qs, &sv, 1);
		raw_headers(&qc, 0, CHROME_BLOCK, 0);
		raw_write(&qc, 0, caps[i], 0);
		pump();
		CHECK(qs.closed && qs.close_code == cap_code[i], "capsule %zu", i);
		raw_free(&qc, &qs, &sv);
	}
}

// Every split of what Chrome sends on the request and the Wisp streams reads the same.
static void test_chrome_splits(void) {
	uint8_t req[512];
	size_t rl = 0;
	uint8_t blk[256];
	size_t bl = unhex(CHROME_BLOCK, blk, sizeof(blk));
	rl += hw_h3_frame_header_put(req, sizeof(req), HW_H3_FRAME_HEADERS, bl);
	memcpy(req + rl, blk, bl);
	rl += bl;
	rl += unhex("00 03 4040 00", req + rl, sizeof(req) - rl);
	uint8_t wisp[64];
	size_t wl = unhex("4041 00 06000000 02 01000000 00 05000000 03 02000000", wisp, sizeof(wisp));
	for (size_t split = 0; split <= rl; split += split < 8 || split > rl - 8 ? 1 : 7) {
		hw_quic_conn qc, qs;
		static endpoint sv;
		raw_setup(&qc, &qs, &sv, 1);
		CHECK_EQ(hw_quic_stream_write(&qc, 0, req, split, 0), (int64_t)(split));
		pump();
		CHECK_EQ(hw_quic_stream_write(&qc, 0, req + split, rl - split, 0), (int64_t)(rl - split));
		pump();
		CHECK(sv.requests == 1 && !qs.closed, "request split at %zu", split);
		size_t ws = split % (wl + 1);
		CHECK_EQ(hw_quic_stream_write(&qc, 4, wisp, ws, 0), (int64_t)(ws));
		pump();
		CHECK_EQ(hw_quic_stream_write(&qc, 4, wisp + ws, wl - ws, 0), (int64_t)(wl - ws));
		pump();
		CHECK(sv.packets == 2 && sv.pkt_len[0] == 6 && sv.pkt_len[1] == 5, "Wisp split at %zu", ws);
		raw_free(&qc, &qs, &sv);
	}
}

// A pause inside a chunk that holds several packets: the rest waits, uncredited, and so does a
// FIN behind it; a resume delivers it in order, then the FIN.
static void test_chrome_pause(void) {
	hw_quic_conn qc, qs;
	static endpoint sv;
	raw_setup(&qc, &qs, &sv, 1);
	raw_headers(&qc, 0, CHROME_BLOCK, 0);
	sv.pause_at = 1;
	raw_write(&qc, 4, "4041 00 05000000 0201000000 06000000 030100000007 05000000 0401000000", 0);
	pump();
	mock_stream *s4 = mock_st(&qs, 4);
	CHECK_EQ(sv.packets, 1);
	CHECK_EQ(s4->consumed, 3 + 4 + 5); // the prefix and the one packet read
	raw_write(&qc, 4, "05000000 0202000000", 1);
	pump();
	CHECK_EQ(sv.packets, 1);
	CHECK_EQ(s4->consumed, 3 + 4 + 5);
	CHECK(hw_wt_ready(sv.w) && sv.closed == 0, "the FIN is behind the held packets");
	sv.pause_at = 3; // pause again from inside the drain
	hw_wt_pause(sv.w, 0);
	CHECK_EQ(sv.packets, 3);
	CHECK(hw_wt_ready(sv.w), "still open");
	hw_wt_pause(sv.w, 0);
	pump();
	CHECK_EQ(sv.packets, 4);
	CHECK(sv.pkt_len[1] == 6 && sv.pkt[1][0] == 0x03 && sv.pkt_len[3] == 5 && sv.pkt[3][1] == 0x02, "in order");
	CHECK_EQ(s4->consumed, s4->received);
	CHECK_EQ(sv.closed, 0); // the Wisp stream's FIN is not the session's end
	CHECK(hw_wt_ready(sv.w), "the server may still send");
	raw_free(&qc, &qs, &sv);
}

// The client role against a server that does not offer WebTransport, and one that sends a GOAWAY.
static void test_client_role(void) {
	hw_quic_conn qc, qs;
	mock_pair(&qc, &qs, 65536);
	static endpoint cl;
	ep_init(&cl, &qc, 1, 4096, 0);
	hw_wt_on_established(cl.w);
	pump();
	// Its SETTINGS, as Chrome's: decoder and encoder streams after the control stream.
	mock_stream *s2 = mock_st(&qs, 2);
	const uint8_t *p = hw_buf_head(&s2->rx);
	CHECK(hw_buf_avail(&s2->rx) > 3 && p[0] == 0x00 && p[1] == HW_H3_FRAME_SETTINGS, "client control stream");
	hw_h3_settings set;
	CHECK_EQ(hw_h3_settings_parse(p + 3, p[2], &set), 0);
	CHECK(set.h3_datagram && set.enable_webtransport, "client SETTINGS");
	CHECK_EQ(hw_buf_head(&mock_st(&qs, 6)->rx)[0], 0x03);
	CHECK_EQ(hw_buf_head(&mock_st(&qs, 10)->rx)[0], 0x02);
	CHECK_EQ(hw_buf_avail(&mock_st(&qs, 0)->rx), 0); // no request before the server's SETTINGS
	// A server whose SETTINGS lack ENABLE_WEBTRANSPORT.
	raw_write(&qs, 3, "00 04 02 3301", 0);
	pump();
	CHECK(qc.closed && qc.close_code == HW_H3_NO_ERROR, "no WebTransport: no request");
	CHECK_EQ(cl.closed, 1);
	ep_free(&cl);
	mock_free(&qc);
	mock_free(&qs);
	// The request it sends: Chrome's block, byte for byte, then the GREASE capsule.
	mock_pair(&qc, &qs, 65536);
	ep_init(&cl, &qc, 1, 4096, 0);
	hw_wt_on_established(cl.w);
	raw_write(&qs, 3, "00 04 07 3301 ab60374201", 0);
	pump();
	mock_stream *s0 = mock_st(&qs, 0);
	uint8_t blk[256];
	size_t bl = unhex(CHROME_BLOCK, blk, sizeof(blk));
	CHECK(hw_buf_avail(&s0->rx) >= bl + 3, "the request");
	CHECK(memcmp(hw_buf_head(&s0->rx) + 3, blk, bl) == 0, "Chrome's request block");
	// A 1xx, then 200 with wt-protocol; then the server's datagram before any Wisp packet.
	raw_headers(&qs, 0, "0000 ff00", 0); // :status 100
	raw_headers(&qs, 0, "0000 d9 2f01 f095abb0e9390f47 88 fe7c1915addc5fcf", 0);
	pump();
	CHECK_EQ(hw_wt_status(cl.w), 200);
	CHECK_STR(hw_wt_protocol(cl.w), "wisp-v2");
	CHECK(hw_wt_ready(cl.w), "ready after 200");
	mock_stream *s4 = mock_st(&qs, 4);
	CHECK(hw_buf_avail(&s4->rx) == 3 && memcmp(hw_buf_head(&s4->rx), "\x40\x41\x00", 3) == 0, "Wisp stream prefix");
	ev_push(EV_DGRAM, &qc, 0, (const uint8_t *)"\x00\x02\x05\x00\x00\x00hi", 8, 0, 0);
	raw_write(&qs, 4, "05000000 03 05000000", 0);
	pump();
	CHECK(cl.packets == 2 && cl.pkt_dgram[0] && !cl.pkt_dgram[1], "datagram and stream to the client");
	// A server bidi request stream is an error for a client.
	raw_write(&qs, 1, "01 00", 0);
	pump();
	CHECK(qc.closed && qc.close_code == HW_H3_STREAM_CREATION_ERROR, "server-initiated request stream");
	CHECK_EQ(cl.closed, 1);
	ep_free(&cl);
	mock_free(&qc);
	mock_free(&qs);
}

// ---- A hostile client --------------------------------------------------------------------------

static void raw_bytes(hw_quic_conn *q, uint64_t id, const uint8_t *d, size_t n) {
	CHECK_EQ(hw_quic_stream_write(q, id, d, n, 0), (int64_t)n);
	pump();
}

// A raw session: SETTINGS, the CONNECT, the Wisp stream (4).
static void raw_session(hw_quic_conn *qc, hw_quic_conn *qs, endpoint *sv) {
	raw_setup(qc, qs, sv, 1);
	raw_headers(qc, 0, CHROME_BLOCK, 0);
	raw_write(qc, 4, "4041 00", 0);
	pump();
	CHECK(hw_wt_ready(sv->w), "session");
}

// Streams the server refuses: unknown and GREASE unidirectional types, WebTransport streams of no
// session, a second Wisp stream. A peer that answers STOP_SENDING with RESET_STREAM, as QUIC
// requires, may open them for as long as it likes, since each is forgotten once reset; one that
// leaves them open is cut off when 64 are tracked, with H3_EXCESSIVE_LOAD.
static void test_hostile_streams(void) {
	static const struct {
		int bidi;
		const char *hex;
		uint64_t code;
	} kinds[] = {
	    {0, "407e cccc", HW_H3_STREAM_CREATION_ERROR},       // a GREASE type
	    {0, "21 00", HW_H3_STREAM_CREATION_ERROR},           // an unknown one
	    {0, "4054 00 bbbb", HW_WT_BUFFERED_STREAM_REJECTED}, // WebTransport unidirectional
	    {1, "4041 04 dddd", HW_WT_BUFFERED_STREAM_REJECTED}, // another session's
	    {1, "4041 00 eeee", HW_WT_BUFFERED_STREAM_REJECTED}, // a second Wisp stream
	};
	for (size_t k = 0; k < HW_ARRAY_LEN(kinds); k++) {
		for (int hostile = 0; hostile <= 1; hostile++) {
			static hw_quic_conn qc, qs;
			static endpoint sv;
			raw_session(&qc, &qs, &sv);
			qc.ignore_stop = hostile;
			int opened = 0;
			for (uint64_t i = 0; i < 300 && !qs.closed; i++, opened++) {
				uint64_t id = kinds[k].bidi ? 8 + 4 * i : 6 + 4 * i;
				raw_write(&qc, id, kinds[k].hex, 0);
				pump();
				if (qs.closed) break;
				CHECK(mock_st(&qc, id)->stop_got == (int64_t)kinds[k].code, "kind %zu stream %d", k, opened);
			}
			if (hostile) {
				CHECK(qs.closed && qs.close_code == HW_H3_EXCESSIVE_LOAD, "kind %zu: cut off", k);
				CHECK(opened <= 64, "kind %zu: %d streams held", k, opened);
			} else {
				CHECK(!qs.closed && opened == 300 && hw_wt_ready(sv.w), "kind %zu: 300 refused, session on", k);
			}
			raw_free(&qc, &qs, &sv);
		}
	}
}

// Endless GREASE and unknown frames on the control stream, a request stream that never sends its
// HEADERS, and endless GREASE capsules on the CONNECT stream: nothing is buffered (every byte is
// credited back as it is read), nothing closes, and the session works after.
static void test_hostile_grease(void) {
	static hw_quic_conn qc, qs;
	static endpoint sv;
	raw_session(&qc, &qs, &sv);
	static uint8_t chunk[2000];
	for (size_t i = 0; i < sizeof chunk; i += 2) {
		chunk[i] = 0x21; // GREASE frame type 0x21, empty
		chunk[i + 1] = 0x00;
	}
	for (int i = 0; i < 100; i++) raw_bytes(&qc, 2, chunk, sizeof chunk);
	raw_write(&qc, 2, "4021 05 0102030405 7f3e 03 aabbcc", 0); // with bodies
	mock_stream *c2 = mock_st(&qs, 2);
	CHECK(!qs.closed && c2->consumed == c2->received, "control stream: %zu of %zu credited", c2->consumed,
	      c2->received);

	// A request stream that sends only unknown frames: read and dropped, then its HEADERS count.
	for (int i = 0; i < 50; i++) raw_bytes(&qc, 8, chunk, sizeof chunk);
	mock_stream *c8 = mock_st(&qs, 8);
	CHECK(!qs.closed && c8->consumed == c8->received, "request stream credited");
	raw_headers(&qc, 8, CHROME_BLOCK, 0);
	pump();
	static decoded d;
	CHECK_EQ(raw_response(&qc, 8, &d), 1);
	CHECK_STR(d.f[0].value, "429");

	// DATA frames on the CONNECT stream, each with 100 GREASE capsules, and an unknown capsule
	// split across two frames.
	static uint8_t data[3 + 200];
	data[0] = 0x00;
	data[1] = 0x40;
	data[2] = 0xc8; // 200
	for (size_t i = 0; i < 200; i += 2) {
		data[3 + i] = 0x17; // GREASE capsule type 0x17, empty
		data[3 + i + 1] = 0x00;
	}
	for (int i = 0; i < 1000; i++) raw_bytes(&qc, 0, data, 3 + 200);
	raw_write(&qc, 0, "00 05 4040 06 0102", 0);
	raw_write(&qc, 0, "00 04 03040506", 0);
	pump();
	mock_stream *c0 = mock_st(&qs, 0);
	CHECK(!qs.closed && hw_wt_ready(sv.w) && c0->consumed == c0->received, "CONNECT stream credited");
	raw_write(&qc, 4, "05000000 0201000000", 0);
	pump();
	CHECK_EQ(sv.packets, 1);
	CHECK_EQ(sv.closed, 0);
	raw_free(&qc, &qs, &sv);
}

// A Wisp length of a megabyte, then the packet a byte at a time: the reassembly buffer holds what
// has arrived, not what was announced, every byte is credited as it is copied, and the packet
// arrives whole. The buffer is let go before the next packet.
static void test_hostile_wisp_length(void) {
	enum {
		BIG = 1000000
	};
	hw_h3_lp r;
	hw_h3_lp_init(&r, 1 << 20);
	uint8_t len4[4];
	hw_put_le32(len4, BIG);
	size_t used;
	const uint8_t *pkt;
	size_t pl;
	CHECK_EQ(hw_h3_lp_next(&r, len4, 4, &used, &pkt, &pl), 0);
	CHECK(r.buf_cap == 0, "a length costs nothing: %zu", r.buf_cap);
	uint8_t *big = malloc(BIG);
	CHECK(big != NULL, "malloc");
	for (size_t i = 0; i < BIG; i++) big[i] = (uint8_t)(i * 13 + 7);
	size_t off = 0;
	for (; off < 5000; off++) CHECK_EQ(hw_h3_lp_next(&r, big + off, 1, &used, &pkt, &pl), 0);
	CHECK(r.buf_cap <= 2 * 5000 + 4096, "5000 bytes in cost %zu", r.buf_cap);
	int rc = 0;
	while (off < BIG) {
		size_t n = HW_MIN((size_t)65536, (size_t)BIG - off);
		rc = hw_h3_lp_next(&r, big + off, n, &used, &pkt, &pl);
		CHECK(rc >= 0 && used == n, "progress");
		off += n;
	}
	CHECK(rc == 1 && pl == BIG && memcmp(pkt, big, BIG) == 0, "the packet, whole");
	CHECK(r.buf_cap <= BIG, "never past the packet: %zu", r.buf_cap);
	uint8_t small[9] = {5, 0, 0, 0, 2, 1, 0, 0, 0};
	CHECK_EQ(hw_h3_lp_next(&r, small, sizeof small, &used, &pkt, &pl), 1);
	CHECK(pl == 5 && r.buf_cap == 0, "the big buffer is gone: %zu", r.buf_cap);
	hw_h3_lp_clear(&r);

	// The same through a session whose max_packet allows it.
	static hw_quic_conn qc, qs;
	static endpoint sv;
	mock_pair(&qc, &qs, 65536);
	ep_init(&sv, &qs, 0, 1 << 20, 0);
	hw_wt_on_established(sv.w);
	raw_write(&qc, 2, CHROME_SETTINGS, 0);
	raw_headers(&qc, 0, CHROME_BLOCK, 0);
	raw_write(&qc, 4, "4041 00 40420f00", 0); // 1000000, little-endian
	pump();
	mock_stream *s4 = mock_st(&qs, 4);
	for (off = 0; off < 3000; off++) raw_bytes(&qc, 4, big + off, 1);
	CHECK(!qs.closed && sv.packets == 0 && s4->consumed == s4->received, "trickled and credited");
	while (off < BIG) {
		size_t n = HW_MIN((size_t)60000, (size_t)BIG - off);
		raw_bytes(&qc, 4, big + off, n);
		off += n;
	}
	CHECK(sv.packets == 1 && sv.pkt_len[0] == BIG && memcmp(sv.pkt[0], big, BIG) == 0, "the packet");
	free(big);
	raw_free(&qc, &qs, &sv);
}

// Datagrams for sessions that do not exist, or before there is one, are dropped unread however
// many come; a quarter stream id past 2^60 - 1, or none, is H3_DATAGRAM_ERROR.
static void test_hostile_datagrams(void) {
	static hw_quic_conn qc, qs;
	static endpoint sv;
	raw_setup(&qc, &qs, &sv, 1);
	ev_push(EV_DGRAM, &qs, 0, (const uint8_t *)"\x00\x02\x05\x00\x00\x00hi", 8, 0, 0);
	pump();
	CHECK(!qs.closed && sv.packets == 0, "before the session: dropped");
	raw_headers(&qc, 0, CHROME_BLOCK, 0);
	raw_write(&qc, 4, "4041 00", 0);
	pump();
	static const char *const qsids[] = {"01", "3f", "4001", "80000001", "c000000000000001", "cfffffffffffffff"};
	uint8_t dg[32];
	for (int i = 0; i < 10000; i++) {
		size_t n = unhex(qsids[i % HW_ARRAY_LEN(qsids)], dg, sizeof dg);
		n += unhex("02 05000000 6869", dg + n, sizeof dg - n);
		ev_push(EV_DGRAM, &qs, 0, dg, n, 0, 0);
		if (i % 1000 == 999) pump();
	}
	pump();
	CHECK(!qs.closed && sv.packets == 0 && hw_wt_ready(sv.w), "other sessions' datagrams: dropped");
	ev_push(EV_DGRAM, &qs, 0, (const uint8_t *)"\x00\x02\x05\x00\x00\x00hi", 8, 0, 0);
	pump();
	CHECK(sv.packets == 1 && sv.pkt_dgram[0], "the session's still arrives");
	size_t n = unhex("d000000000000000 02 05000000 6869", dg, sizeof dg); // 2^60
	ev_push(EV_DGRAM, &qs, 0, dg, n, 0, 0);
	pump();
	CHECK(qs.closed && qs.close_code == HW_H3_DATAGRAM_ERROR, "a quarter stream id past 2^60 - 1");
	raw_free(&qc, &qs, &sv);

	raw_session(&qc, &qs, &sv);
	ev_push(EV_DGRAM, &qs, 0, (const uint8_t *)"\x40", 1, 0, 0); // a varint cut short
	pump();
	CHECK(qs.closed && qs.close_code == HW_H3_DATAGRAM_ERROR, "no quarter stream id");
	raw_free(&qc, &qs, &sv);
}

// The server's close as Chrome needs it on the wire: the CLOSE_WEBTRANSPORT_SESSION capsule and
// the CONNECT stream's FIN first, and no STOP_SENDING or RESET_STREAM on any stream before them
// (Chrome reports "Connection lost" and never answers a capsule that its streams' resets
// overtook); the Wisp stream gets a FIN behind what was queued on it. Chrome then resets its data
// streams with H3_CONNECT_ERROR and answers with its FIN, in either order, which closes the
// connection with H3_NO_ERROR.
static void test_chrome_server_close(void) {
	for (int reset_first = 0; reset_first <= 1; reset_first++) {
		static hw_quic_conn qc, qs;
		static endpoint sv;
		raw_session(&qc, &qs, &sv);
		raw_write(&qc, 6, "4054 00 bbbb", 0); // a refused stream, answered long before the close
		pump();
		uint8_t p[16];
		size_t n = make_packet(p, HW_WISP_DATA, 1, 4, 3);
		CHECK_EQ(hw_wt_send(sv.w, p, n, 0), 0);
		pump();
		size_t before0 = hw_buf_avail(&mock_st(&qc, 0)->rx);
		size_t before4 = hw_buf_avail(&mock_st(&qc, 4)->rx);
		qc.nlog = 0;
		hw_wt_close(sv.w, 42, "bye");
		pump();
		CHECK(qc.nlog >= 1 && qc.log[0].type == EV_DATA && qc.log[0].id == 0 && qc.log[0].fin, "the capsule first");
		mock_stream *c0 = mock_st(&qc, 0);
		uint8_t want[16];
		size_t wl = unhex("00 0a 6843 07 0000002a 627965", want, sizeof(want));
		CHECK(hw_buf_avail(&c0->rx) == before0 + wl && memcmp(hw_buf_head(&c0->rx) + before0, want, wl) == 0,
		      "the capsule's bytes");
		CHECK(c0->rx_fin, "and the FIN");
		for (size_t i = 0; i < qc.nlog; i++) {
			CHECK(qc.log[i].type != EV_RESET && qc.log[i].type != EV_STOP && qc.log[i].type != EV_CLOSED,
			      "event %zu is %d on %llu", i, qc.log[i].type, (unsigned long long)qc.log[i].id);
		}
		mock_stream *c4 = mock_st(&qc, 4);
		CHECK(c4->rx_fin && c4->rx_reset < 0 && hw_buf_avail(&c4->rx) == before4, "the Wisp stream: a FIN");
		CHECK(!qs.closed && sv.closed == 0, "waiting for the answer, and no session_closed after hw_wt_close");
		// Chrome's answer.
		if (reset_first) {
			hw_quic_stream_reset(&qc, 4, 0x10f);
			pump();
			CHECK(!qs.closed, "a reset of the Wisp stream is not the answer");
		}
		raw_write(&qc, 0, "", 1);
		if (!reset_first) hw_quic_stream_reset(&qc, 4, 0x10f);
		pump();
		CHECK(qs.closed && qs.close_code == HW_H3_NO_ERROR, "closed once answered");
		CHECK_EQ(sv.closed, 0);
		raw_free(&qc, &qs, &sv);
	}
}

int main(void) {
	RUN(test_huffman_vectors);
	RUN(test_huffman_roundtrip);
	RUN(test_qpack_static);
	RUN(test_qpack_chrome_request);
	RUN(test_qpack_refusals);
	RUN(test_qpack_hostile);
	RUN(test_qpack_encode);
	RUN(test_settings);
	RUN(test_tlv_splits);
	RUN(test_stream_kind);
	RUN(test_capsule);
	RUN(test_request_validation);
	RUN(test_protocol_first);
	RUN(test_lp_splits);
	RUN(test_session);
	RUN(test_session_close);
	RUN(test_session_pause);
	RUN(test_session_refused);
	RUN(test_session_oversize);
	RUN(test_chrome_session);
	RUN(test_chrome_other_requests);
	RUN(test_chrome_errors);
	RUN(test_chrome_splits);
	RUN(test_chrome_pause);
	RUN(test_client_role);
	RUN(test_chrome_server_close);
	RUN(test_hostile_streams);
	RUN(test_hostile_grease);
	RUN(test_hostile_wisp_length);
	RUN(test_hostile_datagrams);
	ev_drop_all();
	free(g_evs);
	return 0;
}
