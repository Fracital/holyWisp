/*
 * tests/test_quic_wire.c - QUIC's wire format below the connection (src/quic/quic_wire.h) and
 * the listener's stateless functions of holywisp/quic.h: varints and packet numbers (RFC 9000
 * appendix A), every sample packet of RFC 9001 appendix A protected and opened byte for byte,
 * transport parameters, Retry tokens, stateless reset and Version Negotiation, and the header
 * parser fed every truncation and a few thousand mutations of those packets under ASan.
 */
#include "holywisp/aead.h"
#include "holywisp/hw.h"
#include "holywisp/quic.h"
#include "holywisp/sha256.h"

#include "quic/quic_wire.h"
#include "test.h"

#include <stdlib.h>
#include <string.h>

#include <netinet/in.h>

// RFC 9001 appendix A, copied from the RFC's text.
static const char A2_CRYPTO[] =
    "060040f1010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e86804fe3a47f06a2b69484c000004130113"
    "02010000c000000010000e00000b6578616d706c652e636f6dff01000100000a00080006001d00170018001000070005"
    "04616c706e000500050100000000003300260024001d00209370b2c9caa47fbabaf4559fedba753de171fa71f50f1ce1"
    "5d43e994ec74d748002b0003020304000d0010000e0403050306030203080408050806002d00020101001c0002400100"
    "3900320408ffffffffffffffff05048000ffff07048000ffff0801100104800075300901100f088394c8f03e51570806"
    "048000ffff";
static const char A2_PROTECTED[] =
    "c000000001088394c8f03e5157080000449e7b9aec34d1b1c98dd7689fb8ec11d242b123dc9bd8bab936b47d92ec356c"
    "0bab7df5976d27cd449f63300099f3991c260ec4c60d17b31f8429157bb35a1282a643a8d2262cad67500cadb8e7378c"
    "8eb7539ec4d4905fed1bee1fc8aafba17c750e2c7ace01e6005f80fcb7df621230c83711b39343fa028cea7f7fb5ff89"
    "eac2308249a02252155e2347b63d58c5457afd84d05dfffdb20392844ae812154682e9cf012f9021a6f0be17ddd0c208"
    "4dce25ff9b06cde535d0f920a2db1bf362c23e596d11a4f5a6cf3948838a3aec4e15daf8500a6ef69ec4e3feb6b1d98e"
    "610ac8b7ec3faf6ad760b7bad1db4ba3485e8a94dc250ae3fdb41ed15fb6a8e5eba0fc3dd60bc8e30c5c4287e53805db"
    "059ae0648db2f64264ed5e39be2e20d82df566da8dd5998ccabdae053060ae6c7b4378e846d29f37ed7b4ea9ec5d82e7"
    "961b7f25a9323851f681d582363aa5f89937f5a67258bf63ad6f1a0b1d96dbd4faddfcefc5266ba6611722395c906556"
    "be52afe3f565636ad1b17d508b73d8743eeb524be22b3dcbc2c7468d54119c7468449a13d8e3b95811a198f3491de3e7"
    "fe942b330407abf82a4ed7c1b311663ac69890f4157015853d91e923037c227a33cdd5ec281ca3f79c44546b9d90ca00"
    "f064c99e3dd97911d39fe9c5d0b23a229a234cb36186c4819e8b9c5927726632291d6a418211cc2962e20fe47feb3edf"
    "330f2c603a9d48c0fcb5699dbfe5896425c5bac4aee82e57a85aaf4e2513e4f05796b07ba2ee47d80506f8d2c25e50fd"
    "14de71e6c418559302f939b0e1abd576f279c4b2e0feb85c1f28ff18f58891ffef132eef2fa09346aee33c28eb130ff2"
    "8f5b766953334113211996d20011a198e3fc433f9f2541010ae17c1bf202580f6047472fb36857fe843b19f5984009dd"
    "c324044e847a4f4a0ab34f719595de37252d6235365e9b84392b061085349d73203a4a13e96f5432ec0fd4a1ee65accd"
    "d5e3904df54c1da510b0ff20dcc0c77fcb2c0e0eb605cb0504db87632cf3d8b4dae6e705769d1de354270123cb11450e"
    "fc60ac47683d7b8d0f811365565fd98c4c8eb936bcab8d069fc33bd801b03adea2e1fbc5aa463d08ca19896d2bf59a07"
    "1b851e6c239052172f296bfb5e72404790a2181014f3b94a4e97d117b438130368cc39dbb2d198065ae3986547926cd2"
    "162f40a29f0c3c8745c0f50fba3852e566d44575c29d39a03f0cda721984b6f440591f355e12d439ff150aab7613499d"
    "bd49adabc8676eef023b15b65bfc5ca06948109f23f350db82123535eb8a7433bdabcb909271a6ecbcb58b936a88cd4e"
    "8f2e6ff5800175f113253d8fa9ca8885c2f552e657dc603f252e1a8e308f76f0be79e2fb8f5d5fbbe2e30ecadd220723"
    "c8c0aea8078cdfcb3868263ff8f0940054da48781893a7e49ad5aff4af300cd804a6b6279ab3ff3afb64491c85194aab"
    "760d58a606654f9f4400e8b38591356fbf6425aca26dc85244259ff2b19c41b9f96f3ca9ec1dde434da7d2d392b905dd"
    "f3d1f9af93d1af5950bd493f5aa731b4056df31bd267b6b90a079831aaf579be0a39013137aac6d404f518cfd4684064"
    "7e78bfe706ca4cf5e9c5453e9f7cfd2b8b4c8d169a44e55c88d4a9a7f9474241e221af44860018ab0856972e194cd934";
static const char A3_PAYLOAD[] =
    "02000000000600405a020000560303eefce7f7b37ba1d1632e96677825ddf73988cfc79825df566dc5430b9a045a1200"
    "130100002e00330024001d00209d3c940d89690b84d08a60993c144eca684d1081287c834d5311bcf32bb9da1a002b00"
    "020304";
static const char A3_PROTECTED[] =
    "cf000000010008f067a5502a4262b5004075c0d95a482cd0991cd25b0aac406a5816b6394100f37a1c69797554780bb3"
    "8cc5a99f5ede4cf73c3ec2493a1839b3dbcba3f6ea46c5b7684df3548e7ddeb9c3bf9c73cc3f3bded74b562bfb19fb84"
    "022f8ef4cdd93795d77d06edbb7aaf2f58891850abbdca3d20398c276456cbc42158407dd074ee";
static const char A4_RETRY[] = "ff000000010008f067a5502a4262b5746f6b656e04a265ba2eff4d829058fb3f0f2496ba";

#define A_DCID     "8394c8f03e515708"
#define A2_HEADER  "c300000001088394c8f03e5157080000449e00000002"
#define A3_HEADER  "c1000000010008f067a5502a4262b50040750001"
#define A5_SECRET  "9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b"
#define A5_PACKET  "4cfe4189655e5cd55c41f69080575d7999c25a5bfb"
#define A5_PN      654360564
#define A2_PAYLOAD 1162
// The client's transport parameters inside A2_CRYPTO's ClientHello (extension 0x39).
#define A2_TP "0408ffffffffffffffff05048000ffff07048000ffff0801100104800075300901100f088394c8f03e51570806048000ffff"

#define BUF_MAX 2048

static size_t hex(const char *s, uint8_t *out, size_t cap) {
	size_t n = strlen(s) / 2;
	CHECK(n <= cap, "vector of %zu bytes over %zu", n, cap);
	for (size_t i = 0; i < 2 * n; i++) {
		char ch = s[i];
		int v = ch >= '0' && ch <= '9' ? ch - '0' : ch >= 'a' && ch <= 'f' ? ch - 'a' + 10 : -1;
		CHECK(v >= 0, "not a hex digit: %c", ch);
		out[i / 2] = (uint8_t)(i % 2 ? out[i / 2] << 4 | v : v);
	}
	return n;
}

// Field by field: the structs have padding, which memcmp would compare too.
static int tp_equal(const hw_qw_tp *a, const hw_qw_tp *b) {
	return a->max_idle_timeout == b->max_idle_timeout && a->max_udp_payload_size == b->max_udp_payload_size &&
	       a->initial_max_data == b->initial_max_data &&
	       a->initial_max_stream_data_bidi_local == b->initial_max_stream_data_bidi_local &&
	       a->initial_max_stream_data_bidi_remote == b->initial_max_stream_data_bidi_remote &&
	       a->initial_max_stream_data_uni == b->initial_max_stream_data_uni &&
	       a->initial_max_streams_bidi == b->initial_max_streams_bidi &&
	       a->initial_max_streams_uni == b->initial_max_streams_uni && a->ack_delay_exponent == b->ack_delay_exponent &&
	       a->max_ack_delay == b->max_ack_delay && a->active_connection_id_limit == b->active_connection_id_limit &&
	       a->max_datagram_frame_size == b->max_datagram_frame_size &&
	       a->disable_active_migration == b->disable_active_migration && a->has_original_dcid == b->has_original_dcid &&
	       a->has_initial_scid == b->has_initial_scid && a->has_retry_scid == b->has_retry_scid &&
	       a->has_reset_token == b->has_reset_token && a->original_dcid_len == b->original_dcid_len &&
	       memcmp(a->original_dcid, b->original_dcid, a->original_dcid_len) == 0 &&
	       a->initial_scid_len == b->initial_scid_len &&
	       memcmp(a->initial_scid, b->initial_scid, a->initial_scid_len) == 0 &&
	       a->retry_scid_len == b->retry_scid_len && memcmp(a->retry_scid, b->retry_scid, a->retry_scid_len) == 0 &&
	       memcmp(a->reset_token, b->reset_token, sizeof(a->reset_token)) == 0;
}

#define CHECK_HEX(got, n, want)                                                                     \
	do {                                                                                            \
		uint8_t want_[BUF_MAX];                                                                     \
		CHECK(strlen(want) == 2 * (size_t)(n), "length %zu != %zu", strlen(want) / 2, (size_t)(n)); \
		hex(want, want_, sizeof(want_));                                                            \
		CHECK(memcmp(got, want_, n) == 0, "bytes differ from %s", want);                            \
	} while (0)

// A fixed-seed generator, so a failing mutation is the same one on the next run.
static uint64_t g_rng = 0x9e3779b97f4a7c15ull;
static uint64_t rng(void) {
	g_rng ^= g_rng << 13;
	g_rng ^= g_rng >> 7;
	g_rng ^= g_rng << 17;
	return g_rng;
}

// ---- Varints and packet numbers -------------------------------------------------------------

static void test_varint(void) {
	static const struct {
		uint64_t v;
		size_t len;
	} edges[] = {
	    {0, 1}, {63, 1}, {64, 2}, {16383, 2}, {16384, 4}, {1073741823, 4}, {1073741824, 8}, {HW_QW_VARINT_MAX, 8},
	};
	uint8_t b[16];
	for (size_t i = 0; i < HW_ARRAY_LEN(edges); i++) {
		CHECK_EQ(hw_qw_varint_len(edges[i].v), edges[i].len);
		CHECK_EQ(hw_qw_varint_put(b, sizeof(b), edges[i].v), edges[i].len);
		uint64_t v = 1;
		CHECK_EQ(hw_qw_varint_get(b, edges[i].len, &v), edges[i].len);
		CHECK(v == edges[i].v, "%llu round-tripped as %llu", (unsigned long long)edges[i].v, (unsigned long long)v);
		CHECK_EQ(hw_qw_varint_get(b, edges[i].len - 1, &v), 0);         // one byte short
		CHECK_EQ(hw_qw_varint_put(b, edges[i].len - 1, edges[i].v), 0); // no room
	}
	CHECK_EQ(hw_qw_varint_put(b, sizeof(b), HW_QW_VARINT_MAX + 1), 0);
	CHECK_EQ(hw_qw_varint_put_n(b, sizeof(b), HW_QW_VARINT_MAX + 1, 8), 0);

	// RFC 9000 A.1, and the non-shortest encodings a reader must accept.
	static const struct {
		const char *hex;
		uint64_t v;
	} rfc[] = {
	    {"c2197c5eff14e88c", 151288809941952652ull},
	    {"9d7f3e7d", 494878333},
	    {"7bbd", 15293},
	    {"25", 37},
	    {"4025", 37},
	    {"80000025", 37},
	    {"c000000000000025", 37},
	    {"c000000000000000", 0},
	};
	for (size_t i = 0; i < HW_ARRAY_LEN(rfc); i++) {
		size_t n = hex(rfc[i].hex, b, sizeof(b));
		uint64_t v = 0;
		CHECK_EQ(hw_qw_varint_get(b, n, &v), n);
		CHECK(v == rfc[i].v, "%s read as %llu", rfc[i].hex, (unsigned long long)v);
	}
	CHECK_EQ(hw_qw_varint_put(b, sizeof(b), 151288809941952652ull), 8);
	CHECK_HEX(b, 8, "c2197c5eff14e88c");
	CHECK_EQ(hw_qw_varint_put(b, sizeof(b), 494878333), 4);
	CHECK_HEX(b, 4, "9d7f3e7d");
	CHECK_EQ(hw_qw_varint_put(b, sizeof(b), 15293), 2);
	CHECK_HEX(b, 2, "7bbd");

	// Fixed widths, as a Length field written before its payload needs.
	CHECK_EQ(hw_qw_varint_put_n(b, sizeof(b), 37, 2), 2);
	CHECK_HEX(b, 2, "4025");
	CHECK_EQ(hw_qw_varint_put_n(b, sizeof(b), 37, 4), 4);
	CHECK_HEX(b, 4, "80000025");
	CHECK_EQ(hw_qw_varint_put_n(b, sizeof(b), 37, 8), 8);
	CHECK_HEX(b, 8, "c000000000000025");
	CHECK_EQ(hw_qw_varint_put_n(b, sizeof(b), 64, 1), 0);
	CHECK_EQ(hw_qw_varint_put_n(b, sizeof(b), 16384, 2), 0);
	CHECK_EQ(hw_qw_varint_put_n(b, sizeof(b), 1073741824, 4), 0);
	CHECK_EQ(hw_qw_varint_put_n(b, sizeof(b), 1, 3), 0);
	CHECK_EQ(hw_qw_varint_put_n(b, 3, 1, 4), 0);
	CHECK_EQ(hw_qw_varint_get(b, 0, &(uint64_t){0}), 0);
}

static void test_pn(void) {
	// RFC 9000 A.2.
	CHECK_EQ(hw_qw_pn_len(0xac5c02, 0xabe8b3), 2);
	CHECK_EQ(hw_qw_pn_len(0xace8fe, 0xabe8b3), 3);
	// Nothing acknowledged: the whole number counts.
	CHECK_EQ(hw_qw_pn_len(0, -1), 1);
	CHECK_EQ(hw_qw_pn_len(127, -1), 1);
	CHECK_EQ(hw_qw_pn_len(128, -1), 2);
	CHECK_EQ(hw_qw_pn_len(32767, -1), 2);
	CHECK_EQ(hw_qw_pn_len(32768, -1), 3);
	CHECK_EQ(hw_qw_pn_len(0x7fffff, -1), 3);
	CHECK_EQ(hw_qw_pn_len(0x800000, -1), 4);
	CHECK_EQ(hw_qw_pn_len(1ull << 40, 0), 4);
	CHECK_EQ(hw_qw_pn_len(5, 5), 1);
	CHECK_EQ(hw_qw_pn_len(1000 + 128, 1000), 1);
	CHECK_EQ(hw_qw_pn_len(1000 + 129, 1000), 2);

	// RFC 9000 A.3.
	CHECK(hw_qw_pn_decode(0xa82f30ea, 0x9b32, 2) == 0xa82f9b32, "A.3 example");
	// Wrap edges.
	CHECK_EQ(hw_qw_pn_decode(-1, 0, 1), 0);
	CHECK_EQ(hw_qw_pn_decode(-1, 0xff, 1), 255);
	CHECK_EQ(hw_qw_pn_decode(255, 0x00, 1), 256);
	CHECK_EQ(hw_qw_pn_decode(300, 0x10, 1), 272);
	CHECK_EQ(hw_qw_pn_decode(300, 0xf0, 1), 240);
	CHECK_EQ(hw_qw_pn_decode(0xffff, 0x0000, 2), 0x10000);
	CHECK_EQ(hw_qw_pn_decode(0x10000, 0xffff, 2), 0xffff);
	CHECK_EQ(hw_qw_pn_decode(0x7fffffff, 0x80000000u, 4), 0x80000000ll);
	CHECK_EQ(hw_qw_pn_decode(0x7fffffff, 0, 4), 0x100000000ll); // exactly half a window back is ahead
	CHECK_EQ(hw_qw_pn_decode(0xfffffffe, 0x00000000, 4), 0x100000000ll);
	// Near 2^62 the window may not run past the end of the number space.
	uint64_t top = (1ull << 62) - 1;
	CHECK(hw_qw_pn_decode((int64_t)top - 1, 0x00, 1) == top - 0xff, "no candidate past 2^62");
	CHECK(hw_qw_pn_decode((int64_t)top - 1, 0xff, 1) == top, "the last packet number");

	// Whatever the receiver's largest is between what was acknowledged and pn - 1, a packet number
	// encoded with hw_qw_pn_len decodes back.
	for (int i = 0; i < 20000; i++) {
		int64_t acked = (int64_t)(rng() % (1ull << 40));
		uint64_t pn = (uint64_t)acked + 1 + rng() % (1ull << (rng() % 31));
		size_t n = hw_qw_pn_len(pn, acked);
		uint64_t trunc = pn & ((1ull << (8 * n)) - 1);
		CHECK(hw_qw_pn_decode(acked, trunc, n) == pn, "pn %llu acked %lld", (unsigned long long)pn, (long long)acked);
		CHECK(hw_qw_pn_decode((int64_t)pn - 1, trunc, n) == pn, "pn %llu", (unsigned long long)pn);
	}
}

// ---- RFC 9001 appendix A --------------------------------------------------------------------

static void test_initial_keys(void) {
	uint8_t dcid[8];
	hex(A_DCID, dcid, sizeof(dcid));
	hw_qw_keys c, s;
	hw_qw_initial_keys(dcid, sizeof(dcid), &c, &s);
	CHECK_EQ(c.cipher, HW_TLS_CIPHER_AES128GCM);
	CHECK_EQ(s.cipher, HW_TLS_CIPHER_AES128GCM);
	CHECK_HEX(c.secret, 32, "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea");
	CHECK_HEX(c.key, 16, "1f369613dd76d5467730efcbe3b1a22d");
	CHECK_HEX(c.iv, 12, "fa044b2f42a3fd3b46fb255c");
	CHECK_HEX(c.hp, 16, "9f50449e04a0e810283a1e9933adedd2");
	CHECK_HEX(s.secret, 32, "3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b");
	CHECK_HEX(s.key, 16, "cf3a5331653c364c88f0f379b6067e37");
	CHECK_HEX(s.iv, 12, "0ac1493ca1905853b0bba03e");
	CHECK_HEX(s.hp, 16, "c206b8d9b9f0f37644430b490eeaa314");

	// Either side alone.
	hw_qw_keys only;
	hw_qw_initial_keys(dcid, sizeof(dcid), NULL, &only);
	CHECK(memcmp(only.key, s.key, 16) == 0, "server keys alone");
	hw_qw_initial_keys(dcid, sizeof(dcid), &only, NULL);
	CHECK(memcmp(only.key, c.key, 16) == 0, "client keys alone");

	// The header-protection masks of A.2 and A.3.
	uint8_t sample[16], mask[5];
	hex("d1b1c98dd7689fb8ec11d242b123dc9b", sample, sizeof(sample));
	CHECK_EQ(hw_qw_hp_mask(&c, sample, mask), 0);
	CHECK_HEX(mask, 5, "437b9aec36");
	hex("2cd0991cd25b0aac406a5816b6394100", sample, sizeof(sample));
	CHECK_EQ(hw_qw_hp_mask(&s, sample, mask), 0);
	CHECK_HEX(mask, 5, "2ec0d8356a");

	hw_qw_keys_clear(&c);
	const uint8_t *bytes = (const uint8_t *)&c; // every byte, padding included, is to be zero
	uint8_t any = 0;
	for (size_t i = 0; i < sizeof(c); i++) any |= bytes[i];
	CHECK_EQ(any, 0);
	hw_qw_keys bad = s;
	bad.cipher = 0x1302;
	CHECK_EQ(hw_qw_hp_mask(&bad, sample, mask), -1);
}

static void test_client_initial(void) {
	uint8_t dcid[8];
	hex(A_DCID, dcid, sizeof(dcid));
	hw_qw_keys c, s;
	hw_qw_initial_keys(dcid, sizeof(dcid), &c, &s);

	uint8_t pkt[BUF_MAX] = {0}, plain[A2_PAYLOAD] = {0};
	size_t hl = hex(A2_HEADER, pkt, sizeof(pkt));
	CHECK_EQ(hl, 22);
	hex(A2_CRYPTO, plain, sizeof(plain)); // the rest is PADDING (zeros)
	memcpy(pkt + hl, plain, sizeof(plain));
	size_t n = hw_qw_protect(&c, pkt, 18, 4, 2, A2_PAYLOAD);
	CHECK_EQ(n, 1200);
	CHECK_HEX(pkt, 1200, A2_PROTECTED);

	hw_qw_hdr h;
	CHECK_EQ(hw_qw_parse(pkt, n, HW_QUIC_CID_LEN, &h), 0);
	CHECK_EQ(h.type, HW_QW_INITIAL);
	CHECK_EQ(h.version, HW_QUIC_VERSION_1);
	CHECK_EQ(h.dcid_len, 8);
	CHECK(memcmp(h.dcid, dcid, 8) == 0, "dcid");
	CHECK_EQ(h.scid_len, 0);
	CHECK_EQ(h.token_len, 0);
	CHECK_EQ(h.pn_offset, 18);
	CHECK_EQ(h.packet_len, 1200);

	uint64_t pn = 0;
	uint8_t *payload = NULL;
	size_t payload_len = 0;
	int kp = -1;
	CHECK_EQ(hw_qw_unprotect(&c, pkt, h.packet_len, h.pn_offset, -1, &pn, &payload, &payload_len, &kp), 0);
	CHECK_EQ(pn, 2);
	CHECK_EQ(kp, 0);
	CHECK_EQ(payload_len, A2_PAYLOAD);
	CHECK(memcmp(payload, plain, A2_PAYLOAD) == 0, "plaintext back");
	CHECK_HEX(pkt, 22, A2_HEADER);

	// The server's keys, a flipped bit, and a cut tag all fail to open it.
	uint8_t copy[BUF_MAX];
	hex(A2_PROTECTED, copy, sizeof(copy));
	CHECK_EQ(hw_qw_unprotect(&s, copy, 1200, 18, -1, &pn, &payload, &payload_len, &kp), -1);
	hex(A2_PROTECTED, copy, sizeof(copy));
	copy[600] ^= 1;
	CHECK_EQ(hw_qw_unprotect(&c, copy, 1200, 18, -1, &pn, &payload, &payload_len, &kp), -1);
	hex(A2_PROTECTED, copy, sizeof(copy));
	CHECK_EQ(hw_qw_unprotect(&c, copy, 1199, 18, -1, &pn, &payload, &payload_len, &kp), -1);
	// Too short to sample: refused before anything is read.
	CHECK_EQ(hw_qw_unprotect(&c, copy, 18 + 19, 18, -1, &pn, &payload, &payload_len, &kp), -1);
	CHECK_EQ(hw_qw_unprotect(&c, copy, 10, 18, -1, &pn, &payload, &payload_len, &kp), -1);

	// The listener's view of the same datagram.
	hw_quic_header qh;
	hex(A2_PROTECTED, copy, sizeof(copy));
	CHECK_EQ(hw_quic_parse_header(copy, 1200, &qh), 0);
	CHECK_EQ(qh.long_header, 1);
	CHECK_EQ(qh.type, 0);
	CHECK_EQ(qh.version, HW_QUIC_VERSION_1);
	CHECK_EQ(qh.dcid_len, 8);
	CHECK(memcmp(qh.dcid, dcid, 8) == 0, "dcid");
	CHECK_EQ(qh.scid_len, 0);
	CHECK_EQ(qh.token_len, 0);
	CHECK_EQ(qh.dgram_len, 1200);

	// The client's transport parameters from its ClientHello.
	uint8_t tpb[64];
	size_t tpl = hex(A2_TP, tpb, sizeof(tpb));
	CHECK_EQ(tpl, 0x32);
	int inside = 0;
	for (size_t i = 0; i + tpl <= A2_PAYLOAD; i++) inside |= memcmp(plain + i, tpb, tpl) == 0;
	CHECK(inside, "A2_TP is inside the ClientHello");
	hw_qw_tp tp;
	CHECK_EQ(hw_qw_tp_decode(tpb, tpl, 0, &tp), 0);
	CHECK(tp.initial_max_data == HW_QW_VARINT_MAX, "initial_max_data");
	CHECK_EQ(tp.initial_max_stream_data_bidi_local, 0xffff);
	CHECK_EQ(tp.initial_max_stream_data_bidi_remote, 0xffff);
	CHECK_EQ(tp.initial_max_stream_data_uni, 0xffff);
	CHECK_EQ(tp.initial_max_streams_bidi, 16);
	CHECK_EQ(tp.initial_max_streams_uni, 16);
	CHECK_EQ(tp.max_idle_timeout, 30000);
	CHECK_EQ(tp.has_initial_scid, 1);
	CHECK_EQ(tp.initial_scid_len, 8);
	CHECK(memcmp(tp.initial_scid, dcid, 8) == 0, "initial_source_connection_id");
	CHECK_EQ(tp.max_udp_payload_size, 65527);
	CHECK_EQ(tp.ack_delay_exponent, 3);
	CHECK_EQ(tp.max_ack_delay, 25);
	CHECK_EQ(tp.active_connection_id_limit, 2);
	CHECK_EQ(tp.has_original_dcid, 0);
	// Nothing in them is server-only, so the same bytes from a server decode too.
	CHECK_EQ(hw_qw_tp_decode(tpb, tpl, 1, &tp), 0);
}

static void test_server_initial(void) {
	uint8_t dcid[8];
	hex(A_DCID, dcid, sizeof(dcid));
	hw_qw_keys c, s;
	hw_qw_initial_keys(dcid, sizeof(dcid), &c, &s);

	uint8_t pkt[BUF_MAX] = {0}, plain[128];
	size_t hl = hex(A3_HEADER, pkt, sizeof(pkt));
	size_t pl = hex(A3_PAYLOAD, plain, sizeof(plain));
	CHECK_EQ(hl, 20);
	CHECK_EQ(pl, 99);
	memcpy(pkt + hl, plain, pl);
	size_t n = hw_qw_protect(&s, pkt, 18, 2, 1, pl);
	CHECK_EQ(n, 135);
	CHECK_HEX(pkt, 135, A3_PROTECTED);

	hw_qw_hdr h;
	CHECK_EQ(hw_qw_parse(pkt, n, HW_QUIC_CID_LEN, &h), 0);
	CHECK_EQ(h.type, HW_QW_INITIAL);
	CHECK_EQ(h.dcid_len, 0);
	CHECK_EQ(h.scid_len, 8);
	CHECK_HEX(h.scid, 8, "f067a5502a4262b5");
	CHECK_EQ(h.pn_offset, 18);
	CHECK_EQ(h.packet_len, 135);

	uint64_t pn = 0;
	uint8_t *payload = NULL;
	size_t payload_len = 0;
	int kp = -1;
	CHECK_EQ(hw_qw_unprotect(&s, pkt, h.packet_len, h.pn_offset, 0, &pn, &payload, &payload_len, &kp), 0);
	CHECK_EQ(pn, 1);
	CHECK_EQ(payload_len, 99);
	CHECK(memcmp(payload, plain, pl) == 0, "plaintext back");
	CHECK_HEX(pkt, 20, A3_HEADER);

	// Coalesced: two packets in one datagram are walked by packet_len.
	uint8_t dg[BUF_MAX];
	size_t a = hex(A3_PROTECTED, dg, sizeof(dg));
	memcpy(dg + a, dg, a);
	CHECK_EQ(hw_qw_parse(dg, 2 * a, HW_QUIC_CID_LEN, &h), 0);
	CHECK_EQ(h.packet_len, a);
	CHECK_EQ(hw_qw_parse(dg + h.packet_len, 2 * a - h.packet_len, HW_QUIC_CID_LEN, &h), 0);
	CHECK_EQ(h.packet_len, a);
}

static void test_retry_tag(void) {
	uint8_t pkt[64], odcid[8], tag[HW_AEAD_TAG];
	size_t n = hex(A4_RETRY, pkt, sizeof(pkt));
	hex(A_DCID, odcid, sizeof(odcid));
	CHECK_EQ(hw_qw_retry_tag(odcid, 8, pkt, n - HW_AEAD_TAG, tag), 0);
	CHECK(memcmp(tag, pkt + n - HW_AEAD_TAG, HW_AEAD_TAG) == 0, "A.4 integrity tag");
	CHECK_EQ(hw_qw_retry_verify(odcid, 8, pkt, n), 1);
	CHECK_EQ(hw_qw_retry_verify(odcid, 7, pkt, n), 0);
	odcid[0] ^= 1;
	CHECK_EQ(hw_qw_retry_verify(odcid, 8, pkt, n), 0);
	odcid[0] ^= 1;
	for (size_t i = 0; i < n; i++) {
		pkt[i] ^= 0x10;
		CHECK_EQ(hw_qw_retry_verify(odcid, 8, pkt, n), 0);
		pkt[i] ^= 0x10;
	}
	CHECK_EQ(hw_qw_retry_verify(odcid, 8, pkt, HW_AEAD_TAG - 1), 0);
	CHECK_EQ(hw_qw_retry_tag(odcid, 21, pkt, n - HW_AEAD_TAG, tag), -1);
	CHECK_EQ(hw_qw_retry_tag(odcid, 8, pkt, HW_QW_RETRY_MAX + 1, tag), -1);

	hw_qw_hdr h;
	CHECK_EQ(hw_qw_parse(pkt, n, HW_QUIC_CID_LEN, &h), 0);
	CHECK_EQ(h.type, HW_QW_RETRY);
	CHECK_EQ(h.version, HW_QUIC_VERSION_1);
	CHECK_EQ(h.dcid_len, 0);
	CHECK_EQ(h.scid_len, 8);
	CHECK_HEX(h.scid, 8, "f067a5502a4262b5");
	CHECK_EQ(h.token_len, 5);
	CHECK(memcmp(h.token, "token", 5) == 0, "token");
	CHECK_EQ(h.packet_len, n);
}

static void test_chacha_short(void) {
	uint8_t secret[32];
	hex(A5_SECRET, secret, sizeof(secret));
	hw_qw_keys k;
	hw_qw_keys_from_secret(&k, HW_TLS_CIPHER_CHACHA20, secret);
	CHECK_HEX(k.key, 32, "c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8");
	CHECK_HEX(k.iv, 12, "e0459b3474bdd0e44a41c144");
	CHECK_HEX(k.hp, 32, "25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4");

	uint8_t sample[16], mask[5];
	hex("5e5cd55c41f69080575d7999c25a5bfb", sample, sizeof(sample));
	CHECK_EQ(hw_qw_hp_mask(&k, sample, mask), 0);
	CHECK_HEX(mask, 5, "aefefe7d03");

	uint8_t pkt[64] = {0};
	hex("4200bff4", pkt, sizeof(pkt));
	pkt[4] = 0x01; // PING
	size_t n = hw_qw_protect(&k, pkt, 1, 3, A5_PN, 1);
	CHECK_EQ(n, 21);
	CHECK_HEX(pkt, 21, A5_PACKET);

	hw_qw_hdr h;
	CHECK_EQ(hw_qw_parse(pkt, n, 0, &h), 0);
	CHECK_EQ(h.type, HW_QW_SHORT);
	CHECK_EQ(h.dcid_len, 0);
	CHECK_EQ(h.pn_offset, 1);
	CHECK_EQ(h.packet_len, 21);
	uint64_t pn = 0;
	uint8_t *payload = NULL;
	size_t payload_len = 0;
	int kp = -1;
	CHECK_EQ(hw_qw_unprotect(&k, pkt, h.packet_len, h.pn_offset, A5_PN - 1, &pn, &payload, &payload_len, &kp), 0);
	CHECK_EQ(pn, A5_PN);
	CHECK_EQ(payload_len, 1);
	CHECK_EQ(payload[0], 0x01);
	CHECK_EQ(kp, 0);
	CHECK_HEX(pkt, 4, "4200bff4");

	// Key update: the next secret is the RFC's ku, its key and iv follow from it, hp stays.
	hw_qw_keys next;
	hw_qw_keys_update(&next, &k);
	CHECK_HEX(next.secret, 32, "1223504755036d556342ee9361d253421a826c9ecdf3c7148684b36b714881f9");
	uint8_t want[32];
	hw_hkdf_expand_label(next.secret, "quic key", NULL, 0, want, 32);
	CHECK(memcmp(next.key, want, 32) == 0, "next key");
	hw_hkdf_expand_label(next.secret, "quic iv", NULL, 0, want, 12);
	CHECK(memcmp(next.iv, want, 12) == 0, "next iv");
	CHECK(memcmp(next.hp, k.hp, 32) == 0, "hp unchanged");
	CHECK_EQ(next.cipher, HW_TLS_CIPHER_CHACHA20);
	// In place gives the same.
	hw_qw_keys same = k;
	hw_qw_keys_update(&same, &same);
	CHECK(memcmp(same.key, next.key, 32) == 0 && memcmp(same.hp, k.hp, 32) == 0, "update in place");

	// A packet sealed under the next generation, with the key phase bit set, opens only with it.
	uint8_t p2[64] = {0};
	p2[0] = 0x44; // short header, key phase 1
	hex("0102030405060708", p2 + 1, 8);
	hex("01000000", p2 + 10, 4); // PING and PADDING
	n = hw_qw_protect(&next, p2, 9, 1, 7, 4);
	CHECK_EQ(n, 9 + 1 + 4 + 16);
	uint8_t p3[64];
	memcpy(p3, p2, n);
	CHECK_EQ(hw_qw_parse(p2, n, 8, &h), 0);
	CHECK_EQ(hw_qw_unprotect(&k, p3, n, 9, 6, &pn, &payload, &payload_len, &kp), -1);
	CHECK_EQ(hw_qw_unprotect(&next, p2, n, 9, 6, &pn, &payload, &payload_len, &kp), 0);
	CHECK_EQ(pn, 7);
	CHECK_EQ(kp, 1);
	CHECK_EQ(payload_len, 4);

	// The same with the mask made first, as a receiver does to read the key phase bit before it
	// chooses the generation: any generation's hp makes it (it is the same key).
	CHECK_EQ(hw_qw_protect(&next, p2, 9, 1, 7, 4), n); // sealed again: the same bytes as before
	uint8_t p4[64], hmask[5];
	memcpy(p4, p2, n);
	CHECK_EQ(hw_qw_hp_mask(&k, p4 + 9 + 4, hmask), 0);
	CHECK_EQ(((p4[0] ^ (hmask[0] & 0x1f)) >> 2) & 1, 1);
	pn = 0;
	kp = -1;
	CHECK_EQ(hw_qw_unprotect_masked(&next, hmask, p4, n, 9, 6, &pn, &payload, &payload_len, &kp), 0);
	CHECK(pn == 7 && kp == 1 && payload_len == 4 && payload[0] == 0x01, "opened with the mask");
	CHECK(p4[0] == 0x44 && p4[9] == 7, "header unmasked in place");
	// A wrong mask is another packet number, which the AEAD refuses.
	memcpy(p4, p2, n);
	hmask[1] ^= 1;
	CHECK_EQ(hw_qw_unprotect_masked(&next, hmask, p4, n, 9, 6, &pn, &payload, &payload_len, &kp), -1);
	hmask[1] ^= 1;
	// Too short to sample, a bad offset and an unknown cipher, before anything is touched.
	memcpy(p4, p2, n);
	CHECK_EQ(hw_qw_unprotect_masked(&next, hmask, p4, 9 + 19, 9, 6, &pn, &payload, &payload_len, &kp), -1);
	CHECK_EQ(hw_qw_unprotect_masked(&next, hmask, p4, n, 0, 6, &pn, &payload, &payload_len, &kp), -1);
	CHECK_EQ(hw_qw_unprotect_masked(&next, hmask, p4, n, n + 1, 6, &pn, &payload, &payload_len, &kp), -1);
	hw_qw_keys unknown = next;
	unknown.cipher = 0;
	CHECK_EQ(hw_qw_unprotect_masked(&unknown, hmask, p4, n, 9, 6, &pn, &payload, &payload_len, &kp), -1);
	CHECK(memcmp(p4, p2, n) == 0, "refusals leave the packet alone");
	CHECK_EQ(hw_qw_unprotect_masked(&next, hmask, p4, n, 9, 6, &pn, &payload, &payload_len, &kp), 0);

	// AES keys from a secret, too: the Initial client secret gives the A.1 keys.
	uint8_t cs[32];
	hex("c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea", cs, sizeof(cs));
	hw_qw_keys_from_secret(&k, HW_TLS_CIPHER_AES128GCM, cs);
	CHECK_HEX(k.key, 16, "1f369613dd76d5467730efcbe3b1a22d");
	CHECK_HEX(k.hp, 16, "9f50449e04a0e810283a1e9933adedd2");

	// Refusals: pn_len outside 1..4, a payload too short to sample.
	CHECK_EQ(hw_qw_protect(&next, p2, 9, 0, 7, 4), 0);
	CHECK_EQ(hw_qw_protect(&next, p2, 9, 5, 7, 4), 0);
	CHECK_EQ(hw_qw_protect(&next, p2, 9, 1, 7, 2), 0);
	hw_qw_keys bad = next;
	bad.cipher = 0x1302;
	CHECK_EQ(hw_qw_protect(&bad, p2, 9, 1, 7, 4), 0);
}

// ---- Headers that are not version 1 Initials ------------------------------------------------

static void test_parse_rules(void) {
	uint8_t b[64] = {0};
	hw_qw_hdr h;
	CHECK_EQ(hw_qw_parse(b, 0, 8, &h), -1);
	// Short header: fixed bit needed, the DCID must fit.
	b[0] = 0x40;
	CHECK_EQ(hw_qw_parse(b, 9, 8, &h), 0);
	CHECK_EQ(h.type, HW_QW_SHORT);
	CHECK_EQ(h.pn_offset, 9);
	CHECK_EQ(hw_qw_parse(b, 8, 8, &h), -1);
	CHECK_EQ(hw_qw_parse(b, 30, 21, &h), -1);
	b[0] = 0x00;
	CHECK_EQ(hw_qw_parse(b, 30, 8, &h), -1);

	// Version 1 long header with the fixed bit clear.
	size_t n = hex("80000000010000"
	               "00"
	               "00",
	               b, sizeof(b)); // Initial, empty CIDs, token 0, length 0
	CHECK_EQ(hw_qw_parse(b, n, 8, &h), -1);
	b[0] = 0xc0;
	CHECK_EQ(hw_qw_parse(b, n, 8, &h), 0);
	CHECK_EQ(h.pn_offset, n);
	CHECK_EQ(h.packet_len, n);
	// Length past the end, token past the end.
	b[n - 1] = 1;
	CHECK_EQ(hw_qw_parse(b, n, 8, &h), -1);
	b[n - 1] = 0;
	b[n - 2] = 5;
	CHECK_EQ(hw_qw_parse(b, n, 8, &h), -1);
	// A Handshake packet has no token field.
	n = hex("e000000001"
	        "0102"
	        "0103"
	        "05"
	        "0000000000",
	        b, sizeof(b));
	CHECK_EQ(n, 15);
	CHECK_EQ(hw_qw_parse(b, n, 8, &h), 0);
	CHECK_EQ(h.type, HW_QW_HANDSHAKE);
	CHECK_EQ(h.dcid_len, 1);
	CHECK_EQ(h.scid_len, 1);
	CHECK_EQ(h.token_len, 0);
	CHECK_EQ(h.pn_offset, 10);
	CHECK_EQ(h.packet_len, 15);
	// A CID over 20 bytes, in any version.
	hex("c000000001"
	    "15",
	    b, sizeof(b));
	CHECK_EQ(hw_qw_parse(b, 40, 8, &h), -1);
	b[1] = 0x1a;
	CHECK_EQ(hw_qw_parse(b, 40, 8, &h), -1);
	// Another version: the invariants only, whatever the fixed bit says.
	n = hex("801a2a3a4a"
	        "02aabb"
	        "03ccddee"
	        "ffffffff",
	        b, sizeof(b));
	CHECK_EQ(hw_qw_parse(b, n, 8, &h), 0);
	CHECK(h.version == 0x1a2a3a4a, "version");
	CHECK_EQ(h.dcid_len, 2);
	CHECK_EQ(h.scid_len, 3);
	CHECK_EQ(h.pn_offset, 0);
	CHECK_EQ(h.packet_len, n);
	// The SCID length byte itself missing.
	CHECK_EQ(hw_qw_parse(b, 8, 8, &h), -1);
	// A Retry shorter than its tag.
	n = hex("f000000001"
	        "00"
	        "00"
	        "0102030405060708090a0b0c0d0e0f",
	        b, sizeof(b));
	CHECK_EQ(hw_qw_parse(b, n, 8, &h), -1);
	CHECK_EQ(hw_qw_parse(b, n + 1, 8, &h), 0);
	CHECK_EQ(h.token_len, 0);
}

// ---- Transport parameters -------------------------------------------------------------------

static void test_tp_roundtrip(void) {
	hw_qw_tp tp, back;
	hw_qw_tp_defaults(&tp);
	CHECK_EQ(tp.max_udp_payload_size, 65527);
	CHECK_EQ(tp.ack_delay_exponent, 3);
	CHECK_EQ(tp.max_ack_delay, 25);
	CHECK_EQ(tp.active_connection_id_limit, 2);
	CHECK_EQ(tp.max_datagram_frame_size, 0);

	// Defaults encode to nothing, and nothing decodes to the defaults.
	uint8_t buf[512];
	CHECK_EQ(hw_qw_tp_encode(&tp, 1, buf, sizeof(buf)), 0);
	CHECK_EQ(hw_qw_tp_decode(buf, 0, 1, &back), 0);
	CHECK(tp_equal(&back, &tp), "empty is the defaults");

	tp.max_idle_timeout = 30000;
	tp.max_udp_payload_size = 1452;
	tp.initial_max_data = 1u << 20;
	tp.initial_max_stream_data_bidi_local = 1;
	tp.initial_max_stream_data_bidi_remote = 64;
	tp.initial_max_stream_data_uni = 16384;
	tp.initial_max_streams_bidi = 1ull << 60;
	tp.initial_max_streams_uni = 3;
	tp.ack_delay_exponent = 20;
	tp.max_ack_delay = 16383;
	tp.active_connection_id_limit = 8;
	tp.max_datagram_frame_size = 65535;
	tp.disable_active_migration = 1;
	tp.has_original_dcid = 1;
	tp.original_dcid_len = 20;
	memset(tp.original_dcid, 0xaa, 20);
	tp.has_initial_scid = 1;
	tp.initial_scid_len = 0; // a zero-length CID is still sent
	tp.has_retry_scid = 1;
	tp.retry_scid_len = 8;
	memset(tp.retry_scid, 0xbb, 8);
	tp.has_reset_token = 1;
	memset(tp.reset_token, 0xcc, 16);

	size_t n = hw_qw_tp_encode(&tp, 1, buf, sizeof(buf));
	CHECK(n > 0, "encoded");
	CHECK_EQ(hw_qw_tp_decode(buf, n, 1, &back), 0);
	CHECK(tp_equal(&back, &tp), "server parameters round-trip");
	// Every shorter buffer is refused, never overrun.
	for (size_t cap = 0; cap < n; cap++) CHECK_EQ(hw_qw_tp_encode(&tp, 1, buf, cap), 0);
	// Every truncation of the encoding either decodes (it ended between two parameters) or is refused.
	for (size_t cut = 0; cut < n; cut++) {
		uint8_t *t = malloc(cut ? cut : 1);
		memcpy(t, buf, cut);
		hw_qw_tp_decode(t, cut, 1, &back);
		free(t);
	}

	// A client sends none of the server's own.
	n = hw_qw_tp_encode(&tp, 0, buf, sizeof(buf));
	CHECK(n > 0, "encoded");
	CHECK_EQ(hw_qw_tp_decode(buf, n, 0, &back), 0);
	CHECK_EQ(back.has_original_dcid, 0);
	CHECK_EQ(back.has_retry_scid, 0);
	CHECK_EQ(back.has_reset_token, 0);
	CHECK_EQ(back.has_initial_scid, 1);
	CHECK_EQ(back.initial_scid_len, 0);
	CHECK_EQ(back.max_datagram_frame_size, 65535);
	CHECK_EQ(back.disable_active_migration, 1);
	CHECK(back.initial_max_streams_bidi == 1ull << 60, "streams");

	// A CID over 20 bytes is not encoded.
	tp.initial_scid_len = 21;
	CHECK_EQ(hw_qw_tp_encode(&tp, 0, buf, sizeof(buf)), 0);
}

// One parameter (hex) on its own: what tp_decode says of it.
static int tp_one(const char *h, int from_server) {
	uint8_t b[128];
	size_t n = hex(h, b, sizeof(b));
	uint8_t *t = malloc(n ? n : 1); // exact size, so ASan sees any overread
	memcpy(t, b, n);
	hw_qw_tp tp;
	int rc = hw_qw_tp_decode(t, n, from_server, &tp);
	free(t);
	return rc;
}

static void test_tp_rules(void) {
	// Boundaries accepted.
	CHECK_EQ(tp_one("030244b0", 0), 0);             // max_udp_payload_size 1200
	CHECK_EQ(tp_one("0a0114", 0), 0);               // ack_delay_exponent 20
	CHECK_EQ(tp_one("0b027fff", 0), 0);             // max_ack_delay 16383
	CHECK_EQ(tp_one("0e0102", 0), 0);               // active_connection_id_limit 2
	CHECK_EQ(tp_one("0808d000000000000000", 0), 0); // initial_max_streams_bidi 2^60
	CHECK_EQ(tp_one("0908d000000000000000", 0), 0);
	CHECK_EQ(tp_one("01048000ea60", 0), 0); // a non-shortest varint value
	// Out of range.
	CHECK_EQ(tp_one("030244af", 0), -1);             // 1199
	CHECK_EQ(tp_one("0a0115", 0), -1);               // 21
	CHECK_EQ(tp_one("0b0480004000", 0), -1);         // 16384
	CHECK_EQ(tp_one("0e0101", 0), -1);               // 1
	CHECK_EQ(tp_one("0e0100", 0), -1);               // 0
	CHECK_EQ(tp_one("0808d000000000000001", 0), -1); // 2^60 + 1
	CHECK_EQ(tp_one("0908d000000000000001", 0), -1);
	// Duplicates, of a known id and of the RFC 9221 one.
	CHECK_EQ(tp_one("0101050101", 0), -1);
	CHECK_EQ(tp_one("200101"
	                "200102",
	                0),
	         -1);
	CHECK_EQ(tp_one("0c00"
	                "0c00",
	                0),
	         -1);
	// Server-only parameters from a client; accepted from a server.
	CHECK_EQ(tp_one("0000", 0), -1);
	CHECK_EQ(tp_one("0000", 1), 0);
	CHECK_EQ(tp_one("021000112233445566778899aabbccddeeff", 0), -1);
	CHECK_EQ(tp_one("021000112233445566778899aabbccddeeff", 1), 0);
	// preferred_address: 192.0.2.1:443, [2001:db8::1]:443, an 8-byte CID and a reset token. Ignored,
	// but held to that shape.
	CHECK_EQ(tp_one("0d31c000020101bb20010db800000000000000000000000101bb080102030405060708"
	                "00112233445566778899aabbccddeeff",
	                1),
	         0);
	CHECK_EQ(tp_one("0d31c000020101bb20010db800000000000000000000000101bb080102030405060708"
	                "00112233445566778899aabbccddeeff",
	                0),
	         -1);
	CHECK_EQ(tp_one("0d3dc000020101bb20010db800000000000000000000000101bb14000102030405060708090a0b0c0d"
	                "0e0f1011121300112233445566778899aabbccddeeff",
	                1),
	         0); // a 20-byte CID
	CHECK_EQ(tp_one("0d3ec000020101bb20010db800000000000000000000000101bb15000102030405060708090a0b0c0d"
	                "0e0f101112131400112233445566778899aabbccddeeff",
	                1),
	         -1); // 21
	CHECK_EQ(tp_one("0d29c000020101bb20010db800000000000000000000000101bb0000112233445566778899aabbccddeeff", 1),
	         -1); // a zero-length CID
	CHECK_EQ(tp_one("0d30c000020101bb20010db800000000000000000000000101bb080102030405060708"
	                "00112233445566778899aabbccddee",
	                1),
	         -1); // a byte short
	CHECK_EQ(tp_one("0d32c000020101bb20010db800000000000000000000000101bb080102030405060708"
	                "00112233445566778899aabbccddeeff00",
	                1),
	         -1); // a byte over
	CHECK_EQ(tp_one("0d0400000000", 1), -1);
	CHECK_EQ(tp_one("0d00", 1), -1);
	CHECK_EQ(tp_one("100101", 0), -1);
	CHECK_EQ(tp_one("100101", 1), 0);
	// Bad lengths.
	CHECK_EQ(tp_one("020f00112233445566778899aabbccddee", 1), -1);             // a 15-byte reset token
	CHECK_EQ(tp_one("0100", 0), -1);                                           // an integer with no bytes
	CHECK_EQ(tp_one("01020500", 0), -1);                                       // a varint that does not fill it
	CHECK_EQ(tp_one("010140", 0), -1);                                         // a varint cut by the length
	CHECK_EQ(tp_one("0c0100", 0), -1);                                         // disable_active_migration has none
	CHECK_EQ(tp_one("0f15000102030405060708090a0b0c0d0e0f1011121314", 0), -1); // a 21-byte CID
	CHECK_EQ(tp_one("0f14000102030405060708090a0b0c0d0e0f10111213", 0), 0);
	CHECK_EQ(tp_one("0105", 0), -1); // length past the end
	CHECK_EQ(tp_one("01", 0), -1);   // no length
	CHECK_EQ(tp_one("40", 0), -1);   // an id cut short
	// Unknown and GREASE (31 * N + 27) ids are skipped, values and all.
	CHECK_EQ(tp_one("1b03aabbcc", 0), 0);
	CHECK_EQ(tp_one("40b600", 0), 0); // 31 * 5 + 27 = 182
	CHECK_EQ(tp_one("1b00"
	                "1b00",
	                0),
	         0);
	CHECK_EQ(tp_one("7fff00", 0), 0);
	uint8_t b[16];
	size_t n = hex("1b03aabbcc"
	               "200401020304",
	               b, sizeof(b));
	hw_qw_tp tp;
	CHECK_EQ(hw_qw_tp_decode(b, n, 0, &tp), -1); // 0x20's value is not a varint of that length
	n = hex("1b03aabbcc"
	        "20048000ffff",
	        b, sizeof(b));
	CHECK_EQ(hw_qw_tp_decode(b, n, 0, &tp), 0);
	CHECK_EQ(tp.max_datagram_frame_size, 0xffff);
}

// ---- Retry tokens, Version Negotiation, stateless reset -------------------------------------

// Addresses by their bytes, network order, without a libc parser.
static struct sockaddr_in v4(const char *addr_hex, uint16_t port) {
	struct sockaddr_in a;
	memset(&a, 0, sizeof(a));
	a.sin_family = AF_INET;
	uint8_t b[4], p[2] = {(uint8_t)(port >> 8), (uint8_t)port};
	hex(addr_hex, b, sizeof(b));
	memcpy(&a.sin_addr, b, 4);
	memcpy(&a.sin_port, p, 2);
	return a;
}

static struct sockaddr_in6 v6(const char *addr_hex, uint16_t port) {
	struct sockaddr_in6 a;
	memset(&a, 0, sizeof(a));
	a.sin6_family = AF_INET6;
	uint8_t b[16], p[2] = {(uint8_t)(port >> 8), (uint8_t)port};
	hex(addr_hex, b, sizeof(b));
	memcpy(&a.sin6_addr, b, 16);
	memcpy(&a.sin6_port, p, 2);
	return a;
}

// The A.2 Initial as the listener sees it, with an SCID of 0x0102030405 so that the Retry's
// DCID can be checked.
static void retry_initial(uint8_t *dg, hw_quic_header *h) {
	memset(dg, 0, 1300);
	size_t n = hex("c000000001"
	               "08" A_DCID "05"
	               "0102030405"
	               "00"
	               "4499",
	               dg, 1300); // Length 1177 fills 1200
	memset(dg + n, 0x5a, 1200 - n);
	CHECK_EQ(hw_quic_parse_header(dg, 1200, h), 0);
	CHECK_EQ(h->dgram_len, 1200);
}

static void test_retry_tokens(void) {
	uint8_t key[HW_QUIC_KEY_LEN], other[HW_QUIC_KEY_LEN];
	memset(key, 0x11, sizeof(key));
	memset(other, 0x22, sizeof(other));
	static const uint8_t scid[HW_QUIC_CID_LEN] = {7, 1, 2, 3, 4, 5, 6, 7};
	uint8_t dg[1300], out[256], odcid[20], odcid_len = 99;
	hw_quic_header h;
	retry_initial(dg, &h);

	struct sockaddr_in peer = v4("c0000201", 4433);
	uint64_t t0 = 1000000;
	size_t n = hw_quic_retry(&h, (struct sockaddr *)&peer, key, t0, scid, out, sizeof(out));
	CHECK(n > 0, "retry made");

	hw_qw_hdr r;
	CHECK_EQ(hw_qw_parse(out, n, HW_QUIC_CID_LEN, &r), 0);
	CHECK_EQ(r.type, HW_QW_RETRY);
	CHECK_EQ(r.version, HW_QUIC_VERSION_1);
	CHECK_EQ(out[0] & 0xf0, 0xf0);
	CHECK_EQ(r.dcid_len, 5);
	CHECK_HEX(r.dcid, 5, "0102030405");
	CHECK_EQ(r.scid_len, HW_QUIC_CID_LEN);
	CHECK(memcmp(r.scid, scid, HW_QUIC_CID_LEN) == 0, "scid");
	CHECK_EQ(hw_qw_retry_verify(h.dcid, h.dcid_len, out, n), 1);
	CHECK_EQ(hw_qw_retry_verify(scid, sizeof(scid), out, n), 0);
	CHECK(r.token_len > 0, "token");
	const uint8_t *tok = r.token;
	size_t tl = r.token_len;

	// The same peer, within the age: accepted, and it names the original DCID.
	CHECK_EQ(hw_quic_token_valid(tok, tl, (struct sockaddr *)&peer, key, t0 + 5000, 30000, odcid, &odcid_len), 1);
	CHECK_EQ(odcid_len, 8);
	CHECK_HEX(odcid, 8, A_DCID);
	CHECK_EQ(hw_quic_token_valid(tok, tl, (struct sockaddr *)&peer, key, t0, 30000, odcid, &odcid_len), 1);
	CHECK_EQ(hw_quic_token_valid(tok, tl, (struct sockaddr *)&peer, key, t0 + 30000, 30000, odcid, &odcid_len), 1);
	// The same address mapped into IPv6 counts as the same peer.
	struct sockaddr_in6 mapped = v6("00000000000000000000ffffc0000201", 4433);
	CHECK_EQ(hw_quic_token_valid(tok, tl, (struct sockaddr *)&mapped, key, t0 + 1, 30000, odcid, &odcid_len), 1);
	// Expired, from the future, another port, another address, another key.
	CHECK_EQ(hw_quic_token_valid(tok, tl, (struct sockaddr *)&peer, key, t0 + 30001, 30000, odcid, &odcid_len), 0);
	CHECK_EQ(odcid_len, 0);
	CHECK_EQ(hw_quic_token_valid(tok, tl, (struct sockaddr *)&peer, key, t0 - 1, 30000, odcid, &odcid_len), 0);
	struct sockaddr_in port = v4("c0000201", 4434);
	CHECK_EQ(hw_quic_token_valid(tok, tl, (struct sockaddr *)&port, key, t0 + 1, 30000, odcid, &odcid_len), 0);
	struct sockaddr_in addr = v4("c0000202", 4433);
	CHECK_EQ(hw_quic_token_valid(tok, tl, (struct sockaddr *)&addr, key, t0 + 1, 30000, odcid, &odcid_len), 0);
	struct sockaddr_in6 six = v6("20010db8000000000000000000000001", 4433);
	CHECK_EQ(hw_quic_token_valid(tok, tl, (struct sockaddr *)&six, key, t0 + 1, 30000, odcid, &odcid_len), 0);
	CHECK_EQ(hw_quic_token_valid(tok, tl, (struct sockaddr *)&peer, other, t0 + 1, 30000, odcid, &odcid_len), 0);
	// Tampered anywhere, cut or lengthened.
	uint8_t copy[256];
	memcpy(copy, tok, tl);
	for (size_t i = 0; i < tl; i++) {
		copy[i] ^= 0x01;
		CHECK_EQ(hw_quic_token_valid(copy, tl, (struct sockaddr *)&peer, key, t0 + 1, 30000, odcid, &odcid_len), 0);
		copy[i] ^= 0x01;
	}
	CHECK_EQ(hw_quic_token_valid(copy, tl, (struct sockaddr *)&peer, key, t0 + 1, 30000, odcid, &odcid_len), 1);
	CHECK_EQ(hw_quic_token_valid(copy, tl - 1, (struct sockaddr *)&peer, key, t0 + 1, 30000, odcid, &odcid_len), 0);
	copy[tl] = 0;
	CHECK_EQ(hw_quic_token_valid(copy, tl + 1, (struct sockaddr *)&peer, key, t0 + 1, 30000, odcid, &odcid_len), 0);
	CHECK_EQ(hw_quic_token_valid(NULL, 0, (struct sockaddr *)&peer, key, t0 + 1, 30000, odcid, &odcid_len), 0);

	// Two Retries for the same Initial carry different tokens (random nonces).
	uint8_t out2[256];
	size_t n2 = hw_quic_retry(&h, (struct sockaddr *)&peer, key, t0, scid, out2, sizeof(out2));
	CHECK_EQ(n2, n);
	CHECK(memcmp(out + (tok - out), out2 + (tok - out), tl) != 0, "fresh nonce per token");

	// An IPv6 peer: bound to its address, not to the IPv4 one that shares its last bytes.
	struct sockaddr_in6 p6 = v6("20010db80000000000000000c0000201", 4433);
	n = hw_quic_retry(&h, (struct sockaddr *)&p6, key, t0, scid, out, sizeof(out));
	CHECK(n > 0, "retry made");
	CHECK_EQ(hw_qw_parse(out, n, HW_QUIC_CID_LEN, &r), 0);
	CHECK_EQ(hw_quic_token_valid(r.token, r.token_len, (struct sockaddr *)&p6, key, t0, 30000, odcid, &odcid_len), 1);
	CHECK_EQ(hw_quic_token_valid(r.token, r.token_len, (struct sockaddr *)&peer, key, t0, 30000, odcid, &odcid_len), 0);

	// What is not answered with a Retry.
	CHECK_EQ(hw_quic_retry(&h, (struct sockaddr *)&peer, key, t0, scid, out, n - 1), 0); // no room
	hw_quic_header small = h;
	small.dgram_len = HW_QUIC_MIN_DGRAM - 1;
	CHECK_EQ(hw_quic_retry(&small, (struct sockaddr *)&peer, key, t0, scid, out, sizeof(out)), 0);
	hw_quic_header hs = h;
	hs.type = 2;
	CHECK_EQ(hw_quic_retry(&hs, (struct sockaddr *)&peer, key, t0, scid, out, sizeof(out)), 0);
	hw_quic_header other_version = h;
	other_version.version = 0x1a2a3a4a;
	CHECK_EQ(hw_quic_retry(&other_version, (struct sockaddr *)&peer, key, t0, scid, out, sizeof(out)), 0);
	CHECK_EQ(hw_quic_retry(&h, (struct sockaddr *)&peer, key, t0, h.dcid, out, sizeof(out)), 0); // SCID = DCID
	struct sockaddr unix_peer = {.sa_family = AF_UNIX};
	CHECK_EQ(hw_quic_retry(&h, &unix_peer, key, t0, scid, out, sizeof(out)), 0);
	CHECK_EQ(hw_quic_token_valid(tok, tl, &unix_peer, key, t0, 30000, odcid, &odcid_len), 0);
}

static void test_version_negotiation(void) {
	uint8_t dg[1300] = {0};
	size_t n = hex("c01a2a3a4a"
	               "08"
	               "0001020304050607"
	               "05"
	               "aabbccddee",
	               dg, sizeof(dg));
	memset(dg + n, 0x33, 1200 - n);
	hw_quic_header h;
	CHECK_EQ(hw_quic_parse_header(dg, 1200, &h), 0);
	CHECK_EQ(h.long_header, 1);
	CHECK(h.version == 0x1a2a3a4a, "version");

	uint8_t out[128];
	size_t vn = hw_quic_version_negotiation(&h, out, sizeof(out));
	CHECK_EQ(vn, 7 + 5 + 8 + 8);
	CHECK_EQ(out[0] & 0xc0, 0xc0);
	CHECK_HEX(out + 1, 4, "00000000");
	CHECK_EQ(out[5], 5);
	CHECK_HEX(out + 6, 5, "aabbccddee"); // the client's SCID is the DCID
	CHECK_EQ(out[11], 8);
	CHECK_HEX(out + 12, 8, "0001020304050607");
	CHECK_HEX(out + 20, 4, "00000001");
	uint32_t grease = (uint32_t)out[24] << 24 | (uint32_t)out[25] << 16 | (uint32_t)out[26] << 8 | out[27];
	CHECK((grease & 0x0f0f0f0f) == 0x0a0a0a0a, "GREASE version %08x", grease);
	hw_qw_hdr p;
	CHECK_EQ(hw_qw_parse(out, vn, HW_QUIC_CID_LEN, &p), 0);
	CHECK_EQ(p.version, 0);

	// No answer for too small a datagram, a Version Negotiation, a short header, no room.
	h.dgram_len = 1199;
	CHECK_EQ(hw_quic_version_negotiation(&h, out, sizeof(out)), 0);
	h.dgram_len = 1200;
	CHECK_EQ(hw_quic_version_negotiation(&h, out, vn - 1), 0);
	CHECK_EQ(hw_quic_version_negotiation(&h, out, vn), vn);
	hw_quic_header vh;
	CHECK_EQ(hw_quic_parse_header(out, vn, &vh), 0);
	vh.dgram_len = 1200;
	CHECK_EQ(hw_quic_version_negotiation(&vh, out, sizeof(out)), 0);
	dg[0] = 0x40;
	CHECK_EQ(hw_quic_parse_header(dg, 1200, &h), 0);
	CHECK_EQ(h.long_header, 0);
	CHECK_EQ(h.dcid_len, HW_QUIC_CID_LEN);
	CHECK_EQ(hw_quic_version_negotiation(&h, out, sizeof(out)), 0);
}

static void test_stateless_reset(void) {
	uint8_t key[HW_QUIC_KEY_LEN], cid[HW_QUIC_CID_LEN] = {3, 9, 9, 9, 9, 9, 9, 9};
	memset(key, 0x44, sizeof(key));
	uint8_t token[HW_QUIC_RESET_LEN], mac[HW_SHA256_LEN];
	hw_qw_reset_token(key, cid, sizeof(cid), token);
	hw_hmac_sha256(key, sizeof(key), cid, sizeof(cid), mac);
	CHECK(memcmp(token, mac, HW_QUIC_RESET_LEN) == 0, "HMAC-SHA-256 truncated");
	uint8_t t2[HW_QUIC_RESET_LEN];
	cid[7] ^= 1;
	hw_qw_reset_token(key, cid, sizeof(cid), t2);
	CHECK(memcmp(token, t2, sizeof(t2)) != 0, "another CID, another token");
	cid[7] ^= 1;

	uint8_t out[2048];
	CHECK_EQ(hw_quic_stateless_reset(cid, key, 0, out, sizeof(out)), 0);
	CHECK_EQ(hw_quic_stateless_reset(cid, key, 21, out, sizeof(out)), 0);
	for (size_t in = 22; in <= 1500; in++) {
		size_t n = hw_quic_stateless_reset(cid, key, in, out, sizeof(out));
		CHECK(n >= 21 && n < in, "reset of %zu for %zu", n, in);
		if (in <= 44) CHECK_EQ(n, in - 1);
		if (in > 44) CHECK(n >= 42 && n <= 73, "reset of %zu for %zu", n, in);
		CHECK_EQ(out[0] & 0xc0, 0x40);
		CHECK(memcmp(out + n - HW_QUIC_RESET_LEN, token, HW_QUIC_RESET_LEN) == 0, "ends in the token");
	}
	CHECK_EQ(hw_quic_stateless_reset(cid, key, 100, out, 20), 0);
	CHECK_EQ(hw_quic_stateless_reset(cid, key, 40, out, 30), 30);
	// The unpredictable bits are not the same twice.
	uint8_t a[64], b[64];
	CHECK_EQ(hw_quic_stateless_reset(cid, key, 44, a, sizeof(a)), 43);
	CHECK_EQ(hw_quic_stateless_reset(cid, key, 44, b, sizeof(b)), 43);
	CHECK(memcmp(a, b, 43 - HW_QUIC_RESET_LEN) != 0, "random bits");
}

// ---- Hostile bytes --------------------------------------------------------------------------

typedef struct {
	const char *hex;
	size_t dcid_short;
	const hw_qw_keys *keys;
	int64_t largest;
} sample_packet;

// Parse (and open, when it parses as a packet that has a packet number) len bytes held in a
// buffer of exactly that size, so ASan stops any read past it. Checks what the parser says
// about where things are.
static void hostile(const uint8_t *src, size_t len, const sample_packet *sp) {
	uint8_t *b = malloc(len ? len : 1);
	memcpy(b, src, len);
	hw_qw_hdr h;
	if (hw_qw_parse(b, len, sp->dcid_short, &h) == 0) {
		CHECK(h.packet_len <= len, "packet_len %zu of %zu", h.packet_len, len);
		CHECK(h.pn_offset <= h.packet_len, "pn_offset");
		CHECK(h.dcid + h.dcid_len <= b + len, "dcid");
		if (h.scid) CHECK(h.scid + h.scid_len <= b + len, "scid");
		if (h.token) CHECK(h.token + h.token_len <= b + len, "token");
		if (h.pn_offset && h.version == HW_QUIC_VERSION_1) {
			uint64_t pn;
			uint8_t *payload;
			size_t pl;
			int kp;
			if (hw_qw_unprotect(sp->keys, b, h.packet_len, h.pn_offset, sp->largest, &pn, &payload, &pl, &kp) == 0) {
				CHECK(payload + pl <= b + h.packet_len, "payload");
			}
		}
	}
	hw_quic_header qh;
	if (hw_quic_parse_header(b, len, &qh) == 0) {
		uint8_t out[256];
		hw_quic_version_negotiation(&qh, out, sizeof(out));
	}
	free(b);
}

static void test_hostile(void) {
	uint8_t dcid[8], secret[32];
	hex(A_DCID, dcid, sizeof(dcid));
	hex(A5_SECRET, secret, sizeof(secret));
	hw_qw_keys c, s, k;
	hw_qw_initial_keys(dcid, sizeof(dcid), &c, &s);
	hw_qw_keys_from_secret(&k, HW_TLS_CIPHER_CHACHA20, secret);
	const sample_packet packets[] = {
	    {A2_PROTECTED, HW_QUIC_CID_LEN, &c, -1},
	    {A3_PROTECTED, HW_QUIC_CID_LEN, &s, 0},
	    {A4_RETRY, HW_QUIC_CID_LEN, &c, -1},
	    {A5_PACKET, 0, &k, A5_PN - 1},
	};
	uint8_t pkt[BUF_MAX];
	for (size_t i = 0; i < HW_ARRAY_LEN(packets); i++) {
		size_t n = hex(packets[i].hex, pkt, sizeof(pkt));
		// Whole, the sample opens; cut anywhere, nothing reads past the cut.
		uint8_t *b = malloc(n);
		memcpy(b, pkt, n);
		hw_qw_hdr h;
		CHECK_EQ(hw_qw_parse(b, n, packets[i].dcid_short, &h), 0);
		free(b);
		for (size_t cut = 0; cut <= n; cut++) hostile(pkt, cut, &packets[i]);
	}
	// Mutations: a few bytes changed, the length changed, the first bytes randomised.
	for (int iter = 0; iter < 6000; iter++) {
		const sample_packet *sp = &packets[rng() % HW_ARRAY_LEN(packets)];
		size_t n = hex(sp->hex, pkt, sizeof(pkt));
		int flips = 1 + (int)(rng() % 4);
		for (int f = 0; f < flips; f++) {
			size_t at = rng() % 3 ? rng() % (n < 40 ? n : 40) : rng() % n; // headers more often
			pkt[at] = (rng() & 1) ? (uint8_t)rng() : (uint8_t)(pkt[at] ^ (1u << (rng() % 8)));
		}
		size_t len = n;
		if (rng() % 4 == 0) len = rng() % (n + 1);
		hostile(pkt, len, sp);
		// The transport parameter decoder on the same bytes.
		hw_qw_tp tp;
		uint8_t *t = malloc(len ? len : 1);
		memcpy(t, pkt, len);
		hw_qw_tp_decode(t, len, (int)(rng() & 1), &tp);
		free(t);
	}
	// Mutated transport parameters.
	uint8_t tpb[64];
	size_t tpl = hex(A2_TP, tpb, sizeof(tpb));
	int ok = 0;
	for (int iter = 0; iter < 4000; iter++) {
		uint8_t m[64];
		memcpy(m, tpb, tpl);
		m[rng() % tpl] = (uint8_t)rng();
		size_t len = rng() % 3 ? tpl : rng() % (tpl + 1);
		uint8_t *t = malloc(len ? len : 1);
		memcpy(t, m, len);
		hw_qw_tp tp;
		ok += hw_qw_tp_decode(t, len, (int)(rng() & 1), &tp) == 0;
		free(t);
	}
	CHECK(ok > 0 && ok < 4000, "some mutations decode, some do not (%d)", ok);
	// Random datagrams.
	for (int iter = 0; iter < 2000; iter++) {
		size_t len = rng() % 200;
		for (size_t i = 0; i < len; i++) pkt[i] = (uint8_t)rng();
		hostile(pkt, len, &packets[rng() % HW_ARRAY_LEN(packets)]);
	}
}

int main(void) {
	RUN(test_varint);
	RUN(test_pn);
	RUN(test_parse_rules);
	RUN(test_tp_roundtrip);
	RUN(test_tp_rules);
	RUN(test_stateless_reset);
	RUN(test_version_negotiation);
	RUN(test_initial_keys);
	RUN(test_client_initial);
	RUN(test_server_initial);
	RUN(test_retry_tag);
	RUN(test_chacha_short);
	RUN(test_retry_tokens);
	RUN(test_hostile);
	return 0;
}
