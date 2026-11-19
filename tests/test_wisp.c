#include "holywisp/hw.h"
#include "holywisp/wisp.h"

#include "test.h"

// The 16-bit little-endian pair (a CONNECT's port) reads and writes exactly two bytes, low first.
static void test_le16(void) {
	static const uint16_t values[] = {0, 1, 0x00FF, 0x0100, 0x01BB, 0x8000, 0xFFFF};
	for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); i++) {
		uint8_t b[4] = {0xA5, 0xA5, 0xA5, 0xA5};
		hw_put_le16(b + 1, values[i]);
		CHECK_EQ(b[1], values[i] & 0xFF);
		CHECK_EQ(b[2], values[i] >> 8);
		CHECK(b[0] == 0xA5 && b[3] == 0xA5, "wrote outside its two bytes for 0x%x", values[i]);
		CHECK_EQ(hw_le16(b + 1), values[i]);
	}
	const uint8_t wire[] = {0x34, 0x12, 0xFF, 0x80};
	CHECK_EQ(hw_le16(wire), 0x1234);
	CHECK_EQ(hw_le16(wire + 2), 0x80FF); // a high bit in either byte is not a sign
}

static void test_header_roundtrip(void) {
	uint8_t hdr[HW_WISP_HEADER_LEN];
	hw_wisp_write_header(hdr, HW_WISP_DATA, 0xDEADBEEF);
	CHECK_EQ(hdr[0], 0x02);
	CHECK_EQ(hdr[1], 0xEF);
	CHECK_EQ(hdr[4], 0xDE);
	hw_wisp_packet p;
	CHECK_EQ(hw_wisp_parse(hdr, sizeof(hdr), &p), 0);
	CHECK_EQ(p.type, HW_WISP_DATA);
	CHECK_EQ(p.stream_id, 0xDEADBEEF);
	CHECK_EQ(p.payload_len, 0);
	CHECK_EQ(hw_wisp_parse(hdr, 4, &p), HW_ERR_INVALID);
}

static void test_connect(void) {
	uint8_t pkt[64];
	size_t n = hw_wisp_build_connect(pkt, sizeof(pkt), 7, HW_STREAM_TCP, 443, "example.org", 11);
	CHECK_EQ(n, 5 + 3 + 11);
	hw_wisp_packet p;
	CHECK_EQ(hw_wisp_parse(pkt, n, &p), 0);
	CHECK_EQ(p.type, HW_WISP_CONNECT);
	CHECK_EQ(p.stream_id, 7);
	hw_wisp_connect c;
	CHECK_EQ(hw_wisp_parse_connect(&p, &c), 0);
	CHECK_EQ(c.stream_type, HW_STREAM_TCP);
	CHECK_EQ(c.port, 443);
	CHECK_EQ(c.host_len, 11);
	CHECK(memcmp(c.host, "example.org", 11) == 0, "host");
	// Little-endian port: 443 = 0x01BB.
	CHECK_EQ(pkt[6], 0xBB);
	CHECK_EQ(pkt[7], 0x01);
	CHECK_EQ(hw_wisp_build_connect(pkt, 10, 7, HW_STREAM_TCP, 443, "example.org", 11), 0);
	p.payload_len = 2;
	CHECK_EQ(hw_wisp_parse_connect(&p, &c), HW_ERR_INVALID);
}

static void test_continue_close(void) {
	uint8_t pkt[16];
	size_t n = hw_wisp_build_continue(pkt, 3, 0x01020304);
	CHECK_EQ(n, 9);
	hw_wisp_packet p;
	hw_wisp_parse(pkt, n, &p);
	CHECK_EQ(p.type, HW_WISP_CONTINUE);
	CHECK_EQ(hw_le32(p.payload), 0x01020304);
	CHECK_EQ(p.payload[0], 0x04);
	n = hw_wisp_build_close(pkt, 3, HW_CLOSE_REFUSED);
	CHECK_EQ(n, 6);
	hw_wisp_parse(pkt, n, &p);
	CHECK_EQ(p.type, HW_WISP_CLOSE);
	CHECK_EQ(p.payload[0], 0x44);
	CHECK_STR(hw_close_reason_str(HW_CLOSE_REFUSED), "connection refused");
	CHECK_STR(hw_wisp_type_str(HW_WISP_CLOSE), "CLOSE");
}

static void test_info_server(void) {
	uint8_t pkt[256];
	size_t n = hw_wisp_build_info(pkt, 2, 1);
	n += hw_wisp_build_extension(pkt + n, sizeof(pkt) - n, HW_EXT_UDP, NULL, 0);
	uint8_t required = 1;
	n += hw_wisp_build_extension(pkt + n, sizeof(pkt) - n, HW_EXT_PASSWORD, &required, 1);
	n += hw_wisp_build_extension(pkt + n, sizeof(pkt) - n, HW_EXT_MOTD, "hi there", 8);
	n += hw_wisp_build_extension(pkt + n, sizeof(pkt) - n, 0x7E, "unknown", 7);
	hw_wisp_packet p;
	CHECK_EQ(hw_wisp_parse(pkt, n, &p), 0);
	CHECK_EQ(p.type, HW_WISP_INFO);
	CHECK_EQ(p.stream_id, 0);
	hw_wisp_info info;
	CHECK_EQ(hw_wisp_parse_info(&p, &info), 0);
	CHECK_EQ(info.major, 2);
	CHECK_EQ(info.minor, 1);
	CHECK(info.has_udp, "udp");
	CHECK(info.has_password, "password");
	CHECK(info.password_required, "required");
	CHECK(!info.has_stream_confirm, "no stream confirm");
	CHECK_EQ(info.motd_len, 8);
	CHECK(memcmp(info.motd, "hi there", 8) == 0, "motd");
	// Truncated extension length must be rejected, not read past the end.
	p.payload_len -= 3;
	CHECK_EQ(hw_wisp_parse_info(&p, &info), HW_ERR_INVALID);
	p.payload_len = 1;
	CHECK_EQ(hw_wisp_parse_info(&p, &info), HW_ERR_INVALID);
}

static void test_info_client_password(void) {
	uint8_t pkt[128];
	size_t n = hw_wisp_build_info(pkt, 2, 1);
	uint8_t meta[] = {5, 'a', 'l', 'i', 'c', 'e', 's', '3', 'c', 'r', '3', 't'};
	n += hw_wisp_build_extension(pkt + n, sizeof(pkt) - n, HW_EXT_PASSWORD, meta, sizeof(meta));
	n += hw_wisp_build_extension(pkt + n, sizeof(pkt) - n, HW_EXT_STREAM_CONFIRM, NULL, 0);
	hw_wisp_packet p;
	hw_wisp_parse(pkt, n, &p);
	hw_wisp_info info;
	CHECK_EQ(hw_wisp_parse_info(&p, &info), 0);
	CHECK(info.has_stream_confirm, "stream confirm");
	CHECK_EQ(info.user_len, 5);
	CHECK(memcmp(info.user, "alice", 5) == 0, "user");
	CHECK_EQ(info.pass_len, 6);
	CHECK(memcmp(info.pass, "s3cr3t", 6) == 0, "pass");
	// Username length claiming more than the metadata holds.
	uint8_t bad[] = {9, 'a'};
	n = hw_wisp_build_info(pkt, 2, 1);
	n += hw_wisp_build_extension(pkt + n, sizeof(pkt) - n, HW_EXT_PASSWORD, bad, sizeof(bad));
	hw_wisp_parse(pkt, n, &p);
	CHECK_EQ(hw_wisp_parse_info(&p, &info), HW_ERR_INVALID);
}

// Lanes: the server's INFO extension 0xE1 (its count, reserved bytes after it skipped), and the
// LANE packet.
static void test_lanes(void) {
	uint8_t pkt[64];
	size_t n = hw_wisp_build_info(pkt, 2, 1);
	uint8_t lanes[3] = {8, 0xaa, 0xbb};
	n += hw_wisp_build_extension(pkt + n, sizeof(pkt) - n, HW_EXT_LANES, lanes, 1);
	n += hw_wisp_build_extension(pkt + n, sizeof(pkt) - n, HW_EXT_UDP, NULL, 0);
	CHECK_EQ(pkt[7], 0xE1);
	CHECK_EQ(hw_le32(pkt + 8), 1);
	CHECK_EQ(pkt[12], 8);
	hw_wisp_packet p;
	CHECK_EQ(hw_wisp_parse(pkt, n, &p), 0);
	hw_wisp_info info;
	CHECK_EQ(hw_wisp_parse_info(&p, &info), 0);
	CHECK_EQ(info.lanes, 8);
	CHECK(info.has_udp, "the extension after it");
	n = hw_wisp_build_info(pkt, 2, 1);
	n += hw_wisp_build_extension(pkt + n, sizeof(pkt) - n, HW_EXT_LANES, lanes, 3);
	CHECK_EQ(hw_wisp_parse(pkt, n, &p), 0);
	CHECK_EQ(hw_wisp_parse_info(&p, &info), 0);
	CHECK_EQ(info.lanes, 8);
	n = hw_wisp_build_info(pkt, 2, 1);
	n += hw_wisp_build_extension(pkt + n, sizeof(pkt) - n, HW_EXT_LANES, NULL, 0); // no count: none
	CHECK_EQ(hw_wisp_parse(pkt, n, &p), 0);
	CHECK_EQ(hw_wisp_parse_info(&p, &info), 0);
	CHECK_EQ(info.lanes, 0);
	n = hw_wisp_build_info(pkt, 2, 1);
	CHECK_EQ(hw_wisp_parse(pkt, n, &p), 0);
	CHECK_EQ(hw_wisp_parse_info(&p, &info), 0);
	CHECK_EQ(info.lanes, 0);

	CHECK_EQ(hw_wisp_build_lane(pkt, 3), HW_WISP_HEADER_LEN + 1);
	static const uint8_t want[] = {0xE1, 0, 0, 0, 0, 3};
	CHECK(memcmp(pkt, want, sizeof(want)) == 0, "LANE bytes");
	CHECK_EQ(hw_wisp_parse(pkt, 6, &p), 0);
	uint8_t idx = 0;
	CHECK_EQ(hw_wisp_parse_lane(&p, &idx), 0);
	CHECK_EQ(idx, 3);
	CHECK_STR(hw_wisp_type_str(HW_WISP_LANE), "LANE");
	pkt[6] = 0x77; // a reserved byte after the index
	CHECK_EQ(hw_wisp_parse(pkt, 7, &p), 0);
	CHECK_EQ(hw_wisp_parse_lane(&p, &idx), 0);
	CHECK_EQ(hw_wisp_parse(pkt, 5, &p), 0); // no index
	CHECK_EQ(hw_wisp_parse_lane(&p, &idx), HW_ERR_INVALID);
	pkt[1] = 1; // not stream 0
	CHECK_EQ(hw_wisp_parse(pkt, 6, &p), 0);
	CHECK_EQ(hw_wisp_parse_lane(&p, &idx), HW_ERR_INVALID);
	hw_wisp_write_header(pkt, HW_WISP_CLOSE, 0); // another type
	CHECK_EQ(hw_wisp_parse(pkt, 6, &p), 0);
	CHECK_EQ(hw_wisp_parse_lane(&p, &idx), HW_ERR_INVALID);
}

// Stream credit: INFO extension 0xE2 (empty from the server, a u32 window from the client, a
// shorter meta as no window, reserved bytes after it skipped) and the CREDIT packet.
static void test_credit(void) {
	uint8_t pkt[64];
	hw_wisp_packet p;
	hw_wisp_info info;
	size_t n = hw_wisp_build_info(pkt, 2, 1);
	n += hw_wisp_build_extension(pkt + n, sizeof(pkt) - n, HW_EXT_CREDIT, NULL, 0);
	n += hw_wisp_build_extension(pkt + n, sizeof(pkt) - n, HW_EXT_UDP, NULL, 0);
	CHECK_EQ(pkt[7], 0xE2);
	CHECK_EQ(hw_le32(pkt + 8), 0);
	CHECK_EQ(hw_wisp_parse(pkt, n, &p), 0);
	CHECK_EQ(hw_wisp_parse_info(&p, &info), 0);
	CHECK(info.has_credit, "server's 0xE2");
	CHECK(!info.has_credit_window, "no window in the server's");
	CHECK(info.has_udp, "the extension after it");

	uint8_t meta[6] = {0x00, 0x00, 0x10, 0x00, 0xaa, 0xbb}; // 1 MiB, then two reserved bytes
	n = hw_wisp_build_info(pkt, 2, 1);
	n += hw_wisp_build_extension(pkt + n, sizeof(pkt) - n, HW_EXT_CREDIT, meta, 6);
	CHECK_EQ(hw_wisp_parse(pkt, n, &p), 0);
	CHECK_EQ(hw_wisp_parse_info(&p, &info), 0);
	CHECK(info.has_credit && info.has_credit_window, "client's 0xE2");
	CHECK_EQ(info.credit_window, 1024 * 1024);
	n = hw_wisp_build_info(pkt, 2, 1);
	n += hw_wisp_build_extension(pkt + n, sizeof(pkt) - n, HW_EXT_CREDIT, meta, 3); // too short for a window
	CHECK_EQ(hw_wisp_parse(pkt, n, &p), 0);
	CHECK_EQ(hw_wisp_parse_info(&p, &info), 0);
	CHECK(info.has_credit && !info.has_credit_window, "3 bytes are no window");
	CHECK_EQ(info.credit_window, 0);
	n = hw_wisp_build_info(pkt, 2, 1);
	CHECK_EQ(hw_wisp_parse(pkt, n, &p), 0);
	CHECK_EQ(hw_wisp_parse_info(&p, &info), 0);
	CHECK(!info.has_credit && !info.has_credit_window, "absent");

	CHECK_EQ(hw_wisp_build_credit(pkt, 7, 0x0102030405060708ull), HW_WISP_HEADER_LEN + 8);
	static const uint8_t want[] = {0xE2, 7, 0, 0, 0, 8, 7, 6, 5, 4, 3, 2, 1};
	CHECK(memcmp(pkt, want, sizeof(want)) == 0, "CREDIT bytes");
	CHECK_EQ(hw_wisp_parse(pkt, 13, &p), 0);
	CHECK_EQ(p.stream_id, 7);
	uint64_t limit = 0;
	CHECK_EQ(hw_wisp_parse_credit(&p, &limit), 0);
	CHECK(limit == 0x0102030405060708ull, "limit %llx", (unsigned long long)limit);
	CHECK_STR(hw_wisp_type_str(HW_WISP_CREDIT), "CREDIT");
	pkt[13] = 0x77; // a reserved byte after the limit
	CHECK_EQ(hw_wisp_parse(pkt, 14, &p), 0);
	CHECK_EQ(hw_wisp_parse_credit(&p, &limit), 0);
	CHECK(limit == 0x0102030405060708ull, "limit with a reserved byte");
	CHECK_EQ(hw_wisp_parse(pkt, 12, &p), 0); // 7 bytes of limit
	CHECK_EQ(hw_wisp_parse_credit(&p, &limit), HW_ERR_INVALID);
	hw_wisp_write_header(pkt, HW_WISP_DATA, 7); // another type
	CHECK_EQ(hw_wisp_parse(pkt, 13, &p), 0);
	CHECK_EQ(hw_wisp_parse_credit(&p, &limit), HW_ERR_INVALID);
	hw_put_le64(pkt, UINT64_MAX);
	CHECK(hw_le64(pkt) == UINT64_MAX, "le64 round trip");
}

// Stream limit: INFO extension 0xE3 (a u32 limit from the server, empty from the client, a
// shorter meta as no limit, reserved bytes after it skipped).
static void test_stream_limit(void) {
	uint8_t pkt[64];
	hw_wisp_packet p;
	hw_wisp_info info;
	uint8_t meta[6] = {0x00, 0x08, 0x00, 0x00, 0xaa, 0xbb}; // 2048, then two reserved bytes
	size_t n = hw_wisp_build_info(pkt, 2, 1);
	n += hw_wisp_build_extension(pkt + n, sizeof(pkt) - n, HW_EXT_STREAM_LIMIT, meta, 6);
	n += hw_wisp_build_extension(pkt + n, sizeof(pkt) - n, HW_EXT_UDP, NULL, 0);
	CHECK_EQ(pkt[7], 0xE3);
	CHECK_EQ(hw_wisp_parse(pkt, n, &p), 0);
	CHECK_EQ(hw_wisp_parse_info(&p, &info), 0);
	CHECK(info.has_stream_limit && info.has_max_streams, "server's 0xE3");
	CHECK_EQ(info.max_streams, 2048);
	CHECK(info.has_udp, "the extension after it");
	meta[0] = meta[1] = 0; // 0: no limit, which is still a limit sent
	n = hw_wisp_build_info(pkt, 2, 1);
	n += hw_wisp_build_extension(pkt + n, sizeof(pkt) - n, HW_EXT_STREAM_LIMIT, meta, 4);
	CHECK_EQ(hw_wisp_parse(pkt, n, &p), 0);
	CHECK_EQ(hw_wisp_parse_info(&p, &info), 0);
	CHECK(info.has_max_streams && info.max_streams == 0, "no limit");
	n = hw_wisp_build_info(pkt, 2, 1);
	n += hw_wisp_build_extension(pkt + n, sizeof(pkt) - n, HW_EXT_STREAM_LIMIT, NULL, 0);
	CHECK_EQ(hw_wisp_parse(pkt, n, &p), 0);
	CHECK_EQ(hw_wisp_parse_info(&p, &info), 0);
	CHECK(info.has_stream_limit && !info.has_max_streams, "client's 0xE3");
	n = hw_wisp_build_info(pkt, 2, 1);
	n += hw_wisp_build_extension(pkt + n, sizeof(pkt) - n, HW_EXT_STREAM_LIMIT, meta, 3);
	CHECK_EQ(hw_wisp_parse(pkt, n, &p), 0);
	CHECK_EQ(hw_wisp_parse_info(&p, &info), 0);
	CHECK(info.has_stream_limit && !info.has_max_streams, "3 bytes are no limit");
	n = hw_wisp_build_info(pkt, 2, 1);
	CHECK_EQ(hw_wisp_parse(pkt, n, &p), 0);
	CHECK_EQ(hw_wisp_parse_info(&p, &info), 0);
	CHECK(!info.has_stream_limit && !info.has_max_streams, "absent");
}

int main(void) {
	RUN(test_le16);
	RUN(test_header_roundtrip);
	RUN(test_connect);
	RUN(test_continue_close);
	RUN(test_info_server);
	RUN(test_info_client_password);
	RUN(test_lanes);
	RUN(test_credit);
	RUN(test_stream_limit);
	return 0;
}
