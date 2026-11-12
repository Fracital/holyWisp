#include "holywisp/hw.h"
#include "holywisp/ws.h"

#include "test.h"

static void roundtrip(uint64_t len, int masked) {
	uint8_t hdr[HW_WS_MAX_HEADER];
	uint8_t mask[4] = {1, 2, 3, 4};
	size_t n = hw_ws_write_header(hdr, 1, HW_WS_BINARY, len, masked ? mask : NULL);
	CHECK_EQ(n, hw_ws_header_len(len, masked));
	hw_ws_frame f;
	CHECK_EQ(hw_ws_parse_header(hdr, n, &f), (int)n);
	CHECK_EQ(f.payload_len, len);
	CHECK_EQ(f.masked, masked);
	CHECK_EQ(f.fin, 1);
	CHECK_EQ(f.opcode, HW_WS_BINARY);
	if (masked) CHECK(memcmp(f.mask, mask, 4) == 0, "mask");
	CHECK_EQ(hw_ws_parse_header(hdr, n - 1, &f), HW_ERR_AGAIN);
}

static void test_header_lengths(void) {
	roundtrip(0, 0);
	roundtrip(125, 0);
	roundtrip(126, 0);
	roundtrip(65535, 0);
	roundtrip(65536, 0);
	roundtrip(1 << 20, 1);
	roundtrip(5, 1);
	uint8_t hdr[HW_WS_MAX_HEADER];
	hw_ws_write_header(hdr, 1, HW_WS_BINARY, 126, NULL);
	CHECK_EQ(hdr[1], 126);
	CHECK_EQ(hdr[2], 0);
	CHECK_EQ(hdr[3], 126);
	hw_ws_write_header(hdr, 1, HW_WS_BINARY, 65536, NULL);
	CHECK_EQ(hdr[1], 127);
	CHECK_EQ(hdr[7], 1);
	CHECK_EQ(hdr[9], 0);
}

static void test_header_rejections(void) {
	hw_ws_frame f;
	uint8_t rsv[] = {0x82 | 0x40, 0x00};
	CHECK_EQ(hw_ws_parse_header(rsv, 2, &f), HW_ERR_PROTOCOL);
	uint8_t frag_ping[] = {0x09, 0x00}; // control frame without FIN
	CHECK_EQ(hw_ws_parse_header(frag_ping, 2, &f), HW_ERR_PROTOCOL);
	uint8_t long_ping[] = {0x89, 126, 0x00, 0x80};
	CHECK_EQ(hw_ws_parse_header(long_ping, 4, &f), HW_ERR_PROTOCOL);
	uint8_t bad_opcode[] = {0x83, 0x00};
	CHECK_EQ(hw_ws_parse_header(bad_opcode, 2, &f), HW_ERR_PROTOCOL);
	uint8_t non_minimal[] = {0x82, 126, 0x00, 0x05};
	CHECK_EQ(hw_ws_parse_header(non_minimal, 4, &f), HW_ERR_PROTOCOL);
	uint8_t huge[] = {0x82, 127, 0x80, 0, 0, 0, 0, 0, 0, 0};
	CHECK_EQ(hw_ws_parse_header(huge, 10, &f), HW_ERR_PROTOCOL);
	uint8_t one[] = {0x82};
	CHECK_EQ(hw_ws_parse_header(one, 1, &f), HW_ERR_AGAIN);
	uint8_t ok_close[] = {0x88, 0x02, 0x03, 0xE8};
	CHECK_EQ(hw_ws_parse_header(ok_close, 4, &f), 2);
	CHECK_EQ(f.opcode, HW_WS_CLOSE);
}

static void test_mask(void) {
	uint8_t mask[4] = {0xAA, 0x55, 0x12, 0x34};
	uint8_t data[1003];
	uint8_t copy[1003];
	for (size_t i = 0; i < sizeof(data); i++) data[i] = copy[i] = (uint8_t)(i * 13 + 1);
	hw_ws_mask(data, sizeof(data), mask, 0);
	for (size_t i = 0; i < sizeof(data); i++) CHECK(data[i] == (copy[i] ^ mask[i & 3]), "masked byte %zu", i);
	hw_ws_mask(data, sizeof(data), mask, 0);
	CHECK(memcmp(data, copy, sizeof(data)) == 0, "unmask restores");
	// Masking in two parts with an offset must equal masking at once.
	hw_ws_mask(data, 7, mask, 0);
	hw_ws_mask(data + 7, sizeof(data) - 7, mask, 7);
	for (size_t i = 0; i < sizeof(data); i++) CHECK(data[i] == (copy[i] ^ mask[i & 3]), "offset byte %zu", i);
	// Every length across the 32-, 8- and 1-byte steps, at every position in the mask cycle and
	// every alignment of the buffer, against the byte-at-a-time definition.
	for (size_t off = 0; off < 4; off++) {
		for (size_t len = 0; len <= 200; len++) {
			for (size_t at = 0; at < 8; at++) {
				for (size_t i = 0; i < len; i++) data[at + i] = copy[i];
				hw_ws_mask(data + at, len, mask, off);
				size_t bad = len;
				for (size_t i = 0; i < len && bad == len; i++) {
					if (data[at + i] != (copy[i] ^ mask[(off + i) & 3])) bad = i;
				}
				CHECK(bad == len, "offset %zu length %zu alignment %zu: byte %zu", off, len, at, bad);
			}
		}
	}
}

static void test_http_request(void) {
	const char *req = "GET /wisp/ HTTP/1.1\r\n"
	                  "Host: example.org:6001\r\n"
	                  "Upgrade: WebSocket\r\n"
	                  "Connection: keep-alive, Upgrade\r\n"
	                  "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
	                  "Sec-WebSocket-Version: 13\r\n"
	                  "Sec-WebSocket-Protocol: Wisp-V2, other\r\n"
	                  "\r\n"
	                  "trailing bytes";
	hw_http_request r;
	int n = hw_http_parse_request((const uint8_t *)req, strlen(req), &r);
	CHECK_EQ(n, (int)(strlen(req) - strlen("trailing bytes")));
	CHECK(r.is_websocket, "upgrade detected");
	CHECK_STR(r.method, "GET");
	CHECK_STR(r.path, "/wisp/");
	CHECK_STR(r.host, "example.org:6001");
	CHECK_STR(r.ws_key, "dGhlIHNhbXBsZSBub25jZQ==");
	CHECK_STR(r.ws_protocol, "Wisp-V2"); // verbatim: the echo has to match what the client sent
	CHECK_EQ(hw_http_parse_request((const uint8_t *)req, 20, &r), HW_ERR_AGAIN);
	const char *plain = "GET /health HTTP/1.1\r\nHost: x\r\n\r\n";
	CHECK_EQ(hw_http_parse_request((const uint8_t *)plain, strlen(plain), &r), (int)strlen(plain));
	CHECK(!r.is_websocket, "plain GET");
	CHECK_STR(r.path, "/health");
	const char *bad = "NOT HTTP\r\n\r\n";
	CHECK_EQ(hw_http_parse_request((const uint8_t *)bad, strlen(bad), &r), HW_ERR_PROTOCOL);
	const char *no_colon = "GET / HTTP/1.1\r\nbroken header\r\n\r\n";
	CHECK_EQ(hw_http_parse_request((const uint8_t *)no_colon, strlen(no_colon), &r), HW_ERR_PROTOCOL);
	// A head that never ends must be rejected once it exceeds the limit.
	static uint8_t big[HW_HTTP_MAX_REQUEST + 1];
	memset(big, 'a', sizeof(big));
	CHECK_EQ(hw_http_parse_request(big, sizeof(big), &r), HW_ERR_PROTOCOL);
}

static int parse(const char *head, hw_http_request *r) {
	return hw_http_parse_request((const uint8_t *)head, strlen(head), r);
}

// The header table is what was sent, or the head is refused. Each case here was a way to make
// the server read a client address other than the one its proxy wrote.
static void test_http_header_table(void) {
	static hw_http_request r;
	char head[HW_HTTP_MAX_REQUEST];
	const char *values[4];
	int cut = -1;

	// Exactly as many headers as the table holds are all kept, in order.
	size_t o = (size_t)snprintf(head, sizeof(head), "GET / HTTP/1.1\r\n");
	for (int i = 0; i < HW_HTTP_MAX_HEADERS - 1; i++) {
		o += (size_t)snprintf(head + o, sizeof(head) - o, "X-J%d: %d\r\n", i, i);
	}
	size_t full = o;
	o += (size_t)snprintf(head + o, sizeof(head) - o, "X-Forwarded-For: 203.0.113.9\r\n\r\n");
	CHECK_EQ(parse(head, &r), (int)o);
	CHECK_EQ(r.header_count, HW_HTTP_MAX_HEADERS);
	CHECK_STR(hw_http_header_get(&r, "x-forwarded-for"), "203.0.113.9");
	CHECK_STR(hw_http_header_get(&r, "X-J46"), "46");
	// One more and the head is refused: a proxy's header after 48 of the client's was dropped.
	snprintf(head + full, sizeof(head) - full, "X-J: 1\r\nX-Forwarded-For: 203.0.113.9\r\n\r\n");
	CHECK_EQ(parse(head, &r), HW_ERR_PROTOCOL);

	// Every instance of a name, in order; the first one alone is not the header.
	const char *twice = "GET / HTTP/1.1\r\nX-Forwarded-For: 6.6.6.6\r\nHost: x\r\n"
	                    "x-forwarded-for:  203.0.113.9, 10.0.0.1 \r\n\r\n";
	CHECK_EQ(parse(twice, &r), (int)strlen(twice));
	CHECK_STR(hw_http_header_get(&r, "X-Forwarded-For"), "6.6.6.6");
	CHECK_EQ(hw_http_header_all(&r, "X-Forwarded-For", values, 4, &cut), 2);
	CHECK_EQ(cut, 0);
	CHECK_STR(values[0], "6.6.6.6");
	CHECK_STR(values[1], "203.0.113.9, 10.0.0.1");
	// More instances than the caller has room for: the count says so, the room is not overrun.
	values[1] = "untouched";
	CHECK_EQ(hw_http_header_all(&r, "X-Forwarded-For", values, 1, &cut), 2);
	CHECK_STR(values[1], "untouched");
	CHECK_EQ(hw_http_header_all(&r, "CF-Connecting-IP", values, 4, &cut), 0);
	CHECK_EQ(cut, 0);

	// A value that does not fit is kept cut, and says so: its end, where the proxy appended the
	// real address, is not there.
	o = (size_t)snprintf(head, sizeof(head), "GET / HTTP/1.1\r\nX-Forwarded-For: 6.6.6.6, ");
	memset(head + o, 'a', 502);
	o += 502;
	o += (size_t)snprintf(head + o, sizeof(head) - o, ", 203.0.113.9\r\nX-Forwarded-For: 10.0.0.1\r\n\r\n");
	CHECK_EQ(parse(head, &r), (int)o);
	CHECK_EQ(hw_http_header_all(&r, "X-Forwarded-For", values, 4, &cut), 2);
	CHECK_EQ(cut, 1);
	CHECK_EQ(r.headers[0].cut, 1);
	CHECK_EQ(r.headers[1].cut, 0);
	CHECK_EQ(strlen(values[0]), sizeof(r.headers[0].value) - 1);
	CHECK(strstr(values[0], "203.0.113.9") == NULL, "the cut value lost its end");
	// One byte under the limit is whole.
	o = (size_t)snprintf(head, sizeof(head), "GET / HTTP/1.1\r\nCookie: ");
	memset(head + o, 'c', sizeof(r.headers[0].value) - 1);
	o += sizeof(r.headers[0].value) - 1;
	o += (size_t)snprintf(head + o, sizeof(head) - o, "\r\n\r\n");
	CHECK_EQ(parse(head, &r), (int)o);
	CHECK_EQ(hw_http_header_all(&r, "Cookie", values, 4, &cut), 1);
	CHECK_EQ(cut, 0);

	// Names are tokens, as sent: nothing is trimmed into a trusted name.
	CHECK_EQ(parse("GET / HTTP/1.1\r\nX-Forwarded-For : 6.6.6.6\r\n\r\n", &r), HW_ERR_PROTOCOL);
	CHECK_EQ(parse("GET / HTTP/1.1\r\nX-Forwarded-For\t: 6.6.6.6\r\n\r\n", &r), HW_ERR_PROTOCOL);
	CHECK_EQ(parse("GET / HTTP/1.1\r\nX Forwarded-For: 6.6.6.6\r\n\r\n", &r), HW_ERR_PROTOCOL);
	CHECK_EQ(parse("GET / HTTP/1.1\r\n: no name\r\n\r\n", &r), HW_ERR_PROTOCOL);
	// A continuation line (obs-fold), with a space or a tab.
	CHECK_EQ(parse("GET / HTTP/1.1\r\nX-A: 1\r\n X-Forwarded-For: 6.6.6.6\r\n\r\n", &r), HW_ERR_PROTOCOL);
	CHECK_EQ(parse("GET / HTTP/1.1\r\nX-Forwarded-For: 6.6.6.6,\r\n\t203.0.113.9\r\n\r\n", &r), HW_ERR_PROTOCOL);
	// A name the table cannot hold whole would be stored as a shorter, different name.
	o = (size_t)snprintf(head, sizeof(head), "GET / HTTP/1.1\r\n");
	memset(head + o, 'n', sizeof(r.headers[0].name));
	o += sizeof(r.headers[0].name);
	snprintf(head + o, sizeof(head) - o, ": 1\r\n\r\n");
	CHECK_EQ(parse(head, &r), HW_ERR_PROTOCOL);
	// A CR inside a value is a line end to some parsers.
	CHECK_EQ(parse("GET / HTTP/1.1\r\nX-A: 1\rX-Forwarded-For: 6.6.6.6\r\n\r\n", &r), HW_ERR_PROTOCOL);
	// And a NUL would end the stored value before the part the proxy appended.
	const char nul[] = "GET / HTTP/1.1\r\nX-Forwarded-For: 6.6.6.6\0, 203.0.113.9\r\n\r\n";
	CHECK_EQ(hw_http_parse_request((const uint8_t *)nul, sizeof(nul) - 1, &r), HW_ERR_PROTOCOL);
	// A value may be empty, and the whitespace around one is not part of it.
	const char *plain = "GET / HTTP/1.1\r\nX-Empty:\r\nX-Pad: \t padded \t\r\n\r\n";
	CHECK_EQ(parse(plain, &r), (int)strlen(plain));
	CHECK_STR(hw_http_header_get(&r, "X-Empty"), "");
	CHECK_STR(hw_http_header_get(&r, "X-Pad"), "padded");
}

// The client writes host and path into the head: neither may carry a line of its own.
static void test_http_upgrade_injection(void) {
	char req[1024];
	const char *key = "dGhlIHNhbXBsZSBub25jZQ==";
	CHECK(hw_http_write_upgrade(req, sizeof(req), "localhost", 6001, "/wisp/", key, NULL, NULL) > 0, "plain");
	CHECK_EQ(hw_http_write_upgrade(req, sizeof(req), "a\r\nX-Forwarded-For: 6.6.6.6", 80, "/", key, NULL, NULL), 0);
	CHECK_EQ(hw_http_write_upgrade(req, sizeof(req), "a\nb", 80, "/", key, NULL, NULL), 0);
	CHECK_EQ(
	    hw_http_write_upgrade(req, sizeof(req), "localhost", 80, "/ HTTP/1.1\r\nX-Evil: 1\r\n\r\n", key, NULL, NULL),
	    0);
	CHECK_EQ(hw_http_write_upgrade(req, sizeof(req), "localhost", 80, "/a\rb", key, NULL, NULL), 0);
	CHECK_EQ(hw_http_write_upgrade(req, sizeof(req), "localhost", 80, "/a\tb", key, NULL, NULL), 0);
	CHECK_EQ(hw_http_write_upgrade(req, sizeof(req), "local\x7fhost", 80, "/", key, NULL, NULL), 0);
	CHECK_EQ(hw_http_write_upgrade(req, sizeof(req), "localhost", 80, "/a b", key, NULL, NULL), 0);
	CHECK_EQ(hw_http_write_upgrade(req, sizeof(req), "", 80, "/", key, NULL, NULL), 0);
	CHECK_EQ(hw_http_write_upgrade(req, sizeof(req), "localhost", 80, "/", key, "wisp\r\nX-Evil: 1", NULL), 0);
	CHECK(hw_http_write_upgrade(req, sizeof(req), "[::1]", 80, "/w?x=%20y", key, "wisp-v2", "X-A: 1\r\n") > 0, "ipv6");
}

static void test_http_upgrade_roundtrip(void) {
	char req[1024];
	size_t n = hw_http_write_upgrade(req, sizeof(req), "localhost", 6001, "/", "dGhlIHNhbXBsZSBub25jZQ==", "wisp-v2",
	                                 NULL);
	CHECK(n > 0, "wrote request");
	hw_http_request r;
	CHECK_EQ(hw_http_parse_request((const uint8_t *)req, n, &r), (int)n);
	CHECK(r.is_websocket, "our own request upgrades");
	CHECK_STR(r.ws_protocol, "wisp-v2");
	const char *resp = "HTTP/1.1 101 Switching Protocols\r\n"
	                   "Upgrade: websocket\r\n"
	                   "Connection: Upgrade\r\n"
	                   "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"
	                   "Sec-WebSocket-Protocol: wisp-v2\r\n"
	                   "\r\n";
	char proto[32];
	CHECK_EQ(hw_http_parse_upgrade_response((const uint8_t *)resp, strlen(resp), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", proto,
	                                        sizeof(proto)),
	         (int)strlen(resp));
	CHECK_STR(proto, "wisp-v2");
	CHECK_EQ(hw_http_parse_upgrade_response((const uint8_t *)resp, strlen(resp), "wrong", proto, sizeof(proto)),
	         HW_ERR_PROTOCOL);
	const char *denied = "HTTP/1.1 426 Upgrade Required\r\n\r\n";
	CHECK_EQ(hw_http_parse_upgrade_response((const uint8_t *)denied, strlen(denied), "x", proto, sizeof(proto)),
	         HW_ERR_PROTOCOL);
	CHECK_EQ(hw_http_parse_upgrade_response((const uint8_t *)resp, 10, "x", proto, sizeof(proto)), HW_ERR_AGAIN);
}

int main(void) {
	RUN(test_header_lengths);
	RUN(test_header_rejections);
	RUN(test_mask);
	RUN(test_http_request);
	RUN(test_http_header_table);
	RUN(test_http_upgrade_injection);
	RUN(test_http_upgrade_roundtrip);
	return 0;
}
