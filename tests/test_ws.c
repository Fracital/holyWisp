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
	RUN(test_http_upgrade_roundtrip);
	return 0;
}
