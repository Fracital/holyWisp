/*
 * holywisp/ws.h - WebSocket (RFC 6455) framing and the HTTP/1.1 upgrade handshake.
 *
 * Pure functions over byte ranges; no I/O. The server and client wrap them around their sockets.
 */
#ifndef HOLYWISP_WS_H
#define HOLYWISP_WS_H

#include <stddef.h>
#include <stdint.h>

enum hw_ws_opcode {
	HW_WS_CONTINUATION = 0x0,
	HW_WS_TEXT = 0x1,
	HW_WS_BINARY = 0x2,
	HW_WS_CLOSE = 0x8,
	HW_WS_PING = 0x9,
	HW_WS_PONG = 0xA
};

#define HW_WS_MAX_HEADER 14 // 2 + 8 (64-bit length) + 4 (mask)
#define HW_WS_GUID       "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
#define HW_WS_ACCEPT_LEN 28 // base64 of 20 bytes, without NUL

typedef struct hw_ws_frame {
	uint8_t fin;
	uint8_t rsv;
	uint8_t opcode;
	uint8_t masked;
	uint8_t mask[4];
	uint64_t payload_len;
	size_t header_len;
} hw_ws_frame;

// Parse a frame header. Returns header_len (> 0) when the whole header is present, HW_ERR_AGAIN
// when more bytes are needed, HW_ERR_PROTOCOL when the header is invalid (rsv bits, control frame
// too long or fragmented, 64-bit length with the high bit set).
int hw_ws_parse_header(const uint8_t *data, size_t len, hw_ws_frame *f);
// XOR data with the mask, starting at `offset` into the mask cycle (for payloads arriving in parts).
void hw_ws_mask(uint8_t *data, size_t len, const uint8_t mask[4], size_t offset);
size_t hw_ws_header_len(uint64_t payload_len, int masked);
// Write a header for a payload of payload_len bytes; mask NULL = unmasked. Returns bytes written.
size_t hw_ws_write_header(uint8_t out[HW_WS_MAX_HEADER], int fin, uint8_t opcode, uint64_t payload_len,
                          const uint8_t *mask);

// Sec-WebSocket-Accept for a Sec-WebSocket-Key; out gets 28 chars + NUL.
void hw_ws_accept_key(const char *key, char out[HW_WS_ACCEPT_LEN + 1]);

// An HTTP/1.1 request head: the request line, the WebSocket fields, and every header (so the
// server can look up whichever proxy headers it was told to trust). The table holds the head as
// it was sent or the head is refused: a server that reads a client's address out of these
// headers must see every one of them, in order, or none.
#define HW_HTTP_MAX_REQUEST 8192
#define HW_HTTP_MAX_HEADERS 48
typedef struct hw_http_header {
	char name[64];
	char value[512];
	int cut; // the value was longer than this and its end is missing
} hw_http_header;

typedef struct hw_http_request {
	char method[8];
	char path[512];
	char host[256];
	char ws_key[64];
	char ws_protocol[64]; // first Sec-WebSocket-Protocol token, verbatim (it is echoed as sent)
	int is_websocket;     // Upgrade: websocket + Connection: upgrade + Sec-WebSocket-Version: 13 + key
	hw_http_header headers[HW_HTTP_MAX_HEADERS];
	int header_count; // every header of the head, in the order they were sent
} hw_http_request;

// Case-insensitive lookup; NULL when absent. Repeated headers: the first one. Not for a header
// whose every instance matters (a forwarded-for list): that is hw_http_header_all.
const char *hw_http_header_get(const hw_http_request *req, const char *name);
// Every instance of a header, in the order they were sent: up to cap of them in values, and the
// number there are as the result (more than cap means values does not hold them all). *cut is 1
// when the value of any instance, stored or not, was cut, and 0 otherwise: a list read from a cut
// value is missing its end, which for a forwarded-for list is the part the proxy wrote.
int hw_http_header_all(const hw_http_request *req, const char *name, const char **values, int cap, int *cut);

// Parse a request head. Returns the bytes consumed (through the blank line) when complete,
// HW_ERR_AGAIN when the head is not all there, HW_ERR_PROTOCOL when it is malformed. Malformed
// includes everything that would make the table differ from what was sent: more than
// HW_HTTP_MAX_HEADERS headers, a header name that is empty, longer than the table holds or not a
// token (so no whitespace before the colon), a continuation line (obs-fold) and a NUL or a bare
// CR inside a value. A value that is too long is kept, cut, and marked (hw_http_header.cut).
int hw_http_parse_request(const uint8_t *data, size_t len, hw_http_request *req);

// Client side: write the upgrade request. extra is NULL or raw "Name: value\r\n" lines appended
// verbatim. Returns bytes written, 0 when cap is too small, and 0 when host, path or protocol
// holds a space, a control byte (CR and LF among them) or nothing at all: written into the head,
// a CR LF ends the line and what follows it is a header that whoever supplied the string chose.
size_t hw_http_write_upgrade(char *out, size_t cap, const char *host, uint16_t port, const char *path,
                             const char key[25], const char *protocol, const char *extra);
// Client side: parse the 101 response. Returns bytes consumed, HW_ERR_AGAIN, or HW_ERR_PROTOCOL
// (including a non-101 status or a wrong accept key). protocol receives the echoed subprotocol.
int hw_http_parse_upgrade_response(const uint8_t *data, size_t len, const char *expected_accept, char *protocol,
                                   size_t protocol_cap);

#endif
