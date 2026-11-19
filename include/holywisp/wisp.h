/*
 * holywisp/wisp.h - Wisp v1/v2 packet codec (https://github.com/MercuryWorkshop/wisp-protocol).
 *
 * A packet is 1 byte type, 4 bytes little-endian stream id, payload. Pure functions, no I/O.
 */
#ifndef HOLYWISP_WISP_H
#define HOLYWISP_WISP_H

#include <stddef.h>
#include <stdint.h>

#define HW_WISP_HEADER_LEN  5
#define HW_WISP_MAJOR       2
#define HW_WISP_MINOR       1
#define HW_WISP_V2_PROTOCOL "wisp-v2"

enum hw_wisp_type {
	HW_WISP_CONNECT = 0x01,
	HW_WISP_DATA = 0x02,
	HW_WISP_CONTINUE = 0x03,
	HW_WISP_CLOSE = 0x04,
	HW_WISP_INFO = 0x05
};

enum hw_stream_type {
	HW_STREAM_TCP = 0x01,
	HW_STREAM_UDP = 0x02,
	HW_STREAM_TERM = 0x03 // Twisp: a PTY running the command named in the hostname field
};

// Twisp resize: payload rows(u16 LE) cols(u16 LE).
#define HW_WISP_TWISP_RESIZE 0xF0
// Lanes (docs/webtransport.md, "Lanes"): the first packet of each extra WebTransport stream a
// client opens, on stream 0, payload index(u8). Never valid anywhere else (an unknown type there).
#define HW_WISP_LANE 0xE1
// Stream credit (a byte window per TCP or Twisp stream toward the client): client -> server,
// payload limit(u64 LE), the total DATA payload bytes the server may have sent on the stream from
// its start. Bytes after it are reserved. Only on a session where both INFOs named HW_EXT_CREDIT.
#define HW_WISP_CREDIT 0xE2
// The smallest initial window: a client that names a smaller one gets this.
#define HW_WISP_CREDIT_MIN 16384

enum hw_close_reason {
	HW_CLOSE_UNKNOWN = 0x01,
	HW_CLOSE_VOLUNTARY = 0x02,
	HW_CLOSE_NETWORK_ERROR = 0x03,
	HW_CLOSE_INCOMPATIBLE = 0x04,
	// server only
	HW_CLOSE_INVALID_INFO = 0x41,
	HW_CLOSE_UNREACHABLE = 0x42,
	HW_CLOSE_NO_RESPONSE = 0x43,
	HW_CLOSE_REFUSED = 0x44,
	HW_CLOSE_TRANSFER_TIMEOUT = 0x47,
	HW_CLOSE_BLOCKED = 0x48,
	HW_CLOSE_THROTTLED = 0x49,
	// client only
	HW_CLOSE_CLIENT_ERROR = 0x81,
	// extensions
	HW_CLOSE_AUTH_BAD_PASSWORD = 0xc0,
	HW_CLOSE_AUTH_BAD_SIGNATURE = 0xc1,
	HW_CLOSE_AUTH_REQUIRED = 0xc2
};

enum hw_wisp_extension {
	HW_EXT_UDP = 0x01,
	HW_EXT_PASSWORD = 0x02,
	HW_EXT_CERTIFICATE = 0x03,
	HW_EXT_MOTD = 0x04,
	HW_EXT_STREAM_CONFIRM = 0x05,
	// Lanes, server -> client over WebTransport: meta lanes(u8), the most a session may have with
	// lane 0 included (0 or 1: none); further bytes are reserved.
	HW_EXT_LANES = 0xE1,
	// Stream credit. Server -> client: meta empty (any bytes are reserved). Client -> server, only
	// when the server's INFO had it: meta initial_window(u32 LE), further bytes reserved; a meta
	// under 4 bytes is as if the extension were absent.
	HW_EXT_CREDIT = 0xE2,
	// Stream limit (docs/extensions.md). Server -> client: meta max_streams(u32 LE), the most
	// streams the connection may have open at once, 0 for no limit; further bytes are reserved, and
	// a meta under 4 bytes is as if the extension were absent. Client -> server: meta empty (any
	// bytes are reserved).
	HW_EXT_STREAM_LIMIT = 0xE3
};

typedef struct hw_wisp_packet {
	uint8_t type;
	uint32_t stream_id;
	const uint8_t *payload;
	size_t payload_len;
} hw_wisp_packet;

typedef struct hw_wisp_connect {
	uint8_t stream_type;
	uint16_t port;
	const char *host; // not NUL-terminated
	size_t host_len;
} hw_wisp_connect;

// Everything an INFO packet can tell us (either direction).
typedef struct hw_wisp_info {
	uint8_t major;
	uint8_t minor;
	int has_udp;
	int has_stream_confirm;
	int has_password;      // extension present
	int password_required; // server->client meta byte
	const char *user;      // client->server, not NUL-terminated
	size_t user_len;
	const char *pass;
	size_t pass_len;
	const char *motd; // server->client
	size_t motd_len;
	int lanes;              // server->client HW_EXT_LANES: lanes offered, lane 0 included; 0 when absent
	int has_credit;         // HW_EXT_CREDIT present, whatever its meta
	int has_credit_window;  // ... with an initial window (client->server: a meta of 4 bytes or more)
	uint32_t credit_window; // that window as sent, 0 without one
	int has_stream_limit;   // HW_EXT_STREAM_LIMIT present, whatever its meta
	int has_max_streams;    // ... with a limit (server->client: a meta of 4 bytes or more)
	uint32_t max_streams;   // that limit as sent (0: none), 0 without one
} hw_wisp_info;

static inline uint32_t hw_le32(const uint8_t *p) {
	return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}
static inline uint16_t hw_le16(const uint8_t *p) {
	return (uint16_t)(p[0] | p[1] << 8);
}
static inline void hw_put_le32(uint8_t *p, uint32_t v) {
	p[0] = (uint8_t)v;
	p[1] = (uint8_t)(v >> 8);
	p[2] = (uint8_t)(v >> 16);
	p[3] = (uint8_t)(v >> 24);
}
static inline uint64_t hw_le64(const uint8_t *p) {
	return (uint64_t)hw_le32(p) | (uint64_t)hw_le32(p + 4) << 32;
}
static inline void hw_put_le64(uint8_t *p, uint64_t v) {
	hw_put_le32(p, (uint32_t)v);
	hw_put_le32(p + 4, (uint32_t)(v >> 32));
}
static inline void hw_put_le16(uint8_t *p, uint16_t v) {
	p[0] = (uint8_t)v;
	p[1] = (uint8_t)(v >> 8);
}

// 0 on success, HW_ERR_INVALID when len < 5. payload points into data.
int hw_wisp_parse(const uint8_t *data, size_t len, hw_wisp_packet *p);
int hw_wisp_parse_connect(const hw_wisp_packet *p, hw_wisp_connect *out);
// Accepts both directions; unknown extensions are skipped. HW_ERR_INVALID on truncation.
int hw_wisp_parse_info(const hw_wisp_packet *p, hw_wisp_info *out);

void hw_wisp_write_header(uint8_t out[HW_WISP_HEADER_LEN], uint8_t type, uint32_t stream_id);
// Builders return bytes written, 0 when cap is too small.
size_t hw_wisp_build_connect(uint8_t *out, size_t cap, uint32_t stream_id, uint8_t stream_type, uint16_t port,
                             const char *host, size_t host_len);
size_t hw_wisp_build_continue(uint8_t out[HW_WISP_HEADER_LEN + 4], uint32_t stream_id, uint32_t buffer_remaining);
size_t hw_wisp_build_close(uint8_t out[HW_WISP_HEADER_LEN + 1], uint32_t stream_id, uint8_t reason);
// INFO header (type, stream 0, major, minor); append extensions with hw_wisp_build_extension.
size_t hw_wisp_build_info(uint8_t out[HW_WISP_HEADER_LEN + 2], uint8_t major, uint8_t minor);
size_t hw_wisp_build_extension(uint8_t *out, size_t cap, uint8_t id, const void *meta, uint32_t meta_len);
// LANE: type HW_WISP_LANE, stream 0, the index. Returns HW_WISP_HEADER_LEN + 1.
size_t hw_wisp_build_lane(uint8_t out[HW_WISP_HEADER_LEN + 1], uint8_t index);
// The index of a LANE packet: 0, or HW_ERR_INVALID when p is not one (another type, a stream other
// than 0, no index). Bytes after the index are reserved and ignored.
int hw_wisp_parse_lane(const hw_wisp_packet *p, uint8_t *index);
// CREDIT: type HW_WISP_CREDIT, the stream, limit as u64 LE. Returns HW_WISP_HEADER_LEN + 8.
size_t hw_wisp_build_credit(uint8_t out[HW_WISP_HEADER_LEN + 8], uint32_t stream_id, uint64_t limit);
// The limit a CREDIT packet carries: 0, or HW_ERR_INVALID when p is not one (another type, a
// payload under 8 bytes). Any stream id is taken; whether the packet applies to it is the
// receiver's question. Bytes after the limit are reserved and ignored.
int hw_wisp_parse_credit(const hw_wisp_packet *p, uint64_t *limit);

const char *hw_wisp_type_str(uint8_t type);
const char *hw_close_reason_str(uint8_t reason);

#endif
