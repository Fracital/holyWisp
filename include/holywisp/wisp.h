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
	HW_STREAM_UDP = 0x02
};

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
	HW_EXT_STREAM_CONFIRM = 0x05
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

const char *hw_wisp_type_str(uint8_t type);
const char *hw_close_reason_str(uint8_t reason);

#endif
