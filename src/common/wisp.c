/*
 * holywisp/wisp.h implementation.
 */
#include "holywisp/wisp.h"

#include "holywisp/hw.h"

#include <string.h>

int hw_wisp_parse(const uint8_t *data, size_t len, hw_wisp_packet *p) {
	if (len < HW_WISP_HEADER_LEN) return HW_ERR_INVALID;
	p->type = data[0];
	p->stream_id = hw_le32(data + 1);
	p->payload = data + HW_WISP_HEADER_LEN;
	p->payload_len = len - HW_WISP_HEADER_LEN;
	return HW_OK;
}

int hw_wisp_parse_connect(const hw_wisp_packet *p, hw_wisp_connect *out) {
	if (p->payload_len < 3) return HW_ERR_INVALID;
	out->stream_type = p->payload[0];
	out->port = hw_le16(p->payload + 1);
	out->host = (const char *)p->payload + 3;
	out->host_len = p->payload_len - 3;
	return HW_OK;
}

int hw_wisp_parse_info(const hw_wisp_packet *p, hw_wisp_info *out) {
	memset(out, 0, sizeof(*out));
	if (p->payload_len < 2) return HW_ERR_INVALID;
	out->major = p->payload[0];
	out->minor = p->payload[1];
	const uint8_t *d = p->payload + 2;
	size_t left = p->payload_len - 2;
	while (left > 0) {
		if (left < 5) return HW_ERR_INVALID;
		uint8_t id = d[0];
		uint32_t meta_len = hw_le32(d + 1);
		d += 5;
		left -= 5;
		if (meta_len > left) return HW_ERR_INVALID;
		const uint8_t *meta = d;
		switch (id) {
		case HW_EXT_UDP:
			out->has_udp = 1;
			break;
		case HW_EXT_STREAM_CONFIRM:
			out->has_stream_confirm = 1;
			break;
		case HW_EXT_MOTD:
			out->motd = (const char *)meta;
			out->motd_len = meta_len;
			break;
		case HW_EXT_PASSWORD:
			out->has_password = 1;
			if (meta_len == 1) {
				// server -> client: one byte, "required"
				out->password_required = meta[0] != 0;
			} else if (meta_len >= 1) {
				// client -> server: u8 username length, username, password
				size_t ulen = meta[0];
				if (1 + ulen > meta_len) return HW_ERR_INVALID;
				out->user = (const char *)meta + 1;
				out->user_len = ulen;
				out->pass = (const char *)meta + 1 + ulen;
				out->pass_len = meta_len - 1 - ulen;
			}
			break;
		default:
			// Unknown extensions are skipped by design (spec: "ignore extensions you don't know").
			break;
		}
		d += meta_len;
		left -= meta_len;
	}
	return HW_OK;
}

void hw_wisp_write_header(uint8_t out[HW_WISP_HEADER_LEN], uint8_t type, uint32_t stream_id) {
	out[0] = type;
	hw_put_le32(out + 1, stream_id);
}

size_t hw_wisp_build_connect(uint8_t *out, size_t cap, uint32_t stream_id, uint8_t stream_type, uint16_t port,
                             const char *host, size_t host_len) {
	size_t need = HW_WISP_HEADER_LEN + 3 + host_len;
	if (cap < need) return 0;
	hw_wisp_write_header(out, HW_WISP_CONNECT, stream_id);
	out[5] = stream_type;
	hw_put_le16(out + 6, port);
	memcpy(out + 8, host, host_len);
	return need;
}

size_t hw_wisp_build_continue(uint8_t out[HW_WISP_HEADER_LEN + 4], uint32_t stream_id, uint32_t buffer_remaining) {
	hw_wisp_write_header(out, HW_WISP_CONTINUE, stream_id);
	hw_put_le32(out + 5, buffer_remaining);
	return HW_WISP_HEADER_LEN + 4;
}

size_t hw_wisp_build_close(uint8_t out[HW_WISP_HEADER_LEN + 1], uint32_t stream_id, uint8_t reason) {
	hw_wisp_write_header(out, HW_WISP_CLOSE, stream_id);
	out[5] = reason;
	return HW_WISP_HEADER_LEN + 1;
}

size_t hw_wisp_build_info(uint8_t out[HW_WISP_HEADER_LEN + 2], uint8_t major, uint8_t minor) {
	hw_wisp_write_header(out, HW_WISP_INFO, 0);
	out[5] = major;
	out[6] = minor;
	return HW_WISP_HEADER_LEN + 2;
}

size_t hw_wisp_build_extension(uint8_t *out, size_t cap, uint8_t id, const void *meta, uint32_t meta_len) {
	size_t need = 5 + meta_len;
	if (cap < need) return 0;
	out[0] = id;
	hw_put_le32(out + 1, meta_len);
	if (meta_len) memcpy(out + 5, meta, meta_len);
	return need;
}

const char *hw_wisp_type_str(uint8_t type) {
	switch (type) {
	case HW_WISP_CONNECT:
		return "CONNECT";
	case HW_WISP_DATA:
		return "DATA";
	case HW_WISP_CONTINUE:
		return "CONTINUE";
	case HW_WISP_CLOSE:
		return "CLOSE";
	case HW_WISP_INFO:
		return "INFO";
	default:
		return "UNKNOWN";
	}
}

const char *hw_close_reason_str(uint8_t reason) {
	switch (reason) {
	case HW_CLOSE_UNKNOWN:
		return "unknown";
	case HW_CLOSE_VOLUNTARY:
		return "voluntary";
	case HW_CLOSE_NETWORK_ERROR:
		return "network error";
	case HW_CLOSE_INCOMPATIBLE:
		return "incompatible extensions";
	case HW_CLOSE_INVALID_INFO:
		return "invalid stream info";
	case HW_CLOSE_UNREACHABLE:
		return "unreachable host";
	case HW_CLOSE_NO_RESPONSE:
		return "no response";
	case HW_CLOSE_REFUSED:
		return "connection refused";
	case HW_CLOSE_TRANSFER_TIMEOUT:
		return "transfer timeout";
	case HW_CLOSE_BLOCKED:
		return "host blocked";
	case HW_CLOSE_THROTTLED:
		return "throttled";
	case HW_CLOSE_CLIENT_ERROR:
		return "client error";
	case HW_CLOSE_AUTH_BAD_PASSWORD:
		return "bad password";
	case HW_CLOSE_AUTH_BAD_SIGNATURE:
		return "bad signature";
	case HW_CLOSE_AUTH_REQUIRED:
		return "authentication required";
	default:
		return "?";
	}
}
