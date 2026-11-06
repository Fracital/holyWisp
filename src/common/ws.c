/*
 * holywisp/ws.h implementation.
 */
#include "holywisp/ws.h"

#include "holywisp/base64.h"
#include "holywisp/hw.h"
#include "holywisp/sha1.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

// ---------------------------------------------------------------------------------- framing

int hw_ws_parse_header(const uint8_t *data, size_t len, hw_ws_frame *f) {
	if (len < 2) return HW_ERR_AGAIN;
	f->fin = (data[0] & 0x80) != 0;
	f->rsv = (data[0] >> 4) & 0x7;
	f->opcode = data[0] & 0x0F;
	f->masked = (data[1] & 0x80) != 0;
	uint8_t code = data[1] & 0x7F;
	size_t hlen = 2;
	if (code == 126) hlen += 2;
	if (code == 127) hlen += 8;
	if (f->masked) hlen += 4;
	if (len < hlen) return HW_ERR_AGAIN;

	if (f->rsv != 0) return HW_ERR_PROTOCOL; // no extensions negotiated
	if (code <= 125) {
		f->payload_len = code;
	} else if (code == 126) {
		f->payload_len = (uint64_t)data[2] << 8 | data[3];
		if (f->payload_len < 126) return HW_ERR_PROTOCOL; // not minimally encoded
	} else {
		if (data[2] & 0x80) return HW_ERR_PROTOCOL;
		f->payload_len = 0;
		for (int i = 0; i < 8; i++) f->payload_len = f->payload_len << 8 | data[2 + i];
		if (f->payload_len < 65536) return HW_ERR_PROTOCOL;
	}
	int control = f->opcode >= 0x8;
	if (control && (!f->fin || f->payload_len > 125)) return HW_ERR_PROTOCOL;
	if (f->opcode > 0x2 && f->opcode < 0x8) return HW_ERR_PROTOCOL;
	if (f->opcode > 0xA) return HW_ERR_PROTOCOL;
	if (f->masked) memcpy(f->mask, data + hlen - 4, 4);
	f->header_len = hlen;
	return (int)hlen;
}

void hw_ws_mask(uint8_t *data, size_t len, const uint8_t mask[4], size_t offset) {
	size_t i = 0;
	// Align to the mask cycle, then XOR 8 bytes at a time with a rotated 64-bit key.
	while (i < len && ((offset + i) & 3) != 0) {
		data[i] ^= mask[(offset + i) & 3];
		i++;
	}
	if (len - i >= 8) {
		uint64_t key = 0;
		for (int k = 7; k >= 0; k--) key = key << 8 | mask[k & 3];
		while (len - i >= 8) {
			uint64_t v;
			memcpy(&v, data + i, 8);
			v ^= key;
			memcpy(data + i, &v, 8);
			i += 8;
		}
	}
	while (i < len) {
		data[i] ^= mask[(offset + i) & 3];
		i++;
	}
}

size_t hw_ws_header_len(uint64_t payload_len, int masked) {
	size_t n = 2;
	if (payload_len > 65535) {
		n += 8;
	} else if (payload_len > 125) {
		n += 2;
	}
	return n + (masked ? 4 : 0);
}

size_t hw_ws_write_header(uint8_t out[HW_WS_MAX_HEADER], int fin, uint8_t opcode, uint64_t payload_len,
                          const uint8_t *mask) {
	out[0] = (uint8_t)((fin ? 0x80 : 0) | (opcode & 0x0F));
	size_t n = 2;
	if (payload_len <= 125) {
		out[1] = (uint8_t)payload_len;
	} else if (payload_len <= 65535) {
		out[1] = 126;
		out[2] = (uint8_t)(payload_len >> 8);
		out[3] = (uint8_t)payload_len;
		n = 4;
	} else {
		out[1] = 127;
		for (int i = 0; i < 8; i++) out[2 + i] = (uint8_t)(payload_len >> (8 * (7 - i)));
		n = 10;
	}
	if (mask) {
		out[1] |= 0x80;
		memcpy(out + n, mask, 4);
		n += 4;
	}
	return n;
}

void hw_ws_accept_key(const char *key, char out[HW_WS_ACCEPT_LEN + 1]) {
	char cat[128];
	snprintf(cat, sizeof(cat), "%s%s", key, HW_WS_GUID);
	uint8_t digest[HW_SHA1_LEN];
	hw_sha1(cat, strlen(cat), digest);
	hw_base64_encode(digest, sizeof(digest), out, HW_WS_ACCEPT_LEN + 1);
}

// ---------------------------------------------------------------------------------- HTTP

// Find "\r\n\r\n"; returns the length through it or 0.
static size_t find_head_end(const uint8_t *data, size_t len) {
	for (size_t i = 3; i < len; i++) {
		if (data[i - 3] == '\r' && data[i - 2] == '\n' && data[i - 1] == '\r' && data[i] == '\n') return i + 1;
	}
	return 0;
}

static void copy_trimmed(char *dst, size_t cap, const char *src, size_t n) {
	while (n > 0 && isspace((unsigned char)src[0])) {
		src++;
		n--;
	}
	while (n > 0 && isspace((unsigned char)src[n - 1])) n--;
	if (n >= cap) n = cap - 1;
	memcpy(dst, src, n);
	dst[n] = '\0';
}

// Comma-separated token list contains `want` (case-insensitive)?
static int token_list_has(const char *list, const char *want) {
	size_t wl = strlen(want);
	const char *p = list;
	while (*p) {
		while (*p == ' ' || *p == ',' || *p == '\t') p++;
		const char *start = p;
		while (*p && *p != ',') p++;
		size_t n = (size_t)(p - start);
		while (n > 0 && isspace((unsigned char)start[n - 1])) n--;
		if (n == wl && strncasecmp(start, want, wl) == 0) return 1;
	}
	return 0;
}

static void first_token_lower(char *dst, size_t cap, const char *list) {
	while (*list == ' ' || *list == '\t') list++;
	size_t n = 0;
	while (list[n] && list[n] != ',' && !isspace((unsigned char)list[n]) && n + 1 < cap) {
		dst[n] = (char)tolower((unsigned char)list[n]);
		n++;
	}
	dst[n] = '\0';
}

int hw_http_parse_request(const uint8_t *data, size_t len, hw_http_request *req) {
	size_t head = find_head_end(data, len);
	if (head == 0) return len >= HW_HTTP_MAX_REQUEST ? HW_ERR_PROTOCOL : HW_ERR_AGAIN;
	if (head > HW_HTTP_MAX_REQUEST) return HW_ERR_PROTOCOL;
	memset(req, 0, sizeof(*req));

	const char *p = (const char *)data;
	const char *end = p + head;
	// Request line: METHOD SP PATH SP HTTP/1.1
	const char *eol = memchr(p, '\n', (size_t)(end - p));
	if (!eol) return HW_ERR_PROTOCOL;
	const char *sp1 = memchr(p, ' ', (size_t)(eol - p));
	if (!sp1) return HW_ERR_PROTOCOL;
	const char *sp2 = memchr(sp1 + 1, ' ', (size_t)(eol - sp1 - 1));
	if (!sp2) return HW_ERR_PROTOCOL;
	copy_trimmed(req->method, sizeof(req->method), p, (size_t)(sp1 - p));
	copy_trimmed(req->path, sizeof(req->path), sp1 + 1, (size_t)(sp2 - sp1 - 1));
	if (strncmp(sp2 + 1, "HTTP/1.1", 8) != 0 && strncmp(sp2 + 1, "HTTP/1.0", 8) != 0) return HW_ERR_PROTOCOL;
	if (!req->method[0] || !req->path[0]) return HW_ERR_PROTOCOL;

	int upgrade = 0, connection = 0, version13 = 0;
	p = eol + 1;
	while (p < end) {
		eol = memchr(p, '\n', (size_t)(end - p));
		if (!eol) break;
		size_t line_len = (size_t)(eol - p);
		if (line_len > 0 && p[line_len - 1] == '\r') line_len--;
		if (line_len == 0) break;
		const char *colon = memchr(p, ':', line_len);
		if (!colon) return HW_ERR_PROTOCOL;
		size_t name_len = (size_t)(colon - p);
		const char *value = colon + 1;
		size_t value_len = line_len - name_len - 1;
		char val[512];
		copy_trimmed(val, sizeof(val), value, value_len);
		if (req->header_count < HW_HTTP_MAX_HEADERS) {
			hw_http_header *h = &req->headers[req->header_count++];
			copy_trimmed(h->name, sizeof(h->name), p, name_len);
			memcpy(h->value, val, sizeof(val));
		}

		if (name_len == 4 && strncasecmp(p, "Host", 4) == 0) {
			copy_trimmed(req->host, sizeof(req->host), val, strlen(val));
		} else if (name_len == 7 && strncasecmp(p, "Upgrade", 7) == 0) {
			upgrade = token_list_has(val, "websocket");
		} else if (name_len == 10 && strncasecmp(p, "Connection", 10) == 0) {
			connection = token_list_has(val, "upgrade");
		} else if (name_len == 17 && strncasecmp(p, "Sec-WebSocket-Key", 17) == 0) {
			copy_trimmed(req->ws_key, sizeof(req->ws_key), val, strlen(val));
		} else if (name_len == 21 && strncasecmp(p, "Sec-WebSocket-Version", 21) == 0) {
			version13 = token_list_has(val, "13");
		} else if (name_len == 22 && strncasecmp(p, "Sec-WebSocket-Protocol", 22) == 0) {
			first_token_lower(req->ws_protocol, sizeof(req->ws_protocol), val);
		}
		p = eol + 1;
	}
	req->is_websocket = upgrade && connection && version13 && req->ws_key[0] && strcmp(req->method, "GET") == 0;
	return (int)head;
}

const char *hw_http_header_get(const hw_http_request *req, const char *name) {
	for (int i = 0; i < req->header_count; i++) {
		if (strcasecmp(req->headers[i].name, name) == 0) return req->headers[i].value;
	}
	return NULL;
}

size_t hw_http_write_upgrade(char *out, size_t cap, const char *host, uint16_t port, const char *path,
                             const char key[25], const char *protocol, const char *extra) {
	char proto_line[128] = "";
	if (protocol && *protocol) snprintf(proto_line, sizeof(proto_line), "Sec-WebSocket-Protocol: %s\r\n", protocol);
	int n = snprintf(out, cap,
	                 "GET %s HTTP/1.1\r\n"
	                 "Host: %s:%u\r\n"
	                 "Upgrade: websocket\r\n"
	                 "Connection: Upgrade\r\n"
	                 "Sec-WebSocket-Key: %s\r\n"
	                 "Sec-WebSocket-Version: 13\r\n"
	                 "%s%s"
	                 "\r\n",
	                 path, host, port, key, proto_line, extra ? extra : "");
	if (n < 0 || (size_t)n >= cap) return 0;
	return (size_t)n;
}

int hw_http_parse_upgrade_response(const uint8_t *data, size_t len, const char *expected_accept, char *protocol,
                                   size_t protocol_cap) {
	size_t head = find_head_end(data, len);
	if (head == 0) return len >= HW_HTTP_MAX_REQUEST ? HW_ERR_PROTOCOL : HW_ERR_AGAIN;
	const char *p = (const char *)data;
	const char *end = p + head;
	if (head < 12 || strncmp(p, "HTTP/1.1 101", 12) != 0) return HW_ERR_PROTOCOL;
	int accept_ok = 0;
	if (protocol_cap) protocol[0] = '\0';
	const char *eol = memchr(p, '\n', head);
	p = eol + 1;
	while (p < end) {
		eol = memchr(p, '\n', (size_t)(end - p));
		if (!eol) break;
		size_t line_len = (size_t)(eol - p);
		if (line_len > 0 && p[line_len - 1] == '\r') line_len--;
		if (line_len == 0) break;
		const char *colon = memchr(p, ':', line_len);
		if (colon) {
			size_t name_len = (size_t)(colon - p);
			char val[512];
			copy_trimmed(val, sizeof(val), colon + 1, line_len - name_len - 1);
			if (name_len == 20 && strncasecmp(p, "Sec-WebSocket-Accept", 20) == 0) {
				accept_ok = strcmp(val, expected_accept) == 0;
			} else if (name_len == 22 && strncasecmp(p, "Sec-WebSocket-Protocol", 22) == 0 && protocol_cap) {
				first_token_lower(protocol, protocol_cap, val);
			}
		}
		p = eol + 1;
	}
	return accept_ok ? (int)head : HW_ERR_PROTOCOL;
}
