/*
 * holywisp/ws.h implementation.
 */
#include "holywisp/ws.h"

#include "holywisp/base64.h"
#include "holywisp/hw.h"
#include "holywisp/sha1.h"

#include <ctype.h>
#include <stdatomic.h>
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

// Unmasking is the server's only per-byte work in user space: every byte a client uploads passes
// through it, and before it was vectorised it was a tenth of the server's CPU under load. 32 bytes
// a step with the compiler's generic vectors, which are two SSE2 or NEON registers anywhere and one
// AVX2 register where the CPU has it: on the bench VM at 16x4 that was 4.8% more bytes per CPU
// second than 8 bytes a step (2.4% for SSE2 alone). `data` starts on a mask cycle; returns the
// bytes done, a multiple of 32.
typedef uint8_t mask_v32 __attribute__((vector_size(32)));

static inline __attribute__((always_inline)) size_t mask_v32_run(uint8_t *data, size_t len, const uint8_t mask[4]) {
	mask_v32 key;
	for (int k = 0; k < 32; k++) key[k] = mask[k & 3];
	size_t i = 0;
	for (; len - i >= 32; i += 32) {
		mask_v32 v;
		memcpy(&v, data + i, 32);
		v ^= key;
		memcpy(data + i, &v, 32);
	}
	return i;
}

static size_t mask_v32_base(uint8_t *data, size_t len, const uint8_t mask[4]) {
	return mask_v32_run(data, len, mask);
}

// The one architecture #if in the tree: AVX2 is not in the x86-64 baseline the release builds
// target, so it is compiled in beside the baseline and picked by asking the CPU, once.
#if defined(__x86_64__)
#include <cpuid.h>

__attribute__((target("avx2"))) static size_t mask_v32_avx2(uint8_t *data, size_t len, const uint8_t mask[4]) {
	return mask_v32_run(data, len, mask);
}

// AVX2 in the CPU (leaf 7) and its registers saved by the OS (OSXSAVE, then XCR0's SSE and AVX
// bits): a CPU that has it under an OS that does not save YMM faults on the first use.
static int cpu_has_avx2(void) {
	unsigned a, b, c, d;
	if (!__get_cpuid(1, &a, &b, &c, &d) || !(c & bit_OSXSAVE) || !(c & bit_AVX)) return 0;
	unsigned lo, hi;
	__asm__ volatile("xgetbv" : "=a"(lo), "=d"(hi) : "c"(0));
	if ((lo & 6) != 6) return 0;
	if (!__get_cpuid_count(7, 0, &a, &b, &c, &d)) return 0;
	return (b & bit_AVX2) != 0;
}

static _Atomic int g_mask_avx2 = -1; // unknown until the first large unmask; every thread finds the same

static size_t mask_vec(uint8_t *data, size_t len, const uint8_t mask[4]) {
	int avx2 = atomic_load_explicit(&g_mask_avx2, memory_order_relaxed);
	if (avx2 < 0) {
		avx2 = cpu_has_avx2();
		atomic_store_explicit(&g_mask_avx2, avx2, memory_order_relaxed);
	}
	return avx2 ? mask_v32_avx2(data, len, mask) : mask_v32_base(data, len, mask);
}
#else
static size_t mask_vec(uint8_t *data, size_t len, const uint8_t mask[4]) {
	return mask_v32_base(data, len, mask);
}
#endif

void hw_ws_mask(uint8_t *data, size_t len, const uint8_t mask[4], size_t offset) {
	size_t i = 0;
	// Align to the mask cycle, then 32 bytes at a time, then 8 with a rotated 64-bit key.
	while (i < len && ((offset + i) & 3) != 0) {
		data[i] ^= mask[(offset + i) & 3];
		i++;
	}
	if (len - i >= 32) i += mask_vec(data + i, len - i, mask);
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

// The first token of a comma-separated header, verbatim. A subprotocol must be echoed exactly as
// the client sent it (browsers compare byte for byte), so no case folding here.
static void first_token(char *dst, size_t cap, const char *list) {
	while (*list == ' ' || *list == '\t') list++;
	size_t n = 0;
	while (list[n] && list[n] != ',' && !isspace((unsigned char)list[n]) && n + 1 < cap) {
		dst[n] = list[n];
		n++;
	}
	dst[n] = '\0';
}

// A header name is a token (RFC 9110): letters, digits and these marks, nothing else.
static int is_token_char(unsigned char c) {
	return isalnum(c) || (c != '\0' && strchr("!#$%&'*+-.^_`|~", c) != NULL);
}

// Copy a header value without the whitespace around it. Returns 1 when it did not fit and was cut.
static int copy_value(char *dst, size_t cap, const char *src, size_t n) {
	while (n > 0 && (src[0] == ' ' || src[0] == '\t')) {
		src++;
		n--;
	}
	while (n > 0 && (src[n - 1] == ' ' || src[n - 1] == '\t')) n--;
	int cut = n >= cap;
	if (cut) n = cap - 1;
	memcpy(dst, src, n);
	dst[n] = '\0';
	return cut;
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

	// Every header goes into the table as it was sent, or the head is refused. What the table
	// drops, cuts or folds is what a client uses to hide the header its proxy wrote, or to pass
	// off one of its own: a proxy and this parser must never disagree on what a header says.
	int upgrade = 0, connection = 0, version13 = 0;
	p = eol + 1;
	while (p < end) {
		eol = memchr(p, '\n', (size_t)(end - p));
		if (!eol) break;
		size_t line_len = (size_t)(eol - p);
		if (line_len > 0 && p[line_len - 1] == '\r') line_len--;
		if (line_len == 0) break;
		// A line that starts with whitespace continues the header before it (obs-fold), which
		// some proxies join and others pass on: refused. So is a name with whitespace or anything
		// else that is not a token in it, where one side reads a header and the other does not.
		const char *colon = memchr(p, ':', line_len);
		if (!colon) return HW_ERR_PROTOCOL;
		size_t name_len = (size_t)(colon - p);
		if (name_len == 0 || name_len >= sizeof(req->headers[0].name)) return HW_ERR_PROTOCOL;
		for (size_t i = 0; i < name_len; i++) {
			if (!is_token_char((unsigned char)p[i])) return HW_ERR_PROTOCOL;
		}
		const char *value = colon + 1;
		size_t value_len = line_len - name_len - 1;
		// A NUL would end the stored string early, a CR is a line end to some parsers.
		if (memchr(value, '\0', value_len) || memchr(value, '\r', value_len)) return HW_ERR_PROTOCOL;
		if (req->header_count >= HW_HTTP_MAX_HEADERS) return HW_ERR_PROTOCOL;
		hw_http_header *h = &req->headers[req->header_count++];
		memcpy(h->name, p, name_len);
		h->name[name_len] = '\0';
		h->cut = copy_value(h->value, sizeof(h->value), value, value_len);
		const char *val = h->value;

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
			first_token(req->ws_protocol, sizeof(req->ws_protocol), val);
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

int hw_http_header_all(const hw_http_request *req, const char *name, const char **values, int cap, int *cut) {
	int n = 0;
	*cut = 0;
	for (int i = 0; i < req->header_count; i++) {
		if (strcasecmp(req->headers[i].name, name) != 0) continue;
		if (req->headers[i].cut) *cut = 1;
		if (n < cap) values[n] = req->headers[i].value;
		n++;
	}
	return n;
}

// Whether s can be written into a request head as one word: not empty, and no space or control
// byte that would end the word or the line it is on.
static int is_head_word(const char *s) {
	if (!*s) return 0;
	for (; *s; s++) {
		unsigned char c = (unsigned char)*s;
		if (c <= 0x20 || c == 0x7f) return 0;
	}
	return 1;
}

size_t hw_http_write_upgrade(char *out, size_t cap, const char *host, uint16_t port, const char *path,
                             const char key[25], const char *protocol, const char *extra) {
	if (!is_head_word(host) || !is_head_word(path)) return 0;
	if (protocol && *protocol && !is_head_word(protocol)) return 0;
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
				first_token(protocol, protocol_cap, val);
			}
		}
		p = eol + 1;
	}
	return accept_ok ? (int)head : HW_ERR_PROTOCOL;
}
