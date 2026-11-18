/*
 * src/quic/qpack.c - QPACK field sections without a dynamic table (RFC 9204), and the HPACK
 * Huffman code they use (RFC 7541 appendix B). See src/quic/h3.h.
 *
 * The Huffman code is canonical: codes of one length are consecutive in symbol order, and each
 * length's first code follows from the counts of the shorter ones. So the only table is the code
 * length of each symbol, as appendix B lists them, and the codes are derived from it per call
 * (a few hundred steps; a header block is decoded once per connection).
 */
#include "holywisp/hw.h"

#include "h3.h"

#include <string.h>

// ---- Static table (RFC 9204 appendix A) -------------------------------------------------------

static const char *const QPACK_STATIC[HW_QPACK_STATIC_COUNT][2] = {
    {":authority", ""},
    {":path", "/"},
    {"age", "0"},
    {"content-disposition", ""},
    {"content-length", "0"},
    {"cookie", ""},
    {"date", ""},
    {"etag", ""},
    {"if-modified-since", ""},
    {"if-none-match", ""},
    {"last-modified", ""},
    {"link", ""},
    {"location", ""},
    {"referer", ""},
    {"set-cookie", ""},
    {":method", "CONNECT"},
    {":method", "DELETE"},
    {":method", "GET"},
    {":method", "HEAD"},
    {":method", "OPTIONS"},
    {":method", "POST"},
    {":method", "PUT"},
    {":scheme", "http"},
    {":scheme", "https"},
    {":status", "103"},
    {":status", "200"},
    {":status", "304"},
    {":status", "404"},
    {":status", "503"},
    {"accept", "*/*"},
    {"accept", "application/dns-message"},
    {"accept-encoding", "gzip, deflate, br"},
    {"accept-ranges", "bytes"},
    {"access-control-allow-headers", "cache-control"},
    {"access-control-allow-headers", "content-type"},
    {"access-control-allow-origin", "*"},
    {"cache-control", "max-age=0"},
    {"cache-control", "max-age=2592000"},
    {"cache-control", "max-age=604800"},
    {"cache-control", "no-cache"},
    {"cache-control", "no-store"},
    {"cache-control", "public, max-age=31536000"},
    {"content-encoding", "br"},
    {"content-encoding", "gzip"},
    {"content-type", "application/dns-message"},
    {"content-type", "application/javascript"},
    {"content-type", "application/json"},
    {"content-type", "application/x-www-form-urlencoded"},
    {"content-type", "image/gif"},
    {"content-type", "image/jpeg"},
    {"content-type", "image/png"},
    {"content-type", "text/css"},
    {"content-type", "text/html; charset=utf-8"},
    {"content-type", "text/plain"},
    {"content-type", "text/plain;charset=utf-8"},
    {"range", "bytes=0-"},
    {"strict-transport-security", "max-age=31536000"},
    {"strict-transport-security", "max-age=31536000; includesubdomains"},
    {"strict-transport-security", "max-age=31536000; includesubdomains; preload"},
    {"vary", "accept-encoding"},
    {"vary", "origin"},
    {"x-content-type-options", "nosniff"},
    {"x-xss-protection", "1; mode=block"},
    {":status", "100"},
    {":status", "204"},
    {":status", "206"},
    {":status", "302"},
    {":status", "400"},
    {":status", "403"},
    {":status", "421"},
    {":status", "425"},
    {":status", "500"},
    {"accept-language", ""},
    {"access-control-allow-credentials", "FALSE"},
    {"access-control-allow-credentials", "TRUE"},
    {"access-control-allow-headers", "*"},
    {"access-control-allow-methods", "get"},
    {"access-control-allow-methods", "get, post, options"},
    {"access-control-allow-methods", "options"},
    {"access-control-expose-headers", "content-length"},
    {"access-control-request-headers", "content-type"},
    {"access-control-request-method", "get"},
    {"access-control-request-method", "post"},
    {"alt-svc", "clear"},
    {"authorization", ""},
    {"content-security-policy", "script-src 'none'; object-src 'none'; base-uri 'none'"},
    {"early-data", "1"},
    {"expect-ct", ""},
    {"forwarded", ""},
    {"if-range", ""},
    {"origin", ""},
    {"purpose", "prefetch"},
    {"server", ""},
    {"timing-allow-origin", "*"},
    {"upgrade-insecure-requests", "1"},
    {"user-agent", ""},
    {"x-forwarded-for", ""},
    {"x-frame-options", "deny"},
    {"x-frame-options", "sameorigin"},
};

const char *hw_qpack_static_name(size_t i) {
	return i < HW_QPACK_STATIC_COUNT ? QPACK_STATIC[i][0] : NULL;
}

const char *hw_qpack_static_value(size_t i) {
	return i < HW_QPACK_STATIC_COUNT ? QPACK_STATIC[i][1] : NULL;
}

// ---- Huffman (RFC 7541 appendix B) ------------------------------------------------------------

#define HUFF_SYMS    257 // 256 octets and EOS
#define HUFF_EOS     256
#define HUFF_MAX_LEN 30

// The code length of each symbol, appendix B's "len in bits" column.
static const uint8_t HUFF_LEN[HUFF_SYMS] = {
    13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28, // 0x00
    28, 28, 28, 28, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 28, // 0x10
    6,  10, 10, 12, 13, 6,  8,  11, 10, 10, 8,  11, 8,  6,  6,  6,  // ' ' to '/'
    5,  5,  5,  6,  6,  6,  6,  6,  6,  6,  7,  8,  15, 6,  12, 10, // '0' to '?'
    13, 6,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  // '@' to 'O'
    7,  7,  7,  7,  7,  7,  7,  7,  8,  7,  8,  13, 19, 13, 14, 6,  // 'P' to '_'
    15, 5,  6,  5,  6,  5,  6,  6,  6,  5,  7,  7,  6,  6,  6,  5,  // '`' to 'o'
    6,  7,  6,  5,  5,  6,  7,  7,  7,  7,  7,  15, 11, 14, 13, 28, // 'p' to 0x7f
    20, 22, 20, 20, 22, 22, 22, 23, 22, 23, 23, 23, 23, 23, 24, 23, // 0x80
    24, 24, 22, 23, 24, 23, 23, 23, 23, 21, 22, 23, 22, 23, 23, 24, // 0x90
    22, 21, 20, 22, 22, 23, 23, 21, 23, 22, 22, 24, 21, 22, 23, 23, // 0xa0
    21, 21, 22, 21, 23, 22, 23, 23, 20, 22, 22, 22, 23, 22, 22, 23, // 0xb0
    26, 26, 20, 19, 22, 23, 22, 25, 26, 26, 26, 27, 27, 26, 24, 25, // 0xc0
    19, 21, 26, 27, 27, 26, 27, 24, 21, 21, 26, 26, 28, 27, 27, 27, // 0xd0
    20, 24, 20, 21, 22, 21, 21, 23, 22, 22, 25, 25, 24, 24, 26, 23, // 0xe0
    26, 27, 26, 26, 27, 27, 27, 27, 27, 28, 27, 27, 27, 27, 27, 26, // 0xf0
    30,                                                             // EOS
};

typedef struct {
	uint32_t first[HUFF_MAX_LEN + 2]; // the first code of each length
	uint16_t count[HUFF_MAX_LEN + 2]; // codes of each length
	uint16_t base[HUFF_MAX_LEN + 2];  // where each length's symbols start in syms
	uint16_t syms[HUFF_SYMS];         // symbols by (length, value)
	uint32_t code[HUFF_SYMS];
} huff_tables;

static void huff_build(huff_tables *t) {
	memset(t, 0, sizeof(*t));
	for (size_t s = 0; s < HUFF_SYMS; s++) t->count[HUFF_LEN[s]]++;
	uint32_t code = 0;
	uint16_t base = 0;
	for (size_t l = 1; l <= HUFF_MAX_LEN; l++) {
		t->first[l] = code;
		t->base[l] = base;
		code = (code + t->count[l]) << 1;
		base = (uint16_t)(base + t->count[l]);
	}
	uint16_t fill[HUFF_MAX_LEN + 2] = {0};
	for (size_t s = 0; s < HUFF_SYMS; s++) {
		size_t l = HUFF_LEN[s];
		t->syms[t->base[l] + fill[l]] = (uint16_t)s;
		t->code[s] = t->first[l] + fill[l];
		fill[l]++;
	}
}

size_t hw_huffman_len(const uint8_t *s, size_t n) {
	uint64_t bits = 0;
	for (size_t i = 0; i < n; i++) bits += HUFF_LEN[s[i]];
	return (size_t)((bits + 7) / 8);
}

static size_t huff_encode(const huff_tables *t, const uint8_t *s, size_t n, uint8_t *out, size_t cap) {
	size_t need = hw_huffman_len(s, n);
	if (need > cap) return 0;
	uint64_t acc = 0;
	unsigned bits = 0;
	size_t o = 0;
	for (size_t i = 0; i < n; i++) {
		acc = (acc << HUFF_LEN[s[i]]) | t->code[s[i]];
		bits += HUFF_LEN[s[i]];
		while (bits >= 8) {
			bits -= 8;
			out[o++] = (uint8_t)(acc >> bits);
		}
	}
	// Padding is the most significant bits of EOS: all ones.
	if (bits) out[o++] = (uint8_t)((acc << (8 - bits)) | (0xffu >> bits));
	return o;
}

size_t hw_huffman_encode(const uint8_t *s, size_t n, uint8_t *out, size_t cap) {
	huff_tables t;
	huff_build(&t);
	return huff_encode(&t, s, n, out, cap);
}

static long long huff_decode(const huff_tables *t, const uint8_t *p, size_t n, uint8_t *out, size_t cap) {
	size_t o = 0;
	uint32_t code = 0;
	unsigned len = 0;
	for (size_t i = 0; i < n; i++) {
		for (int b = 7; b >= 0; b--) {
			code = (code << 1) | ((p[i] >> b) & 1u);
			len++;
			if (code >= t->first[len] && code - t->first[len] < t->count[len]) {
				uint16_t sym = t->syms[t->base[len] + (code - t->first[len])];
				if (sym == HUFF_EOS) return -1;
				if (o >= cap) return -2;
				out[o++] = (uint8_t)sym;
				code = 0;
				len = 0;
			} else if (len >= HUFF_MAX_LEN) {
				return -1;
			}
		}
	}
	// What is left must be padding: under 8 bits, all ones (RFC 7541 section 5.2).
	if (len > 7 || code != (1u << len) - 1) return -1;
	return (long long)o;
}

long long hw_huffman_decode(const uint8_t *p, size_t n, uint8_t *out, size_t cap) {
	huff_tables t;
	huff_build(&t);
	return huff_decode(&t, p, n, out, cap);
}

// ---- Field section decoding ---------------------------------------------------------------------

// The prefix integers of RFC 9204 section 4.1.1 (RFC 7541 section 5.1). Values are capped well
// below anything that could overflow: nothing here is longer than a header block.
#define QPACK_INT_MAX 0x0fffffffu

static int qint_get(const uint8_t *p, size_t len, size_t *off, unsigned prefix, uint32_t *v) {
	if (*off >= len) return -1;
	uint32_t mask = (1u << prefix) - 1;
	uint32_t x = p[*off] & mask;
	(*off)++;
	if (x < mask) {
		*v = x;
		return 0;
	}
	unsigned shift = 0;
	for (;;) {
		if (*off >= len || shift > 21) return -1;
		uint8_t b = p[(*off)++];
		x += (uint32_t)(b & 0x7f) << shift;
		if (x > QPACK_INT_MAX) return -1;
		shift += 7;
		if (!(b & 0x80)) break;
	}
	*v = x;
	return 0;
}

typedef struct {
	const huff_tables *t;
	char *arena;
	size_t cap, used;
	int too_big;
} qpack_out;

// Copies a string literal (H bit at hbit, length with prefix bits) into the arena.
static const char *qstr_get(qpack_out *o, const uint8_t *p, size_t len, size_t *off, uint8_t hbit, unsigned prefix,
                            size_t *out_len) {
	if (*off >= len) return NULL;
	int huff = (p[*off] & hbit) != 0;
	uint32_t n;
	if (qint_get(p, len, off, prefix, &n) < 0 || n > len - *off) return NULL;
	char *dst = o->arena + o->used;
	size_t room = o->cap - o->used;
	size_t dlen;
	if (huff) {
		long long r = huff_decode(o->t, p + *off, n, (uint8_t *)dst, room ? room - 1 : 0);
		if (r < 0) {
			if (r == -2) o->too_big = 1;
			return NULL;
		}
		dlen = (size_t)r;
	} else {
		if ((size_t)n + 1 > room) {
			o->too_big = 1;
			return NULL;
		}
		memcpy(dst, p + *off, n);
		dlen = n;
	}
	*off += n;
	if (memchr(dst, '\0', dlen)) return NULL;
	dst[dlen] = '\0';
	o->used += dlen + 1;
	*out_len = dlen;
	return dst;
}

static const char *qstatic_copy(qpack_out *o, const char *s, size_t *out_len) {
	size_t n = strlen(s);
	if (n + 1 > o->cap - o->used) {
		o->too_big = 1;
		return NULL;
	}
	char *dst = o->arena + o->used;
	memcpy(dst, s, n + 1);
	o->used += n + 1;
	*out_len = n;
	return dst;
}

int hw_qpack_decode(const uint8_t *p, size_t len, char *arena, size_t arena_cap, hw_qpack_field *fields,
                    size_t max_fields) {
	huff_tables t;
	huff_build(&t);
	qpack_out o = {&t, arena, arena_cap, 0, 0};
	size_t off = 0;
	uint32_t ric, base;
	// Required Insert Count: anything but 0 needs the dynamic table we said we do not have.
	if (qint_get(p, len, &off, 8, &ric) < 0 || ric != 0) return HW_ERR_INVALID;
	if (qint_get(p, len, &off, 7, &base) < 0) return HW_ERR_INVALID;
	size_t n = 0;
	while (off < len) {
		if (n == max_fields) return HW_ERR_TOOBIG;
		hw_qpack_field *f = &fields[n];
		uint8_t b = p[off];
		uint32_t idx;
		if (b & 0x80) {
			// Indexed field line: 1 T index(6). T = 0 is the dynamic table.
			if (!(b & 0x40)) return HW_ERR_INVALID;
			if (qint_get(p, len, &off, 6, &idx) < 0 || idx >= HW_QPACK_STATIC_COUNT) return HW_ERR_INVALID;
			f->name = qstatic_copy(&o, QPACK_STATIC[idx][0], &f->name_len);
			f->value = f->name ? qstatic_copy(&o, QPACK_STATIC[idx][1], &f->value_len) : NULL;
		} else if (b & 0x40) {
			// Literal with name reference: 0 1 N T index(4), then the value.
			if (!(b & 0x10)) return HW_ERR_INVALID;
			if (qint_get(p, len, &off, 4, &idx) < 0 || idx >= HW_QPACK_STATIC_COUNT) return HW_ERR_INVALID;
			f->name = qstatic_copy(&o, QPACK_STATIC[idx][0], &f->name_len);
			f->value = f->name ? qstr_get(&o, p, len, &off, 0x80, 7, &f->value_len) : NULL;
		} else if (b & 0x20) {
			// Literal with literal name: 0 0 1 N H namelen(3), the name, then the value.
			f->name = qstr_get(&o, p, len, &off, 0x08, 3, &f->name_len);
			f->value = f->name ? qstr_get(&o, p, len, &off, 0x80, 7, &f->value_len) : NULL;
		} else {
			// Indexed with post-base index (0001) or literal with post-base name reference
			// (0000): both the dynamic table.
			return HW_ERR_INVALID;
		}
		if (!f->name || !f->value) return o.too_big ? HW_ERR_TOOBIG : HW_ERR_INVALID;
		n++;
	}
	return (int)n;
}

// ---- Field line encoding ------------------------------------------------------------------------

static size_t qint_put(uint8_t *out, size_t cap, uint8_t first, unsigned prefix, size_t v) {
	size_t mask = ((size_t)1 << prefix) - 1;
	if (cap < 1) return 0;
	if (v < mask) {
		out[0] = (uint8_t)(first | v);
		return 1;
	}
	out[0] = (uint8_t)(first | mask);
	v -= mask;
	size_t n = 1;
	while (v >= 0x80) {
		if (n >= cap) return 0;
		out[n++] = (uint8_t)(0x80 | (v & 0x7f));
		v >>= 7;
	}
	if (n >= cap) return 0;
	out[n++] = (uint8_t)v;
	return n;
}

static size_t qstr_put(const huff_tables *t, uint8_t *out, size_t cap, uint8_t first, uint8_t hbit, unsigned prefix,
                       const char *s, size_t n) {
	size_t hl = hw_huffman_len((const uint8_t *)s, n);
	int huff = hl < n;
	size_t slen = huff ? hl : n;
	size_t h = qint_put(out, cap, (uint8_t)(first | (huff ? hbit : 0)), prefix, slen);
	if (!h || cap - h < slen) return 0;
	if (huff) {
		huff_encode(t, (const uint8_t *)s, n, out + h, cap - h);
	} else if (n) {
		memcpy(out + h, s, n);
	}
	return h + slen;
}

size_t hw_qpack_prefix_put(uint8_t *out, size_t cap) {
	if (cap < 2) return 0;
	out[0] = 0;
	out[1] = 0;
	return 2;
}

size_t hw_qpack_field_put(uint8_t *out, size_t cap, const char *name, size_t name_len, const char *value,
                          size_t value_len) {
	huff_tables t;
	huff_build(&t);
	long name_idx = -1;
	for (size_t i = 0; i < HW_QPACK_STATIC_COUNT; i++) {
		if (strlen(QPACK_STATIC[i][0]) != name_len || memcmp(QPACK_STATIC[i][0], name, name_len) != 0) continue;
		if (strlen(QPACK_STATIC[i][1]) == value_len && memcmp(QPACK_STATIC[i][1], value, value_len) == 0) {
			return qint_put(out, cap, 0xc0, 6, i); // indexed, static
		}
		if (name_idx < 0) name_idx = (long)i;
	}
	if (name_idx >= 0) {
		size_t h = qint_put(out, cap, 0x50, 4, (size_t)name_idx); // literal, static name reference
		if (!h) return 0;
		size_t v = qstr_put(&t, out + h, cap - h, 0x00, 0x80, 7, value, value_len);
		return v ? h + v : 0;
	}
	size_t h = qstr_put(&t, out, cap, 0x20, 0x08, 3, name, name_len); // literal name
	if (!h) return 0;
	size_t v = qstr_put(&t, out + h, cap - h, 0x00, 0x80, 7, value, value_len);
	return v ? h + v : 0;
}
