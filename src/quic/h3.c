/*
 * src/quic/h3.c - HTTP/3 frames, settings, stream prefixes, capsules, request and response
 * validation, and the Wisp length-delimited framing (src/quic/h3.h).
 */
#include "h3.h"

#include "holywisp/hw.h"
#include "holywisp/webtransport.h"
#include "holywisp/wisp.h"

#include "quic_wire.h"

#include <stdlib.h>
#include <string.h>

// ---- Frames and capsules ------------------------------------------------------------------

void hw_h3_tlv_init(hw_h3_tlv *r) {
	memset(r, 0, sizeof(*r));
}

int hw_h3_tlv_mid(const hw_h3_tlv *r) {
	return r->hdr_len > 0 || r->in_body;
}

size_t hw_h3_tlv_step(hw_h3_tlv *r, const uint8_t *p, size_t len, hw_h3_tlv_ev *ev) {
	memset(ev, 0, sizeof(*ev));
	if (r->in_body) {
		size_t n = len < r->left ? len : (size_t)r->left;
		ev->kind = HW_H3_TLV_BODY;
		ev->type = r->type;
		ev->len = r->len;
		ev->data = p;
		ev->n = n;
		r->left -= n;
		if (r->left == 0) {
			ev->end = 1;
			r->in_body = 0;
		} else if (n == 0) {
			ev->kind = HW_H3_TLV_NEED; // no input and more of the body to come
		}
		return n;
	}
	// The header: two varints, at most 16 bytes, gathered across calls.
	size_t used = 0;
	while (used < len) {
		if (r->hdr_len == 0 && len - used >= 16) break; // the common case: parse in place
		r->hdr[r->hdr_len++] = p[used++];
		uint64_t type, flen;
		size_t a = hw_qw_varint_get(r->hdr, r->hdr_len, &type);
		if (!a) continue;
		size_t b = hw_qw_varint_get(r->hdr + a, r->hdr_len - a, &flen);
		if (!b) continue;
		r->hdr_len = 0;
		r->type = type;
		r->len = r->left = flen;
		r->in_body = 1;
		ev->kind = HW_H3_TLV_START;
		ev->type = type;
		ev->len = flen;
		return used;
	}
	if (used < len) {
		uint64_t type = 0, flen = 0;
		size_t a = hw_qw_varint_get(p + used, len - used, &type);
		size_t b = hw_qw_varint_get(p + used + a, len - used - a, &flen);
		// len - used >= 16 holds both varints whole.
		used += a + b;
		r->type = type;
		r->len = r->left = flen;
		r->in_body = 1;
		ev->kind = HW_H3_TLV_START;
		ev->type = type;
		ev->len = flen;
		return used;
	}
	ev->kind = HW_H3_TLV_NEED;
	return used;
}

size_t hw_h3_frame_header_put(uint8_t *out, size_t cap, uint64_t type, uint64_t len) {
	size_t a = hw_qw_varint_put(out, cap, type);
	if (!a) return 0;
	size_t b = hw_qw_varint_put(out + a, cap - a, len);
	if (!b) return 0;
	return a + b;
}

// ---- Settings -----------------------------------------------------------------------------

uint64_t hw_h3_settings_parse(const uint8_t *p, size_t len, hw_h3_settings *s) {
	memset(s, 0, sizeof(*s));
	s->max_field_section_size = UINT64_MAX;
	unsigned seen = 0;
	size_t off = 0;
	while (off < len) {
		uint64_t id, v;
		size_t a = hw_qw_varint_get(p + off, len - off, &id);
		if (!a) return HW_H3_FRAME_ERROR;
		size_t b = hw_qw_varint_get(p + off + a, len - off - a, &v);
		if (!b) return HW_H3_FRAME_ERROR;
		off += a + b;
		if (id >= 0x02 && id <= 0x05) return HW_H3_SETTINGS_ERROR;
		unsigned bit = 0;
		uint64_t *dst = NULL;
		int boolean = 0;
		switch (id) {
		case HW_H3_SETTING_QPACK_MAX_TABLE_CAPACITY:
			bit = 1u << 0;
			dst = &s->qpack_max_table_capacity;
			break;
		case HW_H3_SETTING_MAX_FIELD_SECTION_SIZE:
			bit = 1u << 1;
			dst = &s->max_field_section_size;
			break;
		case HW_H3_SETTING_QPACK_BLOCKED_STREAMS:
			bit = 1u << 2;
			dst = &s->qpack_blocked_streams;
			break;
		case HW_H3_SETTING_ENABLE_CONNECT_PROTOCOL:
			bit = 1u << 3;
			dst = &s->enable_connect_protocol;
			boolean = 1;
			break;
		case HW_H3_SETTING_H3_DATAGRAM:
			bit = 1u << 4;
			boolean = 1;
			break;
		case HW_H3_SETTING_H3_DATAGRAM_DRAFT04:
			bit = 1u << 5;
			boolean = 1;
			break;
		case HW_H3_SETTING_ENABLE_WEBTRANSPORT:
			bit = 1u << 6;
			dst = &s->enable_webtransport;
			break;
		case HW_H3_SETTING_WT_MAX_SESSIONS:
			bit = 1u << 7;
			dst = &s->wt_max_sessions;
			break;
		default:
			continue; // unknown and GREASE settings are ignored
		}
		if (seen & bit) return HW_H3_SETTINGS_ERROR;
		seen |= bit;
		if (boolean && v > 1) return HW_H3_SETTINGS_ERROR;
		if (dst) {
			*dst = v;
		} else if (v == 1) {
			s->h3_datagram = 1;
		}
	}
	return 0;
}

// A GREASE setting and frame type, 0x1f * n + 0x21: fixed, so a test can name the bytes.
#define H3_GREASE_SETTING (0x1f * 0x2c1ull + 0x21)
#define H3_GREASE_FRAME   (0x1f * 0x1d3ull + 0x21)

size_t hw_h3_settings_frame(uint8_t *out, size_t cap, int is_client) {
	static const uint64_t server[][2] = {
	    {HW_H3_SETTING_QPACK_MAX_TABLE_CAPACITY, 0},
	    {HW_H3_SETTING_MAX_FIELD_SECTION_SIZE, HW_H3_FIELD_SECTION_MAX},
	    {HW_H3_SETTING_QPACK_BLOCKED_STREAMS, 0},
	    {HW_H3_SETTING_ENABLE_CONNECT_PROTOCOL, 1},
	    {HW_H3_SETTING_H3_DATAGRAM, 1},
	    {HW_H3_SETTING_H3_DATAGRAM_DRAFT04, 1},
	    {HW_H3_SETTING_ENABLE_WEBTRANSPORT, 1},
	    {HW_H3_SETTING_WT_MAX_SESSIONS, 1},
	};
	static const uint64_t client[][2] = {
	    {HW_H3_SETTING_QPACK_MAX_TABLE_CAPACITY, 0},
	    {HW_H3_SETTING_MAX_FIELD_SECTION_SIZE, HW_H3_FIELD_SECTION_MAX},
	    {HW_H3_SETTING_QPACK_BLOCKED_STREAMS, 0},
	    {HW_H3_SETTING_H3_DATAGRAM, 1},
	    {HW_H3_SETTING_H3_DATAGRAM_DRAFT04, 1},
	    {HW_H3_SETTING_ENABLE_WEBTRANSPORT, 1},
	    {H3_GREASE_SETTING, 0},
	};
	const uint64_t (*list)[2] = is_client ? client : server;
	size_t count = is_client ? HW_ARRAY_LEN(client) : HW_ARRAY_LEN(server);
	uint8_t body[128];
	size_t blen = 0;
	for (size_t i = 0; i < count; i++) {
		blen += hw_qw_varint_put(body + blen, sizeof(body) - blen, list[i][0]);
		blen += hw_qw_varint_put(body + blen, sizeof(body) - blen, list[i][1]);
	}
	size_t h = hw_h3_frame_header_put(out, cap, HW_H3_FRAME_SETTINGS, blen);
	if (!h || cap - h < blen) return 0;
	memcpy(out + h, body, blen);
	size_t n = h + blen;
	if (is_client) {
		size_t g = hw_h3_frame_header_put(out + n, cap - n, H3_GREASE_FRAME, 0);
		if (!g) return 0;
		n += g;
	}
	return n;
}

// ---- Stream prefixes ------------------------------------------------------------------------

int hw_h3_stream_kind_parse(const uint8_t *p, size_t len, int bidi, hw_h3_stream_kind *k) {
	memset(k, 0, sizeof(*k));
	uint64_t type, session;
	size_t a = hw_qw_varint_get(p, len, &type);
	if (!a) return 0;
	k->type = type;
	int wt = bidi ? type == HW_H3_WT_BIDI_SIGNAL : type == HW_H3_STREAM_WT_UNI;
	if (wt) {
		size_t b = hw_qw_varint_get(p + a, len - a, &session);
		if (!b) return 0;
		k->kind = bidi ? HW_H3_SK_WT_BIDI : HW_H3_SK_WT_UNI;
		k->session = session;
		k->prefix = a + b;
		return 1;
	}
	if (bidi) {
		k->kind = HW_H3_SK_REQUEST;
		k->prefix = 0;
		return 1;
	}
	switch (type) {
	case HW_H3_STREAM_CONTROL:
		k->kind = HW_H3_SK_CONTROL;
		break;
	case HW_H3_STREAM_PUSH:
		k->kind = HW_H3_SK_PUSH;
		break;
	case HW_H3_STREAM_QPACK_ENC:
		k->kind = HW_H3_SK_QPACK_ENC;
		break;
	case HW_H3_STREAM_QPACK_DEC:
		k->kind = HW_H3_SK_QPACK_DEC;
		break;
	default:
		k->kind = HW_H3_SK_UNKNOWN;
		break;
	}
	k->prefix = a;
	return 1;
}

// ---- Capsules -----------------------------------------------------------------------------

size_t hw_h3_close_capsule_frame(uint8_t *out, size_t cap, uint32_t code, const char *reason) {
	size_t rlen = reason ? strlen(reason) : 0;
	if (rlen > HW_H3_CLOSE_REASON_MAX) rlen = HW_H3_CLOSE_REASON_MAX;
	uint64_t vlen = 4 + rlen;
	uint64_t clen = hw_qw_varint_len(HW_H3_CAPSULE_CLOSE_SESSION) + hw_qw_varint_len(vlen) + vlen;
	size_t n = hw_h3_frame_header_put(out, cap, HW_H3_FRAME_DATA, clen);
	if (!n) return 0;
	size_t c = hw_h3_frame_header_put(out + n, cap - n, HW_H3_CAPSULE_CLOSE_SESSION, vlen);
	if (!c) return 0;
	n += c;
	if (cap - n < vlen) return 0;
	out[n++] = (uint8_t)(code >> 24);
	out[n++] = (uint8_t)(code >> 16);
	out[n++] = (uint8_t)(code >> 8);
	out[n++] = (uint8_t)code;
	// The reason goes on the wire without its NUL.
	for (size_t i = 0; i < rlen; i++) out[n + i] = (uint8_t)reason[i];
	return n + rlen;
}

int hw_h3_close_capsule_parse(const uint8_t *v, size_t n, uint32_t *code, char *reason, size_t cap) {
	if (n < 4 || n - 4 > HW_H3_CLOSE_REASON_MAX || cap < n - 4 + 1) return -1;
	*code = (uint32_t)v[0] << 24 | (uint32_t)v[1] << 16 | (uint32_t)v[2] << 8 | v[3];
	memcpy(reason, v + 4, n - 4);
	reason[n - 4] = '\0';
	return 0;
}

// ---- Requests and responses -----------------------------------------------------------------

static int field_is(const hw_qpack_field *f, const char *name) {
	return strcmp(f->name, name) == 0;
}

// RFC 9110 tchar, lower case only (RFC 9114 section 4.2: an upper-case name is malformed).
static int name_ok(const hw_qpack_field *f, int pseudo) {
	if (f->name_len == (size_t)pseudo) return 0;
	for (size_t i = (size_t)pseudo; i < f->name_len; i++) {
		unsigned char c = (unsigned char)f->name[i];
		if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) continue;
		if (c && strchr("!#$%&'*+-.^_`|~", c)) continue;
		return 0;
	}
	return 1;
}

static int value_ok(const hw_qpack_field *f) {
	for (size_t i = 0; i < f->value_len; i++) {
		if (f->value[i] == '\r' || f->value[i] == '\n' || f->value[i] == '\0') return 0;
	}
	return 1;
}

int hw_h3_request_parse(const hw_qpack_field *f, size_t n, char *join, size_t join_cap, hw_h3_request *r) {
	memset(r, 0, sizeof(*r));
	int regular = 0;
	size_t join_len = 0;
	int joined = 0;
	for (size_t i = 0; i < n; i++) {
		if (!value_ok(&f[i])) return -1;
		if (f[i].name_len && f[i].name[0] == ':') {
			if (regular || !name_ok(&f[i], 1)) return -1;
			const char **slot;
			if (field_is(&f[i], ":method")) {
				slot = &r->method;
			} else if (field_is(&f[i], ":scheme")) {
				slot = &r->scheme;
			} else if (field_is(&f[i], ":authority")) {
				slot = &r->authority;
			} else if (field_is(&f[i], ":path")) {
				slot = &r->path;
			} else if (field_is(&f[i], ":protocol")) {
				slot = &r->protocol;
			} else {
				return -1;
			}
			if (*slot) return -1;
			*slot = f[i].value;
			continue;
		}
		regular = 1;
		if (!name_ok(&f[i], 0)) return -1;
		if (field_is(&f[i], "connection") || field_is(&f[i], "keep-alive") || field_is(&f[i], "proxy-connection") ||
		    field_is(&f[i], "transfer-encoding") || field_is(&f[i], "upgrade")) {
			return -1;
		}
		if (field_is(&f[i], "te") && strcmp(f[i].value, "trailers") != 0) return -1;
		if (field_is(&f[i], "origin")) {
			if (!r->origin) r->origin = f[i].value;
		} else if (field_is(&f[i], "sec-webtransport-http3-draft02")) {
			if (!r->draft02) r->draft02 = f[i].value;
		} else if (field_is(&f[i], "wt-available-protocols")) {
			if (!r->protocols) {
				r->protocols = f[i].value;
				continue;
			}
			// A list split over several lines is one list (RFC 9110 section 5.3).
			if (!joined) {
				size_t l = strlen(r->protocols);
				if (l + 1 > join_cap) return -1;
				memcpy(join, r->protocols, l);
				join_len = l;
				joined = 1;
			}
			if (join_len + 2 + f[i].value_len + 1 > join_cap) return -1;
			memcpy(join + join_len, ", ", 2);
			memcpy(join + join_len + 2, f[i].value, f[i].value_len);
			join_len += 2 + f[i].value_len;
			join[join_len] = '\0';
			r->protocols = join;
		}
	}
	if (!r->method) return -1;
	if (strcmp(r->method, "CONNECT") == 0) {
		if (!r->authority || !*r->authority) return -1;
		if (r->protocol) {
			if (!r->scheme || !r->path || !*r->path) return -1;
		} else if (r->scheme || r->path) {
			return -1;
		}
		return 0;
	}
	if (r->protocol || !r->scheme || !r->path || !*r->path) return -1;
	return 0;
}

int hw_h3_response_parse(const hw_qpack_field *f, size_t n, int *status, const char **wt_protocol) {
	*status = 0;
	*wt_protocol = NULL;
	if (n == 0 || strcmp(f[0].name, ":status") != 0) return -1;
	const char *v = f[0].value;
	if (f[0].value_len != 3) return -1;
	for (int i = 0; i < 3; i++) {
		if (v[i] < '0' || v[i] > '9') return -1;
	}
	int st = (v[0] - '0') * 100 + (v[1] - '0') * 10 + (v[2] - '0');
	if (st < 100) return -1;
	for (size_t i = 1; i < n; i++) {
		if (!value_ok(&f[i])) return -1;
		if (f[i].name_len && f[i].name[0] == ':') return -1;
		if (!name_ok(&f[i], 0)) return -1;
		if (field_is(&f[i], "wt-protocol") && !*wt_protocol) *wt_protocol = f[i].value;
	}
	*status = st;
	return 0;
}

// ---- Wisp length-delimited framing ------------------------------------------------------------

#define H3_LP_GROW_MIN 4096        // the reassembly buffer's first size
#define H3_LP_KEEP     (64 * 1024) // kept between packets up to this size

void hw_h3_lp_init(hw_h3_lp *r, size_t max_packet) {
	memset(r, 0, sizeof(*r));
	r->max_packet = max_packet;
}

void hw_h3_lp_clear(hw_h3_lp *r) {
	free(r->buf);
	size_t max = r->max_packet;
	hw_h3_lp_init(r, max);
}

int hw_h3_lp_mid(const hw_h3_lp *r) {
	return r->hdr_len > 0 || r->in_packet;
}

int hw_h3_lp_next(hw_h3_lp *r, const uint8_t *p, size_t len, size_t *used, const uint8_t **pkt, size_t *pkt_len) {
	size_t off = 0;
	*used = 0;
	if (!r->in_packet) {
		// Between packets: a large buffer the last one needed is not kept for the next (the packet
		// it held was valid only until this call).
		if (r->buf_cap > H3_LP_KEEP) {
			free(r->buf);
			r->buf = NULL;
			r->buf_cap = 0;
		}
		// The length, whole in the input, or gathered across calls.
		if (r->hdr_len == 0 && len >= 4) {
			r->need = hw_le32(p);
			off = 4;
		} else {
			while (r->hdr_len < 4 && off < len) r->hdr[r->hdr_len++] = p[off++];
			if (r->hdr_len < 4) {
				*used = off;
				return 0;
			}
			r->need = hw_le32(r->hdr);
			r->hdr_len = 0;
		}
		if (r->need > r->max_packet) {
			*used = off;
			return HW_ERR_TOOBIG;
		}
		r->in_packet = 1;
		r->have = 0;
		// Whole in the input: handed out in place, no copy.
		if (len - off >= r->need) {
			*pkt = p + off;
			*pkt_len = r->need;
			*used = off + r->need;
			r->in_packet = 0;
			return 1;
		}
	}
	size_t take = HW_MIN(len - off, r->need - r->have);
	if (r->have + take > r->buf_cap) {
		// Grown with what has arrived, never to what the length claims before it has: a client
		// that names max_packet and then trickles costs what it sent.
		size_t cap = HW_MAX(HW_MAX(r->buf_cap * 2, r->have + take), (size_t)H3_LP_GROW_MIN);
		cap = HW_MIN(cap, r->need);
		uint8_t *nb = realloc(r->buf, cap);
		if (!nb) {
			*used = off;
			return HW_ERR_NOMEM;
		}
		r->buf = nb;
		r->buf_cap = cap;
	}
	if (take) memcpy(r->buf + r->have, p + off, take);
	r->have += take;
	off += take;
	*used = off;
	if (r->have < r->need) return 0;
	r->in_packet = 0;
	*pkt = r->buf;
	*pkt_len = r->need;
	return 1;
}
