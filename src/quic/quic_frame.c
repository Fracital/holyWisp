/*
 * src/quic/quic_frame.c - QUIC frames (RFC 9000 section 19, RFC 9221 section 4): one parser for
 * every type, and the writers the connection sends with. Lengths are checked against the
 * packet; nothing here allocates or keeps state.
 */
#include "quic_internal.h"

#include <string.h>

#define GET(var)                                \
	do {                                        \
		size_t n_ = hw_qc_vget(p, end, &(var)); \
		if (!n_) return 0;                      \
		p += n_;                                \
	} while (0)

size_t hw_qc_frame_parse(const uint8_t *p, const uint8_t *end, hw_qc_frame *f) {
	const uint8_t *start = p;
	uint64_t type;
	memset(f, 0, sizeof(*f));
	f->type = UINT64_MAX;
	GET(type);
	f->type = type;
	switch (type) {
	case HW_QC_F_PADDING:
		while (p < end && *p == 0) p++;
		break;
	case HW_QC_F_PING:
	case HW_QC_F_HANDSHAKE_DONE:
		break;
	case HW_QC_F_ACK:
	case HW_QC_F_ACK_ECN: {
		GET(f->ack_largest);
		GET(f->ack_delay);
		GET(f->ack_count);
		GET(f->ack_first);
		if (f->ack_first > f->ack_largest) return 0;
		uint64_t smallest = f->ack_largest - f->ack_first;
		f->ack_ranges = p;
		for (uint64_t i = 0; i < f->ack_count; i++) {
			uint64_t gap, len;
			GET(gap);
			GET(len);
			// The next range's largest is smallest - gap - 2, its smallest that minus len.
			if (smallest < gap + 2) return 0;
			uint64_t largest = smallest - gap - 2;
			if (largest < len) return 0;
			smallest = largest - len;
		}
		f->ack_ranges_len = (size_t)(p - f->ack_ranges);
		if (type == HW_QC_F_ACK_ECN) {
			uint64_t e;
			GET(e);
			GET(e);
			GET(e);
		}
		f->type = HW_QC_F_ACK;
		break;
	}
	case HW_QC_F_RESET_STREAM:
		GET(f->stream_id);
		GET(f->error);
		GET(f->value);
		if (f->value > HW_QW_VARINT_MAX) return 0;
		break;
	case HW_QC_F_STOP_SENDING:
		GET(f->stream_id);
		GET(f->error);
		break;
	case HW_QC_F_CRYPTO: {
		uint64_t len;
		GET(f->offset);
		GET(len);
		if (len > (uint64_t)(end - p) || f->offset + len > HW_QW_VARINT_MAX) return 0;
		f->data = p;
		f->len = (size_t)len;
		p += len;
		break;
	}
	case HW_QC_F_NEW_TOKEN: {
		uint64_t len;
		GET(len);
		if (len == 0 || len > (uint64_t)(end - p)) return 0;
		f->data = p;
		f->len = (size_t)len;
		p += len;
		break;
	}
	case HW_QC_F_MAX_DATA:
	case HW_QC_F_DATA_BLOCKED:
		GET(f->value);
		break;
	case HW_QC_F_MAX_STREAMS_BIDI:
	case HW_QC_F_MAX_STREAMS_UNI:
	case HW_QC_F_STREAMS_BLOCKED_BIDI:
	case HW_QC_F_STREAMS_BLOCKED_UNI:
		GET(f->value);
		if (f->value > HW_QC_STREAMS_MAX_VALUE) return 0;
		break;
	case HW_QC_F_MAX_STREAM_DATA:
	case HW_QC_F_STREAM_DATA_BLOCKED:
		GET(f->stream_id);
		GET(f->value);
		break;
	case HW_QC_F_NEW_CONNECTION_ID:
		GET(f->value);
		GET(f->value2);
		if (f->value2 > f->value || p >= end) return 0;
		f->len = *p++;
		if (f->len < 1 || f->len > 20 || (size_t)(end - p) < f->len + HW_QUIC_RESET_LEN) return 0;
		f->data = p;
		p += f->len;
		f->token = p;
		p += HW_QUIC_RESET_LEN;
		break;
	case HW_QC_F_RETIRE_CONNECTION_ID:
		GET(f->value);
		break;
	case HW_QC_F_PATH_CHALLENGE:
	case HW_QC_F_PATH_RESPONSE:
		if (end - p < 8) return 0;
		f->data = p;
		f->len = 8;
		p += 8;
		break;
	case HW_QC_F_CONNECTION_CLOSE:
	case HW_QC_F_CONNECTION_CLOSE_APP: {
		uint64_t len;
		GET(f->error);
		if (type == HW_QC_F_CONNECTION_CLOSE) GET(f->value);
		GET(len);
		if (len > (uint64_t)(end - p)) return 0;
		f->data = p;
		f->len = (size_t)len;
		p += len;
		break;
	}
	case HW_QC_F_DATAGRAM:
	case HW_QC_F_DATAGRAM_LEN:
		if (type == HW_QC_F_DATAGRAM_LEN) {
			uint64_t len;
			GET(len);
			if (len > (uint64_t)(end - p)) return 0;
			f->len = (size_t)len;
		} else {
			f->len = (size_t)(end - p);
		}
		f->data = p;
		p += f->len;
		f->type = HW_QC_F_DATAGRAM;
		break;
	default:
		if (type >= 0x08 && type <= 0x0f) {
			GET(f->stream_id);
			if (type & 0x04) GET(f->offset);
			if (type & 0x02) {
				uint64_t len;
				GET(len);
				if (len > (uint64_t)(end - p)) return 0;
				f->len = (size_t)len;
			} else {
				f->len = (size_t)(end - p);
			}
			if (f->offset + f->len > HW_QW_VARINT_MAX) return 0;
			f->fin = (int)(type & 0x01);
			f->data = p;
			p += f->len;
			f->type = HW_QC_F_STREAM;
			break;
		}
		return 0;
	}
	return (size_t)(p - start);
}

#undef GET

void hw_qc_ack_iter_init(hw_qc_ack_iter *it, const hw_qc_frame *f) {
	it->p = f->ack_ranges;
	it->end = f->ack_ranges + f->ack_ranges_len;
	it->hi = f->ack_largest;
	it->lo = f->ack_largest - f->ack_first;
	it->left = f->ack_count;
}

int hw_qc_ack_iter_next(hw_qc_ack_iter *it) {
	if (!it->left) return 0;
	uint64_t gap = 0, len = 0;
	// The parser checked these decode and do not underflow.
	it->p += hw_qc_vget(it->p, it->end, &gap);
	it->p += hw_qc_vget(it->p, it->end, &len);
	it->hi = it->lo - gap - 2;
	it->lo = it->hi - len;
	it->left--;
	return 1;
}

size_t hw_qc_put_ack(uint8_t *p, size_t room, const hw_qc_ranges *recv, uint64_t delay_field, size_t *ranges_out) {
	if (!recv->n) return 0;
	const hw_qc_range *top = &recv->r[recv->n - 1];
	uint64_t largest = top->hi - 1;
	uint64_t first = largest - top->lo;
	size_t need = 1 + hw_qc_vlen(largest) + hw_qc_vlen(delay_field) + 1 + hw_qc_vlen(first);
	if (need > room) return 0;
	// As many lower ranges as fit (at most 63, so the count is one byte).
	size_t count = 0;
	uint64_t smallest = top->lo;
	for (size_t i = recv->n - 1; i > 0 && count < 63; i--) {
		const hw_qc_range *r = &recv->r[i - 1];
		uint64_t gap = smallest - r->hi - 1;
		uint64_t len = r->hi - 1 - r->lo;
		size_t sz = hw_qc_vlen(gap) + hw_qc_vlen(len);
		if (need + sz > room) break;
		need += sz;
		count++;
		smallest = r->lo;
	}
	uint8_t *q = p;
	*q++ = HW_QC_F_ACK;
	q = hw_qc_vput(q, largest);
	q = hw_qc_vput(q, delay_field);
	q = hw_qc_vput(q, count);
	q = hw_qc_vput(q, first);
	smallest = top->lo;
	for (size_t k = 0; k < count; k++) {
		const hw_qc_range *r = &recv->r[recv->n - 2 - k];
		q = hw_qc_vput(q, smallest - r->hi - 1);
		q = hw_qc_vput(q, r->hi - 1 - r->lo);
		smallest = r->lo;
	}
	if (ranges_out) *ranges_out = count + 1;
	return (size_t)(q - p);
}

size_t hw_qc_put_stream_header(uint8_t *p, size_t room, uint64_t id, uint64_t off, size_t len, int fin) {
	size_t need = 1 + hw_qc_vlen(id) + (off ? hw_qc_vlen(off) : 0) + hw_qc_vlen(len);
	if (need + len > room) return 0;
	uint8_t *q = p;
	*q++ = (uint8_t)(HW_QC_F_STREAM | (off ? 0x04 : 0) | 0x02 | (fin ? 0x01 : 0));
	q = hw_qc_vput(q, id);
	if (off) q = hw_qc_vput(q, off);
	q = hw_qc_vput(q, len);
	return (size_t)(q - p);
}

size_t hw_qc_put_crypto_header(uint8_t *p, size_t room, uint64_t off, size_t len) {
	size_t need = 1 + hw_qc_vlen(off) + hw_qc_vlen(len);
	if (need + len > room) return 0;
	uint8_t *q = p;
	*q++ = HW_QC_F_CRYPTO;
	q = hw_qc_vput(q, off);
	q = hw_qc_vput(q, len);
	return (size_t)(q - p);
}

size_t hw_qc_put_simple(uint8_t *p, size_t room, uint64_t type, uint64_t a) {
	size_t need = hw_qc_vlen(type) + hw_qc_vlen(a);
	if (need > room) return 0;
	uint8_t *q = hw_qc_vput(p, type);
	q = hw_qc_vput(q, a);
	return (size_t)(q - p);
}

size_t hw_qc_put_pair(uint8_t *p, size_t room, uint64_t type, uint64_t a, uint64_t b) {
	size_t need = hw_qc_vlen(type) + hw_qc_vlen(a) + hw_qc_vlen(b);
	if (need > room) return 0;
	uint8_t *q = hw_qc_vput(p, type);
	q = hw_qc_vput(q, a);
	q = hw_qc_vput(q, b);
	return (size_t)(q - p);
}

size_t hw_qc_put_reset_stream(uint8_t *p, size_t room, uint64_t id, uint64_t err, uint64_t final_size) {
	size_t need = 1 + hw_qc_vlen(id) + hw_qc_vlen(err) + hw_qc_vlen(final_size);
	if (need > room) return 0;
	uint8_t *q = p;
	*q++ = HW_QC_F_RESET_STREAM;
	q = hw_qc_vput(q, id);
	q = hw_qc_vput(q, err);
	q = hw_qc_vput(q, final_size);
	return (size_t)(q - p);
}

size_t hw_qc_put_new_cid(uint8_t *p, size_t room, uint64_t seq, uint64_t retire_prior_to, const uint8_t *cid,
                         size_t cid_len, const uint8_t token[HW_QUIC_RESET_LEN]) {
	size_t need = 1 + hw_qc_vlen(seq) + hw_qc_vlen(retire_prior_to) + 1 + cid_len + HW_QUIC_RESET_LEN;
	if (need > room) return 0;
	uint8_t *q = p;
	*q++ = HW_QC_F_NEW_CONNECTION_ID;
	q = hw_qc_vput(q, seq);
	q = hw_qc_vput(q, retire_prior_to);
	*q++ = (uint8_t)cid_len;
	memcpy(q, cid, cid_len);
	q += cid_len;
	memcpy(q, token, HW_QUIC_RESET_LEN);
	q += HW_QUIC_RESET_LEN;
	return (size_t)(q - p);
}

size_t hw_qc_put_path(uint8_t *p, size_t room, uint64_t type, const uint8_t data[8]) {
	if (room < 9) return 0;
	p[0] = (uint8_t)type;
	memcpy(p + 1, data, 8);
	return 9;
}

size_t hw_qc_put_close(uint8_t *p, size_t room, int app, uint64_t err, uint64_t frame_type, const char *reason,
                       size_t reason_len) {
	size_t fixed = 1 + hw_qc_vlen(err) + (app ? 0 : hw_qc_vlen(frame_type));
	if (fixed + 1 > room) return 0;
	// The reason is cut to what fits; the peer gets the code either way.
	size_t max_reason = room - fixed - 1;
	if (max_reason > 63) max_reason = room - fixed - 2 < 16383 ? room - fixed - 2 : 16383;
	if (reason_len > max_reason) reason_len = max_reason;
	if (reason_len > 63 && fixed + 2 + reason_len > room) reason_len = 63;
	uint8_t *q = p;
	*q++ = app ? HW_QC_F_CONNECTION_CLOSE_APP : HW_QC_F_CONNECTION_CLOSE;
	q = hw_qc_vput(q, err);
	if (!app) q = hw_qc_vput(q, frame_type);
	q = hw_qc_vput(q, reason_len);
	if (reason_len) memcpy(q, reason, reason_len);
	q += reason_len;
	return (size_t)(q - p);
}

size_t hw_qc_put_datagram(uint8_t *p, size_t room, const uint8_t *data, size_t len) {
	size_t need = 1 + hw_qc_vlen(len) + len;
	if (need > room) return 0;
	uint8_t *q = p;
	*q++ = HW_QC_F_DATAGRAM_LEN;
	q = hw_qc_vput(q, len);
	memcpy(q, data, len);
	q += len;
	return (size_t)(q - p);
}
