/*
 * src/quic/quic_stream.c - the containers under QUIC streams (quic_internal.h): range sets,
 * the send buffer that keeps bytes until they are acknowledged, the receive reassembly that
 * copies only what arrives out of order, and the stream id map.
 */
#include "quic_internal.h"

#include <stdlib.h>
#include <string.h>

// ---- Range sets ----------------------------------------------------------------------------

void hw_qc_ranges_init(hw_qc_ranges *s, size_t max, int drop) {
	memset(s, 0, sizeof(*s));
	s->max = max;
	s->drop = drop;
}

void hw_qc_ranges_clear(hw_qc_ranges *s) {
	free(s->r);
	s->r = NULL;
	s->n = s->cap = 0;
}

static int ranges_grow(hw_qc_ranges *s) {
	if (s->n < s->cap) return 0;
	size_t cap = s->cap ? s->cap * 2 : 4;
	hw_qc_range *r = realloc(s->r, cap * sizeof(*r));
	if (!r) return -1;
	s->r = r;
	s->cap = cap;
	return 0;
}

// The first range whose hi is >= v (one that ends before v cannot touch it).
static size_t ranges_find(const hw_qc_ranges *s, uint64_t v) {
	size_t lo = 0, hi = s->n;
	while (lo < hi) {
		size_t mid = lo + (hi - lo) / 2;
		if (s->r[mid].hi < v) {
			lo = mid + 1;
		} else {
			hi = mid;
		}
	}
	return lo;
}

int hw_qc_ranges_add(hw_qc_ranges *s, uint64_t lo, uint64_t hi) {
	if (s->drop && lo < s->floor) lo = s->floor;
	if (lo >= hi) return 0;
	// The common case: extending the last range.
	if (s->n && s->r[s->n - 1].hi >= lo && s->r[s->n - 1].lo <= lo) {
		if (hi > s->r[s->n - 1].hi) s->r[s->n - 1].hi = hi;
		return 0;
	}
	size_t i = ranges_find(s, lo);
	size_t j = i;
	while (j < s->n && s->r[j].lo <= hi) j++;
	if (i == j) {
		if (s->max && s->n >= s->max) {
			if (!s->drop) return -1;
			if (i == 0) {
				// Lower than everything kept: it would be the one forgotten.
				if (s->floor < hi) s->floor = hi;
				return 0;
			}
			if (s->floor < s->r[0].hi) s->floor = s->r[0].hi;
			memmove(&s->r[0], &s->r[1], (s->n - 1) * sizeof(s->r[0]));
			s->n--;
			i--;
		}
		if (ranges_grow(s) < 0 || s->n >= s->cap || i > s->n) return -1;
		memmove(&s->r[i + 1], &s->r[i], (s->n - i) * sizeof(s->r[0]));
		s->r[i].lo = lo;
		s->r[i].hi = hi;
		s->n++;
		return 0;
	}
	if (lo < s->r[i].lo) s->r[i].lo = lo;
	s->r[i].hi = HW_MAX(hi, s->r[j - 1].hi);
	if (j - i > 1) {
		memmove(&s->r[i + 1], &s->r[j], (s->n - j) * sizeof(s->r[0]));
		s->n -= j - i - 1;
	}
	return 0;
}

int hw_qc_ranges_remove(hw_qc_ranges *s, uint64_t lo, uint64_t hi) {
	if (lo >= hi || !s->n) return 0;
	size_t i = ranges_find(s, lo + 1);
	while (i < s->n && s->r[i].lo < hi) {
		hw_qc_range *r = &s->r[i];
		if (r->lo >= lo && r->hi <= hi) {
			memmove(&s->r[i], &s->r[i + 1], (s->n - i - 1) * sizeof(s->r[0]));
			s->n--;
			continue;
		}
		if (r->lo < lo && r->hi > hi) {
			if (ranges_grow(s) < 0) return -1;
			memmove(&s->r[i + 1], &s->r[i], (s->n - i) * sizeof(s->r[0]));
			s->n++;
			s->r[i].hi = lo;
			s->r[i + 1].lo = hi;
			return 0;
		}
		if (r->lo < lo) {
			r->hi = lo;
		} else {
			r->lo = hi;
		}
		i++;
	}
	return 0;
}

int hw_qc_ranges_contains(const hw_qc_ranges *s, uint64_t v) {
	if (s->drop && v < s->floor) return 1;
	size_t i = ranges_find(s, v + 1);
	return i < s->n && s->r[i].lo <= v;
}

void hw_qc_ranges_forget_below(hw_qc_ranges *s, uint64_t v) {
	size_t k = 0;
	while (k < s->n && s->r[k].hi <= v) k++;
	if (k) {
		memmove(&s->r[0], &s->r[k], (s->n - k) * sizeof(s->r[0]));
		s->n -= k;
	}
}

void hw_qc_ranges_prune_below(hw_qc_ranges *s, uint64_t v) {
	hw_qc_ranges_forget_below(s, v);
	if (s->floor < v) s->floor = v;
}

// ---- Ring helpers --------------------------------------------------------------------------

static void ring_put(uint8_t *buf, size_t cap, uint64_t off, const uint8_t *src, size_t len) {
	size_t pos = (size_t)(off & (cap - 1));
	size_t first = HW_MIN(len, cap - pos);
	memcpy(buf + pos, src, first);
	if (len > first) memcpy(buf, src + first, len - first);
}

static void ring_get(const uint8_t *buf, size_t cap, uint64_t off, uint8_t *dst, size_t len) {
	size_t pos = (size_t)(off & (cap - 1));
	size_t first = HW_MIN(len, cap - pos);
	memcpy(dst, buf + pos, first);
	if (len > first) memcpy(dst + first, buf, len - first);
}

static size_t pow2_at_least(size_t n) {
	size_t c = 4096;
	while (c < n) c *= 2;
	return c;
}

// ---- Send buffer ---------------------------------------------------------------------------

void hw_qc_sendbuf_init(hw_qc_sendbuf *b) {
	memset(b, 0, sizeof(*b));
	hw_qc_ranges_init(&b->acked, 0, 0);
	hw_qc_ranges_init(&b->lost, 0, 0);
}

void hw_qc_sendbuf_clear(hw_qc_sendbuf *b) {
	free(b->buf);
	hw_qc_ranges_clear(&b->acked);
	hw_qc_ranges_clear(&b->lost);
	b->buf = NULL;
	b->cap = 0;
}

int hw_qc_sendbuf_write(hw_qc_sendbuf *b, const uint8_t *data, size_t len) {
	if (!len) return 0;
	size_t held = (size_t)(b->end - b->base);
	if (held + len > b->cap) {
		size_t cap = pow2_at_least(held + len);
		uint8_t *nb = malloc(cap);
		if (!nb) return -1;
		// Re-lay the held bytes at their positions in the bigger ring.
		for (uint64_t off = b->base; off < b->end;) {
			size_t pos = (size_t)(off & (b->cap - 1));
			size_t n = (size_t)HW_MIN(b->end - off, (uint64_t)(b->cap - pos));
			ring_put(nb, cap, off, b->buf + pos, n);
			off += n;
		}
		free(b->buf);
		b->buf = nb;
		b->cap = cap;
	}
	ring_put(b->buf, b->cap, b->end, data, len);
	b->end += len;
	return 0;
}

int hw_qc_sendbuf_pending(const hw_qc_sendbuf *b) {
	if (b->lost.n || b->sent < b->end) return 1;
	if (b->fin && (!b->fin_sent || b->fin_lost) && !b->fin_acked) return 1;
	return 0;
}

int hw_qc_sendbuf_next(const hw_qc_sendbuf *b, size_t max, uint64_t *off, size_t *len, int *fin) {
	if (b->lost.n) {
		const hw_qc_range *r = &b->lost.r[0];
		uint64_t n = HW_MIN(r->hi - r->lo, (uint64_t)max);
		*off = r->lo;
		*len = (size_t)n;
		*fin = b->fin && r->lo + n == b->end && b->sent == b->end && (b->fin_lost || !b->fin_sent) && !b->fin_acked;
		return n > 0 || *fin;
	}
	if (b->sent < b->end) {
		uint64_t n = HW_MIN(b->end - b->sent, (uint64_t)max);
		*off = b->sent;
		*len = (size_t)n;
		*fin = b->fin && b->sent + n == b->end && !b->fin_acked;
		return n > 0 || *fin;
	}
	if (b->fin && (!b->fin_sent || b->fin_lost) && !b->fin_acked) {
		*off = b->end;
		*len = 0;
		*fin = 1;
		return 1;
	}
	return 0;
}

void hw_qc_sendbuf_copy(const hw_qc_sendbuf *b, uint64_t off, size_t len, uint8_t *dst) {
	if (len) ring_get(b->buf, b->cap, off, dst, len);
}

void hw_qc_sendbuf_sent(hw_qc_sendbuf *b, uint64_t off, size_t len, int fin) {
	if (b->lost.n) hw_qc_ranges_remove(&b->lost, off, off + len);
	if (off + len > b->sent) b->sent = off + len;
	if (fin) {
		b->fin_sent = 1;
		b->fin_lost = 0;
	}
}

size_t hw_qc_sendbuf_ack(hw_qc_sendbuf *b, uint64_t off, size_t len, int fin) {
	if (fin) b->fin_acked = 1;
	uint64_t lo = HW_MAX(off, b->base), hi = off + len;
	if (lo >= hi) return 0;
	if (b->lost.n) hw_qc_ranges_remove(&b->lost, lo, hi);
	if (lo == b->base && (!b->acked.n || b->acked.r[0].lo > hi)) {
		// In-order acknowledgment, the usual case: no range to keep.
		b->base = hi;
		return (size_t)(hi - lo);
	}
	if (hw_qc_ranges_add(&b->acked, lo, hi) < 0) return 0; // forgotten, sent again if lost: harmless
	if (b->acked.r[0].lo != b->base) return 0;
	uint64_t nb = b->acked.r[0].hi;
	size_t freed = (size_t)(nb - b->base);
	b->base = nb;
	memmove(&b->acked.r[0], &b->acked.r[1], (b->acked.n - 1) * sizeof(b->acked.r[0]));
	b->acked.n--;
	return freed;
}

void hw_qc_sendbuf_lost(hw_qc_sendbuf *b, uint64_t off, size_t len, int fin) {
	if (fin && !b->fin_acked) b->fin_lost = 1;
	uint64_t lo = HW_MAX(off, b->base), hi = off + len;
	if (hi > b->sent) hi = b->sent;
	if (lo >= hi) return;
	// Add [lo, hi) minus the acknowledged ranges.
	size_t i = 0;
	while (i < b->acked.n && b->acked.r[i].hi <= lo) i++;
	uint64_t at = lo;
	for (; i < b->acked.n && b->acked.r[i].lo < hi; i++) {
		if (b->acked.r[i].lo > at) hw_qc_ranges_add(&b->lost, at, b->acked.r[i].lo);
		at = HW_MAX(at, b->acked.r[i].hi);
	}
	if (at < hi) hw_qc_ranges_add(&b->lost, at, hi);
}

// ---- Receive reassembly --------------------------------------------------------------------

void hw_qc_recvbuf_init(hw_qc_recvbuf *b, size_t max_ranges) {
	memset(b, 0, sizeof(*b));
	b->final = HW_QC_NONE;
	hw_qc_ranges_init(&b->have, max_ranges, 0);
}

void hw_qc_recvbuf_clear(hw_qc_recvbuf *b) {
	free(b->buf);
	b->buf = NULL;
	b->cap = 0;
	hw_qc_ranges_clear(&b->have);
}

static int recvbuf_fit(hw_qc_recvbuf *b, uint64_t hi) {
	size_t need = (size_t)(hi - b->off);
	if (need <= b->cap) return 0;
	size_t cap = pow2_at_least(need);
	uint8_t *nb = malloc(cap);
	if (!nb) return -1;
	for (size_t i = 0; i < b->have.n; i++) {
		for (uint64_t off = b->have.r[i].lo; off < b->have.r[i].hi;) {
			size_t pos = (size_t)(off & (b->cap - 1));
			size_t n = (size_t)HW_MIN(b->have.r[i].hi - off, (uint64_t)(b->cap - pos));
			ring_put(nb, cap, off, b->buf + pos, n);
			off += n;
		}
	}
	free(b->buf);
	b->buf = nb;
	b->cap = cap;
	return 0;
}

int hw_qc_recvbuf_push(hw_qc_recvbuf *b, uint64_t off, const uint8_t *data, size_t len, const uint8_t **direct,
                       size_t *direct_len) {
	*direct = NULL;
	*direct_len = 0;
	uint64_t hi = off + len;
	if (hi > b->highest) b->highest = hi;
	if (hi <= b->off) return 0;
	if (off <= b->off) {
		// At the delivered offset: hand it over as it is.
		*direct = data + (b->off - off);
		*direct_len = (size_t)(hi - b->off);
		return 0;
	}
	// Ahead of it: copy what is not held already.
	if (recvbuf_fit(b, hi) < 0) return -1;
	size_t i = 0;
	while (i < b->have.n && b->have.r[i].hi <= off) i++;
	uint64_t at = off;
	for (; i < b->have.n && b->have.r[i].lo < hi; i++) {
		if (b->have.r[i].lo > at) ring_put(b->buf, b->cap, at, data + (at - off), (size_t)(b->have.r[i].lo - at));
		at = HW_MAX(at, b->have.r[i].hi);
	}
	if (at < hi) ring_put(b->buf, b->cap, at, data + (at - off), (size_t)(hi - at));
	return hw_qc_ranges_add(&b->have, off, hi);
}

void hw_qc_recvbuf_advance(hw_qc_recvbuf *b, size_t n) {
	b->off += n;
	if (b->have.n) hw_qc_ranges_remove(&b->have, 0, b->off);
}

size_t hw_qc_recvbuf_peek(const hw_qc_recvbuf *b, const uint8_t **p) {
	if (!b->have.n || b->have.r[0].lo > b->off) return 0;
	size_t pos = (size_t)(b->off & (b->cap - 1));
	size_t n = (size_t)HW_MIN(b->have.r[0].hi - b->off, (uint64_t)(b->cap - pos));
	*p = b->buf + pos;
	return n;
}

// ---- Stream map ----------------------------------------------------------------------------

void hw_qc_smap_init(hw_qc_smap *m) {
	memset(m, 0, sizeof(*m));
}

void hw_qc_smap_clear(hw_qc_smap *m) {
	free(m->slot);
	memset(m, 0, sizeof(*m));
}

// Stream ids are bounded by the stream limits the endpoint grants, so the peer cannot pick them
// to collide; a multiplicative hash is enough.
static size_t smap_hash(uint64_t id, size_t cap) {
	return (size_t)((id * 0x9e3779b97f4a7c15ull) >> 32) & (cap - 1);
}

hw_qc_stream *hw_qc_smap_get(const hw_qc_smap *m, uint64_t id) {
	if (!m->cap) return NULL;
	for (size_t i = smap_hash(id, m->cap);; i = (i + 1) & (m->cap - 1)) {
		hw_qc_stream *s = m->slot[i];
		if (!s) return NULL;
		if (s->id == id) return s;
	}
}

static int smap_insert(hw_qc_stream **slot, size_t cap, hw_qc_stream *s) {
	size_t i = smap_hash(s->id, cap);
	while (slot[i]) {
		if (slot[i]->id == s->id) return 1;
		i = (i + 1) & (cap - 1);
	}
	slot[i] = s;
	return 0;
}

int hw_qc_smap_put(hw_qc_smap *m, hw_qc_stream *s) {
	if ((m->count + 1) * 2 > m->cap) {
		size_t cap = m->cap ? m->cap * 2 : 16;
		hw_qc_stream **slot = calloc(cap, sizeof(*slot));
		if (!slot) return -1;
		for (size_t i = 0; i < m->cap; i++) {
			if (m->slot[i]) smap_insert(slot, cap, m->slot[i]);
		}
		free(m->slot);
		m->slot = slot;
		m->cap = cap;
	}
	if (smap_insert(m->slot, m->cap, s) == 0) m->count++;
	return 0;
}

void hw_qc_smap_remove(hw_qc_smap *m, uint64_t id) {
	if (!m->cap) return;
	size_t mask = m->cap - 1;
	size_t i = smap_hash(id, m->cap);
	while (m->slot[i] && m->slot[i]->id != id) i = (i + 1) & mask;
	if (!m->slot[i]) return;
	m->slot[i] = NULL;
	m->count--;
	// Backward shift: pull later entries of the run into the hole when their home allows.
	for (size_t j = (i + 1) & mask; m->slot[j]; j = (j + 1) & mask) {
		size_t home = smap_hash(m->slot[j]->id, m->cap);
		// The entry at j may move to i when i lies cyclically in [home, j).
		int movable = (j > i) ? (home <= i || home > j) : (home <= i && home > j);
		if (movable) {
			m->slot[i] = m->slot[j];
			m->slot[j] = NULL;
			i = j;
		}
	}
}
