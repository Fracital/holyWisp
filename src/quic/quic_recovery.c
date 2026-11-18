/*
 * src/quic/quic_recovery.c - RFC 9002's arithmetic: the RTT estimator, NewReno congestion
 * control with its recovery period and persistent congestion, the undoing of a recovery period
 * whose every loss proved spurious, the pacer (section 7.7), and the ring of sent packets loss
 * detection walks. The decisions that need the connection (which packets are lost, what to send
 * again, the adaptive loss thresholds) are quic.c's.
 */
#include "quic_internal.h"

#include <stdlib.h>
#include <string.h>

// ---- RTT (section 5) -----------------------------------------------------------------------

void hw_qc_rtt_init(hw_qc_rtt *r) {
	memset(r, 0, sizeof(*r));
	r->smoothed = HW_QC_INITIAL_RTT_US;
	r->var = HW_QC_INITIAL_RTT_US / 2;
}

void hw_qc_rtt_sample(hw_qc_rtt *r, uint64_t latest, uint64_t ack_delay, uint64_t now) {
	r->latest = latest;
	if (!r->has_sample) {
		r->has_sample = 1;
		r->first_sample_time = now;
		r->min = latest;
		r->smoothed = latest;
		r->var = latest / 2;
		return;
	}
	if (latest < r->min) r->min = latest;
	// The ack delay comes off only when that does not take the sample under min_rtt.
	uint64_t adjusted = latest;
	if (latest >= r->min + ack_delay) adjusted = latest - ack_delay;
	uint64_t diff = r->smoothed > adjusted ? r->smoothed - adjusted : adjusted - r->smoothed;
	r->var = (3 * r->var + diff) / 4;
	r->smoothed = (7 * r->smoothed + adjusted) / 8;
}

uint64_t hw_qc_rtt_pto(const hw_qc_rtt *r) {
	return r->smoothed + HW_MAX(4 * r->var, (uint64_t)HW_QC_GRANULARITY_US);
}

uint64_t hw_qc_rtt_loss_delay(const hw_qc_rtt *r, unsigned shift) {
	uint64_t d = HW_MAX(r->latest, r->smoothed);
	d += d >> shift;
	return HW_MAX(d, (uint64_t)HW_QC_GRANULARITY_US);
}

// ---- NewReno (section 7, appendix B) -------------------------------------------------------

#define CC_CWND_MAX (256ull << 20) // a bound so that nothing overflows; far past any real window

static uint64_t cc_min_window(const hw_qc_cc *c) {
	return 2 * c->mds;
}

void hw_qc_cc_init(hw_qc_cc *c, uint64_t mds, uint64_t now) {
	memset(c, 0, sizeof(*c));
	c->mds = mds;
	c->cwnd = HW_MIN(10 * mds, HW_MAX(14720u, 2 * mds));
	c->ssthresh = UINT64_MAX;
	c->tokens = c->cwnd;
	c->last_refill = now;
}

void hw_qc_cc_on_sent(hw_qc_cc *c, uint64_t bytes) {
	c->in_flight += bytes;
}

void hw_qc_cc_remove(hw_qc_cc *c, uint64_t bytes) {
	c->in_flight = c->in_flight > bytes ? c->in_flight - bytes : 0;
}

void hw_qc_cc_on_acked(hw_qc_cc *c, uint64_t bytes, uint64_t time_sent, int limited) {
	hw_qc_cc_remove(c, bytes);
	if (limited) return;
	if (c->in_recovery_valid && time_sent <= c->recovery_start) return;
	if (c->cwnd >= CC_CWND_MAX) return;
	if (c->cwnd < c->ssthresh) {
		c->cwnd += bytes;
		return;
	}
	// Congestion avoidance: one datagram per window acknowledged.
	c->ca_acked += bytes;
	if (c->ca_acked >= c->cwnd) {
		c->ca_acked -= c->cwnd;
		c->cwnd += c->mds;
	}
}

void hw_qc_cc_congestion_event(hw_qc_cc *c, uint64_t time_sent, uint64_t nlost, uint64_t now) {
	if (c->in_recovery_valid && time_sent <= c->recovery_start) {
		c->undo_lost += nlost;
		return;
	}
	c->epoch++;
	c->undo_cwnd = c->cwnd;
	c->undo_ssthresh = c->ssthresh;
	c->undo_lost = nlost;
	c->undo_ok = 1;
	c->in_recovery_valid = 1;
	c->recovery_start = now;
	c->ssthresh = HW_MAX(c->cwnd / 2, cc_min_window(c));
	c->cwnd = c->ssthresh;
	c->ca_acked = 0;
}

void hw_qc_cc_persistent(hw_qc_cc *c) {
	c->cwnd = cc_min_window(c);
	c->ca_acked = 0;
	c->undo_ok = 0;
}

// Only the current period is undone, and only when every packet it declared lost came back:
// one that never does was lost, and the reduction stands. An older period's packet proves
// nothing about the current one.
int hw_qc_cc_spurious(hw_qc_cc *c, uint16_t epoch) {
	if (!c->undo_ok || epoch != c->epoch || !c->undo_lost) return 0;
	if (--c->undo_lost) return 0;
	c->undo_ok = 0;
	c->cwnd = HW_MAX(c->cwnd, c->undo_cwnd);
	c->ssthresh = c->undo_ssthresh;
	c->in_recovery_valid = 0;
	c->ca_acked = 0;
	return 1;
}

// ---- Pacer (section 7.7) -------------------------------------------------------------------
// A token bucket: rate 5/4 * cwnd / smoothed_rtt, a burst of the larger of ten datagrams and
// two milliseconds' worth (the caller's clock ticks in milliseconds, so a smaller burst would
// cap the rate rather than smooth it), never more than the window.

static uint64_t pacer_rate(const hw_qc_cc *c, const hw_qc_rtt *r) {
	uint64_t srtt = HW_MAX(r->smoothed, (uint64_t)HW_QC_GRANULARITY_US);
	// bytes per second
	return (c->cwnd * 5 / 4) * 1000000 / srtt;
}

uint64_t hw_qc_pacer_next(hw_qc_cc *c, const hw_qc_rtt *r, uint64_t now) {
	uint64_t rate = pacer_rate(c, r);
	uint64_t burst = HW_MAX(10 * c->mds, rate / 500);
	if (burst > c->cwnd) burst = HW_MAX(c->cwnd, 2 * c->mds);
	if (now > c->last_refill) {
		uint64_t add = (now - c->last_refill) * rate / 1000000;
		if (add) {
			c->tokens = HW_MIN(c->tokens + add, burst);
			c->last_refill = now;
		}
	} else if (now < c->last_refill) {
		c->last_refill = now;
	}
	if (c->tokens > burst) c->tokens = burst;
	if (c->tokens >= c->mds) return now;
	uint64_t wait = (c->mds - c->tokens) * 1000000 / (rate ? rate : 1) + 1;
	return c->last_refill + wait;
}

void hw_qc_pacer_on_sent(hw_qc_cc *c, uint64_t bytes) {
	c->tokens = c->tokens > bytes ? c->tokens - bytes : 0;
}

// ---- Sent packet ring ----------------------------------------------------------------------

void hw_qc_ring_init(hw_qc_ring *r) {
	memset(r, 0, sizeof(*r));
}

void hw_qc_ring_clear(hw_qc_ring *r) {
	free(r->pk);
	free(r->fr);
	uint64_t next = r->next;
	memset(r, 0, sizeof(*r));
	r->base = r->next = next;
}

int hw_qc_ring_reserve(hw_qc_ring *r, size_t nframes) {
	if (r->next - r->base + 1 > r->pcap) {
		size_t cap = r->pcap ? r->pcap * 2 : 64;
		hw_qc_sent *pk = malloc(cap * sizeof(*pk));
		if (!pk) return -1;
		for (uint64_t pn = r->base; pn < r->next; pn++) pk[pn & (cap - 1)] = r->pk[pn & (r->pcap - 1)];
		free(r->pk);
		r->pk = pk;
		r->pcap = cap;
	}
	if (r->fhead - r->ftail + nframes > r->fcap) {
		size_t cap = r->fcap ? r->fcap : 256;
		while (cap < r->fhead - r->ftail + nframes) cap *= 2;
		hw_qc_frec *fr = malloc(cap * sizeof(*fr));
		if (!fr) return -1;
		for (uint64_t i = r->ftail; i < r->fhead; i++) fr[i & (cap - 1)] = r->fr[i & (r->fcap - 1)];
		free(r->fr);
		r->fr = fr;
		r->fcap = cap;
	}
	return 0;
}

void hw_qc_ring_add_frame(hw_qc_ring *r, const hw_qc_frec *f) {
	r->fr[r->fhead & (r->fcap - 1)] = *f;
	r->fhead++;
}

void hw_qc_ring_add_packet(hw_qc_ring *r, const hw_qc_sent *s) {
	r->pk[r->next & (r->pcap - 1)] = *s;
	r->next++;
}

void hw_qc_ring_trim(hw_qc_ring *r, uint64_t keep_since) {
	while (r->base < r->next) {
		hw_qc_sent *s = &r->pk[r->base & (r->pcap - 1)];
		int resolved = (s->flags & HW_QC_SENT_ACKED) || ((s->flags & HW_QC_SENT_LOST) && s->time < keep_since);
		// A packet nothing waits for (ACK-only, not in flight) may be forgotten once the ring
		// is long: the peer never has to acknowledge those.
		if (!resolved && !(s->flags & HW_QC_SENT_IN_FLIGHT) && r->next - r->base > HW_QC_SENT_RING_MAX) resolved = 1;
		if (!resolved) break;
		r->base++;
		r->ftail = r->base < r->next ? r->pk[r->base & (r->pcap - 1)].frame0 : r->fhead;
	}
}
