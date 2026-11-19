/*
 * src/quic/quic_recovery.c - RFC 9002's arithmetic: the RTT estimator, NewReno congestion
 * control with its recovery period and persistent congestion, the undoing of a recovery period
 * whose every loss proved spurious, the pacer (section 7.7), and the ring of sent packets loss
 * detection walks. BBR replaces NewReno's window where the connection asks for it: delivery
 * rate samples, the bandwidth and min-RTT model, and the pacing rate and window it sets. The decisions that need the
 * connection (which packets are lost, what to send again, the adaptive loss thresholds) are quic.c's.
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
	if (c->bbr) {
		c->rs.acked += bytes; // the window moves in hw_qc_cc_on_ack_done
		return;
	}
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
	c->rs.lost += nlost;
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
	// BBR does not take a loss for congestion: its model is the delivery rate, which random
	// loss does not move (the reason it is here: NewReno halved its window on every one of a
	// path's 0.3% and ran at a tenth of the same path's TCP).
	if (c->bbr) return;
	c->ssthresh = HW_MAX(c->cwnd / 2, cc_min_window(c));
	c->cwnd = c->ssthresh;
	c->ca_acked = 0;
}

void hw_qc_cc_persistent(hw_qc_cc *c) {
	c->cwnd = c->bbr ? 4 * c->mds : cc_min_window(c);
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

// ---- Delivery rate estimation -------------------------------------------------------------

void hw_qc_rs_on_sent(hw_qc_cc *c, hw_qc_sent *s, uint64_t now) {
	if (c->in_flight == 0) c->first_sent_time = c->delivered_time = now;
	s->delivered = c->delivered;
	s->delivered_time = c->delivered_time;
	s->first_sent_time = c->first_sent_time;
	s->rs_app_limited = c->app_limited != 0;
}

void hw_qc_rs_on_acked(hw_qc_cc *c, const hw_qc_sent *s, uint64_t now) {
	c->delivered += s->size;
	c->delivered_time = now;
	// The sample is the newest packet's: the one sent with the most delivered before it.
	if (!c->rs.has || s->delivered >= c->rs.prior_delivered) {
		c->rs.has = 1;
		c->rs.prior_delivered = s->delivered;
		c->rs.prior_time = s->delivered_time;
		c->rs.is_app_limited = s->rs_app_limited;
		c->rs.send_elapsed = s->time > s->first_sent_time ? s->time - s->first_sent_time : 0;
		c->rs.ack_elapsed = now > s->delivered_time ? now - s->delivered_time : 0;
		c->first_sent_time = s->time;
	}
}

void hw_qc_cc_app_limited(hw_qc_cc *c) {
	uint64_t mark = c->delivered + c->in_flight;
	c->app_limited = mark ? mark : 1;
	if (c->in_flight == 0) c->b.idle_restart = 1;
}

// ---- BBR -----------------------------------------------------------------------------------
// Version 1 with Linux's constants: gains in 1/256, a bandwidth filter over 10 rounds, a min
// RTT that expires after 10 s and is measured again with 4 packets in flight for 200 ms.

#define BBR_UNIT              256u
#define BBR_HIGH_GAIN         739u // 2/ln(2): startup doubles the delivery rate each round
#define BBR_DRAIN_GAIN        88u  // its inverse, to empty the queue startup built
#define BBR_CWND_GAIN         512u
#define BBR_BW_ROUNDS         10u
#define BBR_MIN_RTT_US        (10ull * 1000000)
#define BBR_PROBE_RTT_US      (200ull * 1000)
#define BBR_FULL_BW_THRESH    320u // 1.25: startup goes on while the bandwidth grows this much
#define BBR_FULL_BW_CNT       3u   // in a round, for this many rounds
#define BBR_MIN_CWND_PACKETS  4u
#define BBR_PACING_MARGIN_PCT 1u // pace 1% under the estimate, so a queue does not build

#define BBR_EXTRA_ACKED_ROUNDS 5u
#define BBR_EXTRA_ACKED_MAX_US (100ull * 1000) // never more than 100 ms of the rate

static const unsigned BBR_CYCLE_GAIN[8] = {320, 192, 256, 256, 256, 256, 256, 256};

static uint64_t bbr_min_cwnd(const hw_qc_cc *c) {
	return BBR_MIN_CWND_PACKETS * c->mds;
}

// The windowed max filter: three samples, each the best of a third of the window or newer.
static void bbr_bw_reset(hw_qc_cc *c, uint64_t t, uint64_t v) {
	for (int i = 0; i < 3; i++) {
		c->b.bw_s[i] = v;
		c->b.bw_t[i] = t;
	}
}

static void bbr_bw_update(hw_qc_cc *c, uint64_t t, uint64_t v) {
	uint64_t *s = c->b.bw_s, *ts = c->b.bw_t;
	const uint64_t win = BBR_BW_ROUNDS;
	if (v >= s[0] || t - ts[2] > win) {
		bbr_bw_reset(c, t, v);
		return;
	}
	if (v >= s[1]) {
		s[1] = s[2] = v;
		ts[1] = ts[2] = t;
	} else if (v >= s[2]) {
		s[2] = v;
		ts[2] = t;
	}
	// The best expired: the second takes its place, and so on.
	uint64_t dt = t - ts[0];
	if (dt > win) {
		s[0] = s[1];
		ts[0] = ts[1];
		s[1] = s[2];
		ts[1] = ts[2];
		s[2] = v;
		ts[2] = t;
		if (t - ts[0] > win) {
			s[0] = s[1];
			ts[0] = ts[1];
			s[1] = s[2];
			ts[1] = ts[2];
		}
	} else if (ts[1] == ts[0] && dt > win / 4) {
		s[1] = s[2] = v;
		ts[1] = ts[2] = t;
	} else if (ts[2] == ts[1] && dt > win / 2) {
		s[2] = v;
		ts[2] = t;
	}
}

// bw * min_rtt * gain, in bytes; the initial window while either is unknown.
static uint64_t bbr_bdp(const hw_qc_cc *c, unsigned gain) {
	if (!c->b.bw || c->b.min_rtt == UINT64_MAX) return c->b.init_cwnd;
	uint64_t bdp = c->b.bw * c->b.min_rtt / 1000000;
	return bdp * gain / BBR_UNIT;
}

void hw_qc_cc_use_bbr(hw_qc_cc *c, uint64_t now) {
	c->bbr = 1;
	memset(&c->b, 0, sizeof(c->b));
	c->b.init_cwnd = c->cwnd;
	c->b.min_rtt = c->b.min_rtt_raw = UINT64_MAX;
	c->b.min_rtt_stamp = now;
	c->b.mode = HW_QC_BBR_STARTUP;
	c->b.pacing_gain = c->b.cwnd_gain = BBR_HIGH_GAIN;
	c->ssthresh = UINT64_MAX;
}

static void bbr_enter_probe_bw(hw_qc_cc *c, uint64_t now) {
	c->b.mode = HW_QC_BBR_PROBE_BW;
	// Any phase but the one that drains, so that flows started together do not probe together.
	unsigned r = (unsigned)((c->delivered ^ (now >> 3)) % 7u);
	c->b.cycle_idx = r == 0 ? 0 : r + 1;
	c->b.cycle_stamp = now;
}

static void bbr_update_cycle(hw_qc_cc *c, uint64_t now) {
	if (c->b.mode != HW_QC_BBR_PROBE_BW) return;
	unsigned gain = BBR_CYCLE_GAIN[c->b.cycle_idx];
	int elapsed = c->b.min_rtt != UINT64_MAX && now - c->b.cycle_stamp > c->b.min_rtt;
	int next;
	if (gain > BBR_UNIT) {
		next = elapsed && (c->rs.lost || c->in_flight >= bbr_bdp(c, gain));
	} else if (gain < BBR_UNIT) {
		next = elapsed || c->in_flight <= bbr_bdp(c, BBR_UNIT);
	} else {
		next = elapsed;
	}
	if (next) {
		c->b.cycle_idx = (c->b.cycle_idx + 1) & 7u;
		c->b.cycle_stamp = now;
	}
}

static void bbr_check_full_bw(hw_qc_cc *c) {
	if (c->b.full_bw_reached || !c->b.round_start || c->rs.is_app_limited) return;
	if (c->b.bw >= c->b.full_bw * BBR_FULL_BW_THRESH / BBR_UNIT) {
		c->b.full_bw = c->b.bw;
		c->b.full_bw_cnt = 0;
		return;
	}
	if (++c->b.full_bw_cnt >= BBR_FULL_BW_CNT) c->b.full_bw_reached = 1;
}

// rtt_raw is the sample as measured; the model's min RTT is never under a tick of the timers,
// which pace and probe no finer than that (at 0 a loopback window was 4 packets).
static void bbr_update_min_rtt(hw_qc_cc *c, uint64_t rtt_raw, uint64_t now) {
	int expired = now > c->b.min_rtt_stamp + BBR_MIN_RTT_US;
	uint64_t rtt_us = rtt_raw ? HW_MAX(rtt_raw, (uint64_t)HW_QC_GRANULARITY_US) : 0;
	if (rtt_raw && (rtt_raw < c->b.min_rtt_raw || expired)) c->b.min_rtt_raw = rtt_raw;
	if (rtt_us && (rtt_us < c->b.min_rtt || expired)) {
		c->b.min_rtt = rtt_us;
		c->b.min_rtt_stamp = now;
	}
	if (expired && !c->b.idle_restart && c->b.mode != HW_QC_BBR_PROBE_RTT) {
		c->b.mode = HW_QC_BBR_PROBE_RTT;
		c->b.prior_cwnd = HW_MAX(c->b.prior_cwnd, c->cwnd);
		c->b.probe_rtt_done = 0;
	}
	if (c->b.mode == HW_QC_BBR_PROBE_RTT) {
		// Its samples measure four packets, not the path, and so do those that span its end: the
		// connection counts as app-limited until what is in flight now is delivered, as in Linux.
		// They may raise the estimate, never replace it: after an app-limited stretch longer than
		// the filter's window one of them did, whole, and the window after the probe was twice the
		// BDP of four packets.
		uint64_t mark = c->delivered + c->in_flight;
		c->app_limited = mark ? mark : 1;
		if (!c->b.probe_rtt_done && c->in_flight <= bbr_min_cwnd(c)) {
			c->b.probe_rtt_done = now + BBR_PROBE_RTT_US;
			c->b.probe_rtt_round_done = 0;
			c->b.next_round_delivered = c->delivered;
		} else if (c->b.probe_rtt_done) {
			if (c->b.round_start) c->b.probe_rtt_round_done = 1;
			if (c->b.probe_rtt_round_done && now > c->b.probe_rtt_done) {
				c->b.min_rtt_stamp = now;
				c->cwnd = HW_MAX(c->cwnd, c->b.prior_cwnd);
				c->b.prior_cwnd = 0;
				if (c->b.full_bw_reached) {
					bbr_enter_probe_bw(c, now);
				} else {
					c->b.mode = HW_QC_BBR_STARTUP;
				}
			}
		}
	}
	if (rtt_us) c->b.idle_restart = 0;
}

static void bbr_update_ack_aggregation(hw_qc_cc *c, uint64_t acked, uint64_t now) {
	if (!acked || !c->b.bw) return;
	if (c->b.round_start && ++c->b.extra_acked_rounds >= BBR_EXTRA_ACKED_ROUNDS) {
		c->b.extra_acked_rounds = 0;
		c->b.extra_acked_idx ^= 1u;
		c->b.extra_acked[c->b.extra_acked_idx] = 0;
	}
	uint64_t expected = c->b.bw * (now - c->b.ack_epoch_start) / 1000000;
	if (c->b.ack_epoch_acked <= expected) {
		c->b.ack_epoch_acked = 0;
		c->b.ack_epoch_start = now;
		expected = 0;
	}
	c->b.ack_epoch_acked += acked;
	uint64_t extra = HW_MIN(c->b.ack_epoch_acked - expected, c->cwnd);
	if (extra > c->b.extra_acked[c->b.extra_acked_idx]) c->b.extra_acked[c->b.extra_acked_idx] = extra;
}

static uint64_t bbr_ack_aggregation_cwnd(const hw_qc_cc *c) {
	if (!c->b.full_bw_reached) return 0;
	uint64_t a = HW_MAX(c->b.extra_acked[0], c->b.extra_acked[1]);
	return HW_MIN(a, c->b.bw * BBR_EXTRA_ACKED_MAX_US / 1000000);
}

static void bbr_update_gains(hw_qc_cc *c) {
	switch (c->b.mode) {
	case HW_QC_BBR_STARTUP:
		c->b.pacing_gain = c->b.cwnd_gain = BBR_HIGH_GAIN;
		break;
	case HW_QC_BBR_DRAIN:
		c->b.pacing_gain = BBR_DRAIN_GAIN;
		c->b.cwnd_gain = BBR_HIGH_GAIN;
		break;
	case HW_QC_BBR_PROBE_BW:
		c->b.pacing_gain = BBR_CYCLE_GAIN[c->b.cycle_idx];
		c->b.cwnd_gain = BBR_CWND_GAIN;
		break;
	default:
		c->b.pacing_gain = c->b.cwnd_gain = BBR_UNIT;
		break;
	}
}

void hw_qc_cc_on_ack_done(hw_qc_cc *c, uint64_t rtt_us, uint64_t now) {
	if (c->app_limited && c->delivered > c->app_limited) c->app_limited = 0;
	if (!c->bbr) {
		memset(&c->rs, 0, sizeof(c->rs));
		return;
	}
	// The sample: bytes delivered over the longer of its send and ack intervals. One shorter
	// than the min RTT is a burst of ACKs, not the path: the RTT as measured, not the model's,
	// which is floored to a tick. Against the tick, a path shorter than one kept only the samples
	// that spanned a stall, and a loopback session ran at a fifth of its speed.
	uint64_t rate = 0;
	if (c->rs.has) {
		uint64_t delivered = c->delivered - c->rs.prior_delivered;
		uint64_t interval = HW_MAX(c->rs.send_elapsed, c->rs.ack_elapsed);
		uint64_t floor = c->b.min_rtt_raw != UINT64_MAX ? c->b.min_rtt_raw : rtt_us;
		if (delivered && interval && interval >= floor) rate = delivered * 1000000 / interval;
		// A round ends when a packet sent after the previous round began is acknowledged.
		c->b.round_start = 0;
		if (c->rs.prior_delivered >= c->b.next_round_delivered) {
			c->b.next_round_delivered = c->delivered;
			c->b.round_count++;
			c->b.round_start = 1;
		}
	} else {
		c->b.round_start = 0;
	}
	if (rate && (!c->rs.is_app_limited || rate >= c->b.bw)) {
		bbr_bw_update(c, c->b.round_count, rate);
		c->b.bw = c->b.bw_s[0];
	}
	bbr_update_ack_aggregation(c, c->rs.acked, now);
	bbr_update_cycle(c, now);
	bbr_check_full_bw(c);
	if (c->b.mode == HW_QC_BBR_STARTUP && c->b.full_bw_reached) c->b.mode = HW_QC_BBR_DRAIN;
	if (c->b.mode == HW_QC_BBR_DRAIN && c->in_flight <= bbr_bdp(c, BBR_UNIT)) bbr_enter_probe_bw(c, now);
	bbr_update_min_rtt(c, rtt_us, now);
	bbr_update_gains(c);
	// Pacing: the gain over the estimate, never lowered before startup has found the path.
	if (c->b.bw) {
		uint64_t r = c->b.bw * c->b.pacing_gain / BBR_UNIT;
		r = r / 100 * (100 - BBR_PACING_MARGIN_PCT);
		if (c->b.full_bw_reached || r > c->b.pacing_rate) c->b.pacing_rate = r;
	}
	// The window: twice the estimated BDP (startup's gain while starting), with room for the
	// bursts the pacer allows and for ACKs that arrive in clumps; it grows by what was
	// acknowledged until it reaches that.
	uint64_t target = bbr_bdp(c, c->b.cwnd_gain) + 3 * c->mds + bbr_ack_aggregation_cwnd(c);
	if (c->b.mode == HW_QC_BBR_PROBE_BW && c->b.cycle_idx == 0) target += 2 * c->mds;
	uint64_t acked = c->rs.acked;
	if (c->b.full_bw_reached) {
		c->cwnd = HW_MIN(c->cwnd + acked, target);
	} else if (c->cwnd < target || c->delivered < c->b.init_cwnd) {
		c->cwnd += acked;
	}
	if (c->cwnd > CC_CWND_MAX) c->cwnd = CC_CWND_MAX;
	if (c->cwnd < bbr_min_cwnd(c)) c->cwnd = bbr_min_cwnd(c);
	if (c->b.mode == HW_QC_BBR_PROBE_RTT && c->cwnd > bbr_min_cwnd(c)) c->cwnd = bbr_min_cwnd(c);
	memset(&c->rs, 0, sizeof(c->rs));
}

// ---- Pacer (section 7.7) -------------------------------------------------------------------
// A token bucket: rate 5/4 * cwnd / smoothed_rtt, a burst of the larger of ten datagrams and
// two milliseconds' worth (the caller's clock ticks in milliseconds, so a smaller burst would
// cap the rate rather than smooth it), never more than the window.

static uint64_t pacer_rate(const hw_qc_cc *c, const hw_qc_rtt *r) {
	uint64_t srtt = HW_MAX(r->smoothed, (uint64_t)HW_QC_GRANULARITY_US);
	if (c->bbr) {
		if (c->b.pacing_rate) return c->b.pacing_rate;
		// No bandwidth sample yet: the startup gain over the window and the RTT there is.
		return c->cwnd * BBR_HIGH_GAIN / BBR_UNIT * 1000000 / srtt;
	}
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
