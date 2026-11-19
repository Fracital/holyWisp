/*
 * src/quic/quic_internal.h - the parts of the QUIC connection (holywisp/quic.h) that its files
 * share, and that tests/test_quic.c reaches into: range sets, stream send and receive buffers,
 * the frame codec, RTT estimation and NewReno with its pacer, the sent-packet ring, and the
 * connection struct itself.
 *
 * Internal to the hw_quic library. Everything here is single-threaded and owned by the
 * connection that holds it. Times are microseconds of the caller's clock (now_ms * 1000).
 */
#ifndef HOLYWISP_QUIC_INTERNAL_H
#define HOLYWISP_QUIC_INTERNAL_H

#include "holywisp/hw.h"
#include "holywisp/quic.h"
#include "holywisp/tls13.h"

#include "quic_wire.h"

#include <stddef.h>
#include <stdint.h>

#include <sys/socket.h>

// ---- Constants ------------------------------------------------------------------------------
#define HW_QC_GRANULARITY_US    1000u   // RFC 9002 kGranularity
#define HW_QC_INITIAL_RTT_US    333000u // RFC 9002 kInitialRtt
#define HW_QC_PACER_BURST_MAX   32u     // datagrams: the most a pacer on a fine tick lets go at once
#define HW_QC_PACKET_THRESHOLD  3u      // RFC 9002 kPacketThreshold: the start of the adaptive one
#define HW_QC_PACKET_THRESH_MAX 256u    // the adaptive packet threshold goes no higher
#define HW_QC_TIME_SHIFT        3u      // time threshold 1 + 2^-3 = RFC 9002 kTimeThreshold, at first
#define HW_QC_PERSISTENT_FACTOR 3u      // RFC 9002 kPersistentCongestionThreshold
#define HW_QC_ACK_RANGES_MAX    32u     // received-packet ranges kept per space
#define HW_QC_SEEN_RANGES_MAX   32u     // received-packet ranges kept per space to drop duplicates
#define HW_QC_CRYPTO_MAX        65536u  // CRYPTO bytes buffered past the delivered offset, per level
#define HW_QC_RECV_RANGES_MAX   1024u   // out-of-order fragments held per stream (then rx_refused)
#define HW_QC_OUR_CIDS          4u      // connection IDs issued to the peer at most
#define HW_QC_PEER_CID_LIMIT    4u      // our active_connection_id_limit
#define HW_QC_PEER_CIDS         8u      // slots for the peer's connection IDs
#define HW_QC_RETIRE_MAX        32u     // RETIRE_CONNECTION_ID frames queued at most
#define HW_QC_MAX_ACK_DELAY_US  25000u  // our max_ack_delay (the default, so it is not sent)
#define HW_QC_ACK_DELAY_EXP     3u      // our ack_delay_exponent (the default)
#define HW_QC_PKT_FRAMES_MAX    64u     // frame records per sent packet
#define HW_QC_REASON_MAX        128u    // CONNECTION_CLOSE reason bytes kept or sent
#define HW_QC_CHALLENGES        4u      // outstanding PATH_CHALLENGE values remembered
#define HW_QC_ACK_ONLY_PING     16u     // ACK-only packets in a row before one carries a PING
#define HW_QC_PMTU_TRIES        3u      // RFC 8899 MAX_PROBES: lost probes before a size counts as too big
#define HW_QC_PMTU_STEP         32u     // the search ends when the bounds are this close
#define HW_QC_PMTU_BH_LOST      3u      // packets above the base size lost before a black hole is believed
#define HW_QC_PMTU_BH_PTOS      2u      // from this PTO in a row on, probes go at the base size
#define HW_QC_SENT_RING_MAX     65536u  // packets tracked per space before ACK-only ones are forgotten
// RFC 9001 6.6: packets that may fail authentication in a connection, across all keys, under
// ChaCha20-Poly1305 (the AEAD TLS selects; AES-128-GCM, Initial packets only, allows 2^52).
#define HW_QC_AEAD_INTEGRITY_LIMIT (1ull << 36)

#define HW_QC_APPLICATION_ERROR   0x0c // CONNECTION_CLOSE 0x1c code for an application close before 1-RTT
#define HW_QC_CONNECTION_ID_LIMIT 0x09
#define HW_QC_KEY_UPDATE_ERROR    0x0e
#define HW_QC_STREAMS_MAX_VALUE   (1ull << 60)
#define HW_QC_NONE                UINT64_MAX

enum {
	HW_QC_SP_INITIAL = 0,
	HW_QC_SP_HANDSHAKE = 1,
	HW_QC_SP_APP = 2,
	HW_QC_SPACES = 3,
};

// ---- Variable-length integers, inline for the data path ------------------------------------
// quic_wire.h has the same codec out of line; these are the ones frames are read and written
// with, where a call per field would be most of the cost.
static inline size_t hw_qc_vlen(uint64_t v) {
	return v < 64 ? 1 : v < 16384 ? 2 : v < 1073741824 ? 4 : 8;
}

// Writes the shortest encoding of v (<= 2^62 - 1) at p, which has room. Returns p past it.
static inline uint8_t *hw_qc_vput(uint8_t *p, uint64_t v) {
	if (v < 64) {
		*p++ = (uint8_t)v;
	} else if (v < 16384) {
		*p++ = (uint8_t)(0x40 | (v >> 8));
		*p++ = (uint8_t)v;
	} else if (v < 1073741824) {
		*p++ = (uint8_t)(0x80 | (v >> 24));
		*p++ = (uint8_t)(v >> 16);
		*p++ = (uint8_t)(v >> 8);
		*p++ = (uint8_t)v;
	} else {
		*p++ = (uint8_t)(0xc0 | (v >> 56));
		for (int s = 48; s >= 0; s -= 8) *p++ = (uint8_t)(v >> s);
	}
	return p;
}

// Reads one varint from [p, end). Returns the bytes it took, 0 when it runs past end.
static inline size_t hw_qc_vget(const uint8_t *p, const uint8_t *end, uint64_t *v) {
	if (p >= end) return 0;
	size_t n = (size_t)1 << (p[0] >> 6);
	if ((size_t)(end - p) < n) return 0;
	uint64_t x = p[0] & 0x3f;
	for (size_t i = 1; i < n; i++) x = (x << 8) | p[i];
	*v = x;
	return n;
}

// ---- Range sets ----------------------------------------------------------------------------
// Disjoint half-open ranges [lo, hi), ascending. With max set, a set holds at most max ranges:
// in drop mode the lowest is forgotten (and floor raised past it), otherwise an add that would
// need one more fails.
typedef struct {
	uint64_t lo, hi;
} hw_qc_range;

typedef struct {
	hw_qc_range *r;
	size_t n, cap;
	size_t max;     // 0 = unbounded
	int drop;       // over max: forget the lowest range instead of failing
	uint64_t floor; // drop mode: everything below was seen once and is forgotten
} hw_qc_ranges;

void hw_qc_ranges_init(hw_qc_ranges *s, size_t max, int drop);
void hw_qc_ranges_clear(hw_qc_ranges *s);
// Adds [lo, hi). Returns 0, or -1 on allocation failure or (not drop mode) over max.
int hw_qc_ranges_add(hw_qc_ranges *s, uint64_t lo, uint64_t hi);
// Removes [lo, hi). Returns 0, or -1 on allocation failure (a split that needed room).
int hw_qc_ranges_remove(hw_qc_ranges *s, uint64_t lo, uint64_t hi);
// 1 when v is in the set (in drop mode, also when it is below floor).
int hw_qc_ranges_contains(const hw_qc_ranges *s, uint64_t v);
// Forget every range that ends at or below v (raising floor to v when that is higher).
void hw_qc_ranges_prune_below(hw_qc_ranges *s, uint64_t v);
// The same without raising floor: what is forgotten may be added again.
void hw_qc_ranges_forget_below(hw_qc_ranges *s, uint64_t v);

// ---- Stream send buffer --------------------------------------------------------------------
// The bytes of one sending stream (or CRYPTO level) from the first unacknowledged one to the
// last written, in a ring. "sent" is the first byte never sent; lost holds ranges below it to
// send again; acked holds acknowledged ranges above base.
typedef struct {
	uint8_t *buf;
	size_t cap; // power of two or 0
	uint64_t base, end, sent;
	hw_qc_ranges acked, lost;
	uint8_t fin, fin_sent, fin_acked, fin_lost;
} hw_qc_sendbuf;

void hw_qc_sendbuf_init(hw_qc_sendbuf *b);
void hw_qc_sendbuf_clear(hw_qc_sendbuf *b);
// Appends len bytes. Returns 0, or -1 on allocation failure.
int hw_qc_sendbuf_write(hw_qc_sendbuf *b, const uint8_t *data, size_t len);
// Whether anything (data or FIN) is waiting to be sent or sent again.
int hw_qc_sendbuf_pending(const hw_qc_sendbuf *b);
// The next frame's worth to send, at most max bytes: lost ranges first, then new bytes. Sets
// off, len, fin; returns 1, or 0 when there is nothing to send.
int hw_qc_sendbuf_next(const hw_qc_sendbuf *b, size_t max, uint64_t *off, size_t *len, int *fin);
// Copies [off, off + len) (all held) to dst.
void hw_qc_sendbuf_copy(const hw_qc_sendbuf *b, uint64_t off, size_t len, uint8_t *dst);
// Records [off, off + len) (and fin) as sent.
void hw_qc_sendbuf_sent(hw_qc_sendbuf *b, uint64_t off, size_t len, int fin);
// Acknowledged: frees what is contiguous from base. Returns the bytes freed.
size_t hw_qc_sendbuf_ack(hw_qc_sendbuf *b, uint64_t off, size_t len, int fin);
// Declared lost: whatever of it is not acknowledged is sent again.
void hw_qc_sendbuf_lost(hw_qc_sendbuf *b, uint64_t off, size_t len, int fin);
// Everything written is acknowledged, FIN included.
static inline int hw_qc_sendbuf_done(const hw_qc_sendbuf *b) {
	return b->fin && b->fin_acked && b->base == b->end;
}

// ---- Receive reassembly --------------------------------------------------------------------
// In-order bytes go to the application straight from the packet; only what arrives ahead of
// the delivered offset is copied, into a ring that covers [off, highest).
typedef struct {
	uint8_t *buf;
	size_t cap;        // power of two or 0
	uint64_t off;      // next offset to deliver
	uint64_t highest;  // one past the highest byte received
	uint64_t final;    // final size, HW_QC_NONE until known
	hw_qc_ranges have; // buffered ranges, all above off
} hw_qc_recvbuf;

void hw_qc_recvbuf_init(hw_qc_recvbuf *b, size_t max_ranges);
void hw_qc_recvbuf_clear(hw_qc_recvbuf *b);
// Takes [off, off + len). The part that starts at the delivered offset is returned in
// *direct/*direct_len (pointing into data, not copied; the caller delivers it and then calls
// hw_qc_recvbuf_advance), the rest is buffered. Returns 0, or -1 on allocation failure or too
// many fragments.
int hw_qc_recvbuf_push(hw_qc_recvbuf *b, uint64_t off, const uint8_t *data, size_t len, const uint8_t **direct,
                       size_t *direct_len);
// Moves the delivered offset forward by n, dropping buffered bytes below it.
void hw_qc_recvbuf_advance(hw_qc_recvbuf *b, size_t n);
// Buffered bytes now at the delivered offset: a pointer into the ring and how many are
// contiguous there (0 when none). The caller delivers them and calls hw_qc_recvbuf_advance.
size_t hw_qc_recvbuf_peek(const hw_qc_recvbuf *b, const uint8_t **p);

// ---- Frames (RFC 9000 section 19, RFC 9221) ------------------------------------------------
enum {
	HW_QC_F_PADDING = 0x00,
	HW_QC_F_PING = 0x01,
	HW_QC_F_ACK = 0x02,
	HW_QC_F_ACK_ECN = 0x03,
	HW_QC_F_RESET_STREAM = 0x04,
	HW_QC_F_STOP_SENDING = 0x05,
	HW_QC_F_CRYPTO = 0x06,
	HW_QC_F_NEW_TOKEN = 0x07,
	HW_QC_F_STREAM = 0x08, // 0x08..0x0f: OFF 0x04, LEN 0x02, FIN 0x01
	HW_QC_F_MAX_DATA = 0x10,
	HW_QC_F_MAX_STREAM_DATA = 0x11,
	HW_QC_F_MAX_STREAMS_BIDI = 0x12,
	HW_QC_F_MAX_STREAMS_UNI = 0x13,
	HW_QC_F_DATA_BLOCKED = 0x14,
	HW_QC_F_STREAM_DATA_BLOCKED = 0x15,
	HW_QC_F_STREAMS_BLOCKED_BIDI = 0x16,
	HW_QC_F_STREAMS_BLOCKED_UNI = 0x17,
	HW_QC_F_NEW_CONNECTION_ID = 0x18,
	HW_QC_F_RETIRE_CONNECTION_ID = 0x19,
	HW_QC_F_PATH_CHALLENGE = 0x1a,
	HW_QC_F_PATH_RESPONSE = 0x1b,
	HW_QC_F_CONNECTION_CLOSE = 0x1c,
	HW_QC_F_CONNECTION_CLOSE_APP = 0x1d,
	HW_QC_F_HANDSHAKE_DONE = 0x1e,
	HW_QC_F_DATAGRAM = 0x30,
	HW_QC_F_DATAGRAM_LEN = 0x31,
};

// One parsed frame. Which fields mean something depends on type (the base type: every STREAM
// variant is HW_QC_F_STREAM with fin and offset decoded, both DATAGRAMs HW_QC_F_DATAGRAM).
typedef struct {
	uint64_t type;
	uint64_t stream_id;   // STREAM, RESET_STREAM, STOP_SENDING, MAX_STREAM_DATA, STREAM_DATA_BLOCKED
	uint64_t offset;      // STREAM, CRYPTO
	uint64_t error;       // RESET_STREAM, STOP_SENDING, CONNECTION_CLOSE
	uint64_t value;       // MAX_*, *_BLOCKED, RESET_STREAM final size, NEW/RETIRE_CONNECTION_ID
	                      // sequence, CONNECTION_CLOSE frame type
	uint64_t value2;      // NEW_CONNECTION_ID retire_prior_to
	const uint8_t *data;  // STREAM/CRYPTO/DATAGRAM/NEW_TOKEN data, CONNECTION_CLOSE reason,
	size_t len;           // NEW_CONNECTION_ID cid, PATH_* data (8 bytes)
	const uint8_t *token; // NEW_CONNECTION_ID stateless reset token
	int fin;
	// ACK: the largest acknowledged, the delay field, the first range, and the encoded ranges
	// after it (count of them), already checked to decode without underflow.
	uint64_t ack_largest, ack_delay, ack_first, ack_count;
	const uint8_t *ack_ranges;
	size_t ack_ranges_len;
} hw_qc_frame;

// Parses the frame at [p, end) into f. Returns the bytes it took, or 0 for a frame that is
// malformed or of an unknown type (FRAME_ENCODING_ERROR). f->type is set whenever the type
// itself could be read. A run of PADDING is one frame.
size_t hw_qc_frame_parse(const uint8_t *p, const uint8_t *end, hw_qc_frame *f);

// Walks an ACK frame's ranges, largest first, as inclusive [lo, hi] packet numbers.
typedef struct {
	const uint8_t *p, *end;
	uint64_t lo, hi;
	uint64_t left; // ranges after the current one
} hw_qc_ack_iter;
void hw_qc_ack_iter_init(hw_qc_ack_iter *it, const hw_qc_frame *f);
// Moves to the next lower range. Returns 1, or 0 when there is none.
int hw_qc_ack_iter_next(hw_qc_ack_iter *it);

// Writers: each writes one whole frame at p when it fits in room and returns its length, or
// returns 0 and writes nothing.
size_t hw_qc_put_ack(uint8_t *p, size_t room, const hw_qc_ranges *recv, uint64_t delay_field, size_t *ranges_out);
size_t hw_qc_put_stream_header(uint8_t *p, size_t room, uint64_t id, uint64_t off, size_t len, int fin);
size_t hw_qc_put_crypto_header(uint8_t *p, size_t room, uint64_t off, size_t len);
size_t hw_qc_put_simple(uint8_t *p, size_t room, uint64_t type, uint64_t a); // MAX_DATA, *_BLOCKED, MAX_STREAMS, RETIRE
size_t hw_qc_put_pair(uint8_t *p, size_t room, uint64_t type, uint64_t a,
                      uint64_t b); // MAX_STREAM_DATA, STOP_SENDING, STREAM_DATA_BLOCKED
size_t hw_qc_put_reset_stream(uint8_t *p, size_t room, uint64_t id, uint64_t err, uint64_t final_size);
size_t hw_qc_put_new_cid(uint8_t *p, size_t room, uint64_t seq, uint64_t retire_prior_to, const uint8_t *cid,
                         size_t cid_len, const uint8_t token[HW_QUIC_RESET_LEN]);
size_t hw_qc_put_path(uint8_t *p, size_t room, uint64_t type, const uint8_t data[8]);
size_t hw_qc_put_close(uint8_t *p, size_t room, int app, uint64_t err, uint64_t frame_type, const char *reason,
                       size_t reason_len);
size_t hw_qc_put_datagram(uint8_t *p, size_t room, const uint8_t *data, size_t len);

// ---- RTT and congestion control (RFC 9002 sections 5, 7) -----------------------------------
typedef struct {
	uint64_t latest, smoothed, var, min;
	int has_sample;
	uint64_t first_sample_time;
} hw_qc_rtt;

void hw_qc_rtt_init(hw_qc_rtt *r);
// A new sample (RFC 9002 5.3). ack_delay is already capped by the caller where that applies.
void hw_qc_rtt_sample(hw_qc_rtt *r, uint64_t latest, uint64_t ack_delay, uint64_t now);
// smoothed + max(4 * var, kGranularity): the PTO without max_ack_delay or backoff.
uint64_t hw_qc_rtt_pto(const hw_qc_rtt *r);
// The loss detection time threshold: (1 + 2^-shift) * max(latest, smoothed), at least
// kGranularity. shift HW_QC_TIME_SHIFT is RFC 9002's 9/8; a connection that saw spurious losses
// lowers it (down to 0, twice the RTT) to tolerate the reordering it saw.
uint64_t hw_qc_rtt_loss_delay(const hw_qc_rtt *r, unsigned shift);

typedef struct {
	uint64_t mds; // max_datagram_size
	uint64_t cwnd, ssthresh, in_flight;
	uint64_t ca_acked; // congestion avoidance: bytes acknowledged toward the next increase
	uint64_t recovery_start;
	int in_recovery_valid;
	// Undoing a spurious congestion event: the window and threshold before the reduction, and
	// the in-flight packets declared lost in that recovery period (epoch) not yet acknowledged.
	uint64_t undo_cwnd, undo_ssthresh;
	uint64_t undo_lost;
	uint16_t epoch; // recovery periods entered (mod 2^16), stamped on the packets each declared lost
	int undo_ok;    // the current period may still be undone
	// Pacer: a token bucket refilled at 5/4 * cwnd / smoothed RTT (NewReno) or at BBR's
	// pacing rate, and how late the caller's timers fire, which sizes its bursts (pacer_burst).
	uint64_t tokens, last_refill;
	uint64_t tick_us;
	// Delivery rate estimation (draft-cheng-iccrg-delivery-rate-estimation), kept by both
	// algorithms and used by BBR: bytes acknowledged so far and when the latest was, the send
	// time of the packet that started the current interval, and the app-limited mark (the
	// delivered count until which samples are app-limited, 0 when none).
	uint64_t delivered, delivered_time, first_sent_time, app_limited;
	// The sample this ACK makes, from the newest packet it acknowledges.
	struct {
		int has;
		int is_app_limited;
		uint64_t prior_delivered, prior_time, send_elapsed, ack_elapsed;
		uint64_t tx_in_flight; // that packet's in flight when it was sent
		uint64_t acked, lost;  // bytes acknowledged and packets declared lost while this ACK is processed
	} rs;
	// BBR (draft-cardwell-iccrg-bbr-congestion-control-00, as Linux's tcp_bbr does it); bbr = 0
	// is NewReno and leaves all of this alone.
	int bbr;
	struct {
		int mode;                        // HW_QC_BBR_*
		uint64_t bw;                     // the max filter's answer, bytes per second
		uint64_t bw_s[3], bw_t[3];       // the windowed max filter (Linux lib/minmax.c): value, round
		uint64_t min_rtt, min_rtt_stamp; // never under a tick of the timers (HW_QC_GRANULARITY_US)
		uint64_t min_rtt_raw;            // the same window's least sample, unfloored
		uint64_t round_count, next_round_delivered;
		int round_start;
		uint64_t full_bw;
		unsigned full_bw_cnt;
		int full_bw_reached;
		unsigned cycle_idx;
		uint64_t cycle_stamp;
		unsigned pacing_gain, cwnd_gain; // in 1/256
		uint64_t pacing_rate;            // bytes per second, 0 until the first is set
		uint64_t prior_cwnd;
		uint64_t probe_rtt_done;
		int probe_rtt_round_done;
		int idle_restart;
		uint64_t init_cwnd;
		// ACK aggregation (Linux's extra_acked): how far the bytes acknowledged ran ahead of
		// the estimated rate since the epoch began, its max over two windows of 5 rounds, added
		// to the window so that ACKs that come late or in clumps do not stall the sender.
		uint64_t ack_epoch_start, ack_epoch_acked;
		uint64_t extra_acked[2];
		unsigned extra_acked_idx, extra_acked_rounds;
		// bbr2 (draft-cardwell-ccwg-bbr, version 3, with its loss response; hw_qc_cc_use_bbr2):
		// what follows is zero and unused in version 1. Bytes, bytes per second and microseconds;
		// UINT64_MAX is "no bound".
		int v2;
		int phase, ack_phase;                // HW_QC_BBR2_* while in PROBE_BW; which of its ACKs are arriving
		uint64_t max_bw, bw_hi[2];           // the max filter: this ProbeBW cycle and the one before
		uint64_t inflight_hi;                // the most in flight that lost under the threshold
		uint64_t bw_lo, inflight_lo;         // short-term bounds after a round of too much loss
		uint64_t undo_inflight_hi;           // inflight_hi when the current recovery period began
		uint64_t bw_latest, inflight_latest; // the round's best rate sample and delivered bytes
		uint64_t loss_round_delivered;
		int loss_round_start, loss_in_round;  // loss_in_round: too much loss seen in this round
		unsigned loss_rounds;                 // rounds in a row with too much loss
		uint64_t round_lost, round_in_flight; // lost this round; in flight when it began
		uint64_t hi_cut_delivered;            // delivered when inflight_hi was last lowered
		unsigned loss_events;                 // discontiguous losses this round (startup's exit)
		uint64_t last_lost_pn;
		int full_bw_now;      // the plateau test passed (startup, or the current UP)
		int bw_probe_samples; // ACKs of what a probe sent are arriving
		uint64_t probe_wait, rounds_since_probe;
		uint64_t probe_rounds_max;       // the next probe after this many rounds at most
		uint64_t last_probe_hi;          // inflight_hi where the last probe left it
		uint64_t probe_end_delivered;    // delivered when this flow last stopped probing
		uint64_t round_lost_since_probe; // lost this round, sent since then
		uint64_t round_max_rtt;          // the round's largest RTT sample
		unsigned overflow_rounds;        // rounds in a row of another flow's overflow
		unsigned probe_up_rounds;
		uint64_t probe_up_acks, probe_up_cnt;
		int cwnd_limited, cwnd_limited_round; // the window was full in the last round, in this one
		uint64_t rng;
		// A round's loss became too much: what inflight_hi becomes, applied by
		// hw_qc_cc_congestion_event after the recovery period's undo state is saved.
		int pend, pend_app_limited;
		uint64_t pend_hi;
	} b;
} hw_qc_cc;

enum {
	HW_QC_BBR_STARTUP = 0,
	HW_QC_BBR_DRAIN,
	HW_QC_BBR_PROBE_BW,
	HW_QC_BBR_PROBE_RTT,
};

// bbr2's phases of PROBE_BW.
enum {
	HW_QC_BBR2_DOWN = 0,
	HW_QC_BBR2_CRUISE,
	HW_QC_BBR2_REFILL,
	HW_QC_BBR2_UP,
};

void hw_qc_cc_init(hw_qc_cc *c, uint64_t mds, uint64_t now);
// After hw_qc_cc_init: the window is BBR's from then on, not NewReno's.
void hw_qc_cc_use_bbr(hw_qc_cc *c, uint64_t now);
// The same, with version 3's loss response (bbr2): an in-flight bound where loss passes 2%.
void hw_qc_cc_use_bbr2(hw_qc_cc *c, uint64_t now);
void hw_qc_cc_on_sent(hw_qc_cc *c, uint64_t bytes);
// An in-flight packet sent at time_sent was acknowledged. limited = the sender was not using
// the window (no growth then).
void hw_qc_cc_on_acked(hw_qc_cc *c, uint64_t bytes, uint64_t time_sent, int limited);
// An in-flight packet left the flight without an acknowledgment (lost or discarded).
void hw_qc_cc_remove(hw_qc_cc *c, uint64_t bytes);
// A loss of nlost in-flight packets, the newest sent at time_sent (RFC 9002 7.3.2): the
// window is reduced once per recovery period. Either way the packets belong to c->epoch
// afterwards (the caller stamps them with it).
void hw_qc_cc_congestion_event(hw_qc_cc *c, uint64_t time_sent, uint64_t nlost, uint64_t now);
// Persistent congestion (7.6.2): back to the minimum window, and never undone.
void hw_qc_cc_persistent(hw_qc_cc *c);
// A packet declared lost in recovery period epoch was acknowledged after all. Once every
// packet the current period declared lost has been, the period was spurious: the window and
// threshold go back to what they were before it, and the period ends. Returns 1 then.
int hw_qc_cc_spurious(hw_qc_cc *c, uint16_t epoch);
// Whether an ack-eliciting packet may be sent now: the window has room.
static inline int hw_qc_cc_can_send(const hw_qc_cc *c) {
	return c->in_flight < c->cwnd;
}
// The pacer: refills, then returns now when a packet of mds bytes may go, or the time when it
// may. On a tick of a millisecond (HW_QC_GRANULARITY_US, what hw_qc_cc_init sets) a burst is
// the larger of ten datagrams and two ticks of the rate, and it waits for one datagram. On a finer
// tick (hw_qc_pacer_set_tick) a burst is two ticks of the rate, at least two datagrams and at
// most HW_QC_PACER_BURST_MAX, and when held back it waits until the bucket is a tick's worth short
// of full, so that a fine timer is not woken for every datagram and one a tick late wastes none.
uint64_t hw_qc_pacer_next(hw_qc_cc *c, const hw_qc_rtt *r, uint64_t now);
// The resolution of the caller's timers in microseconds: how late after its deadline it may be
// woken. HW_QC_GRANULARITY_US or more is the millisecond pacer above.
void hw_qc_pacer_set_tick(hw_qc_cc *c, uint64_t tick_us);
void hw_qc_pacer_on_sent(hw_qc_cc *c, uint64_t bytes);

// ---- Sent packets --------------------------------------------------------------------------
enum {
	HW_QC_SENT_ACK_ELICITING = 0x01,
	HW_QC_SENT_IN_FLIGHT = 0x02,
	HW_QC_SENT_ACKED = 0x04,
	HW_QC_SENT_LOST = 0x08,
	HW_QC_SENT_PHASE = 0x10,   // 1-RTT: sent with key phase 1
	HW_QC_SENT_LIMITED = 0x20, // sent while the sender was not using the congestion window
	HW_QC_SENT_STAMPED = 0x40, // lost in flight, loss_epoch says in which recovery period
	HW_QC_SENT_PMTU = 0x80,    // a PMTU probe: neither in flight nor counted as ack-eliciting
};

typedef struct {
	uint64_t time;
	uint64_t frame0; // index of its first frame record
	uint16_t size;
	uint16_t nframes;
	uint8_t flags;
	uint8_t rs_app_limited; // in flight: sent while the sender was app-limited (hw_qc_cc.app_limited)
	uint16_t loss_epoch;    // HW_QC_SENT_LOST: the recovery period that declared it (hw_qc_cc.epoch)
	// In flight: the connection's delivery state when it was sent (hw_qc_cc.delivered and the
	// rest), from which its acknowledgment makes a delivery rate sample, and what was in flight
	// then, itself included (bbr2 bounds the flight with it).
	uint64_t delivered, delivered_time, first_sent_time;
	uint64_t tx_in_flight;
	// Once an ACK can no longer change it (acknowledged, or lost without being in flight): a
	// packet number below it such that every packet between the two is so too, for ACK processing
	// to skip them (quic.c, ack_next_open). Its own number until then.
	uint64_t below;
} hw_qc_sent;

// Delivery rate estimation. An in-flight packet is being sent (before hw_qc_cc_on_sent counts
// it): it takes the connection's delivery state.
void hw_qc_rs_on_sent(hw_qc_cc *c, hw_qc_sent *s, uint64_t now);
// An in-flight packet was acknowledged (before hw_qc_cc_on_acked).
void hw_qc_rs_on_acked(hw_qc_cc *c, const hw_qc_sent *s, uint64_t now);
// An in-flight packet, number pn, was declared lost: before hw_qc_cc_remove takes it out of the
// flight and before the hw_qc_cc_congestion_event of its batch.
void hw_qc_cc_on_lost(hw_qc_cc *c, const hw_qc_sent *s, uint64_t pn);
// The sender has room in the window and pacer but nothing to send: what goes out until what is
// in flight now is delivered says nothing about the path's bandwidth.
void hw_qc_cc_app_limited(hw_qc_cc *c);
// An ACK frame has been processed (its packets acknowledged, losses detected): BBR updates its
// model, pacing rate and window from the sample. rtt_us is the RTT sample it made, as measured
// (BBR floors its model to a tick itself), 0 for none.
void hw_qc_cc_on_ack_done(hw_qc_cc *c, uint64_t rtt_us, uint64_t now);

// What a sent frame needs to be sent again when it is lost, or forgotten when it is acked.
enum {
	HW_QC_R_STREAM = 1,
	HW_QC_R_CRYPTO,
	HW_QC_R_ACK, // id: the largest it acknowledged
	HW_QC_R_MAX_DATA,
	HW_QC_R_MAX_STREAM_DATA,
	HW_QC_R_MAX_STREAMS_BIDI,
	HW_QC_R_MAX_STREAMS_UNI,
	HW_QC_R_RESET_STREAM,
	HW_QC_R_STOP_SENDING,
	HW_QC_R_NEW_CID,
	HW_QC_R_RETIRE_CID,
	HW_QC_R_HANDSHAKE_DONE,
	HW_QC_R_DATAGRAM,
};

typedef struct {
	uint8_t type;
	uint8_t fin;
	uint16_t len;
	uint64_t id;
	uint64_t off;
} hw_qc_frec;

// The packets of one space from the oldest still tracked to the newest, indexed by packet
// number (they are consecutive), and their frame records in a second ring.
typedef struct {
	hw_qc_sent *pk;
	size_t pcap;         // power of two or 0
	uint64_t base, next; // packets [base, next)
	hw_qc_frec *fr;
	size_t fcap;           // power of two or 0
	uint64_t ftail, fhead; // frame records [ftail, fhead)
} hw_qc_ring;

void hw_qc_ring_init(hw_qc_ring *r);
void hw_qc_ring_clear(hw_qc_ring *r);
// Room for one more packet with up to nframes frame records. Returns 0, or -1.
int hw_qc_ring_reserve(hw_qc_ring *r, size_t nframes);
// Appends a frame record (room reserved).
void hw_qc_ring_add_frame(hw_qc_ring *r, const hw_qc_frec *f);
// Appends packet number r->next (room reserved); its frames are [frame0, fhead).
void hw_qc_ring_add_packet(hw_qc_ring *r, const hw_qc_sent *s);
// The packet pn when it is tracked, NULL otherwise.
static inline hw_qc_sent *hw_qc_ring_get(const hw_qc_ring *r, uint64_t pn) {
	if (pn < r->base || pn >= r->next) return NULL;
	return &r->pk[pn & (r->pcap - 1)];
}
static inline hw_qc_frec *hw_qc_ring_frame(const hw_qc_ring *r, uint64_t idx) {
	return &r->fr[idx & (r->fcap - 1)];
}
// Forgets the oldest packets while they are acknowledged, or lost and sent before keep_since:
// a packet declared lost is remembered a while so that a late acknowledgment of it shows the
// loss was spurious. HW_QC_NONE forgets every lost one.
void hw_qc_ring_trim(hw_qc_ring *r, uint64_t keep_since);

// ---- Streams ---------------------------------------------------------------------------------
typedef struct hw_qc_stream hw_qc_stream;
struct hw_qc_stream {
	uint64_t id;
	hw_qc_stream *all_prev, *all_next;   // every live stream
	hw_qc_stream *send_prev, *send_next; // round robin of streams with data to send
	hw_qc_stream *ctl_next;              // streams with control frames due
	hw_qc_stream *blk_next;              // streams waiting for stream_writable
	uint8_t in_send, in_ctl, in_blk;
	uint8_t has_send, has_recv;
	uint8_t freed; // queued to be freed at the next safe point
	// Sending side.
	hw_qc_sendbuf sb;
	uint64_t tx_max; // the peer's MAX_STREAM_DATA
	uint8_t tx_reset, tx_reset_acked;
	uint64_t tx_reset_err, tx_reset_final;
	uint8_t ctl_reset, ctl_stop, ctl_msd, ctl_sdb;
	uint64_t sdb_value;
	// Receiving side.
	hw_qc_recvbuf rb;
	uint64_t rx_max;      // credit granted (MAX_STREAM_DATA)
	uint64_t rx_consumed; // bytes the application consumed
	uint8_t rx_reset, rx_stopped, fin_delivered;
	uint64_t stop_err;
};

// Stream id -> stream, open addressing with backward-shift deletion.
typedef struct {
	hw_qc_stream **slot;
	size_t cap; // power of two or 0
	size_t count;
} hw_qc_smap;

void hw_qc_smap_init(hw_qc_smap *m);
void hw_qc_smap_clear(hw_qc_smap *m);
hw_qc_stream *hw_qc_smap_get(const hw_qc_smap *m, uint64_t id);
int hw_qc_smap_put(hw_qc_smap *m, hw_qc_stream *s); // 0, or -1 on allocation failure
void hw_qc_smap_remove(hw_qc_smap *m, uint64_t id);

// ---- The connection ------------------------------------------------------------------------
typedef struct {
	hw_qw_keys rx, tx;
	uint8_t has_rx, has_tx, discarded;
	// Receiving. recv is what our ACKs still report, seen what duplicates are dropped by: an
	// ACK of our ACK takes ranges off recv, but a packet below them that arrives late (one
	// reordered) is new to seen, processed, and acknowledged on its own.
	hw_qc_ranges recv; // packet numbers received and not yet known to be acknowledged
	hw_qc_ranges seen; // packet numbers received
	int64_t largest_rx;
	uint64_t largest_rx_time;
	uint32_t ae_unacked; // ack-eliciting packets received since our last ACK
	uint8_t ack_new;     // any packet received since our last ACK
	uint8_t ack_now;     // send an ACK at once
	uint64_t ack_deadline;
	// Sending.
	hw_qc_ring ring;
	uint64_t scan_from; // every packet below is acknowledged or lost: loss detection starts here
	int64_t largest_acked;
	uint64_t last_ae_time;
	uint64_t loss_time; // 0 = none
	uint32_t ae_in_flight;
	uint32_t probes;
	uint32_t ack_only_run; // ACK-only packets sent in a row
	hw_qc_sendbuf crypto_tx;
	hw_qc_recvbuf crypto_rx;
} hw_qc_space;

typedef struct {
	uint64_t seq;
	uint8_t cid[HW_QUIC_CID_LEN];
	uint8_t token[HW_QUIC_RESET_LEN];
	uint8_t active, ncid_pending, announced;
} hw_qc_our_cid;

typedef struct {
	uint64_t seq;
	uint8_t cid[20];
	uint8_t len;
	uint8_t token[HW_QUIC_RESET_LEN];
	uint8_t has_token, used;
} hw_qc_peer_cid;

typedef struct {
	uint8_t *data;
	size_t len;
} hw_qc_dgram;

enum {
	HW_QC_ST_HANDSHAKE = 0,
	HW_QC_ST_ACTIVE,
	HW_QC_ST_CLOSING,  // we sent CONNECTION_CLOSE
	HW_QC_ST_DRAINING, // the peer did, or we went silent
	HW_QC_ST_DRAINED,
};

struct hw_quic_conn {
	// Word-sized fields first and the one-byte flags of every part last, so that the struct
	// has no padding to speak of; the comments say which part a field belongs to.
	hw_quic_config cfg;
	hw_quic_callbacks cb;
	uint64_t now; // the caller's clock at the current entry point, us
	hw_tls *tls;
	size_t tp_len;
	hw_qw_tp peer_tp;
	hw_qc_space sp[HW_QC_SPACES];

	// 1-RTT key phases: rx (sp[APP].rx) is the current phase; prev for late packets of the
	// last one, next for the peer's next update.
	hw_qw_keys rx_prev, rx_next;
	uint64_t rx_phase_first_pn; // first packet number received in the current rx phase
	uint64_t rx_prev_discard;   // when rx_prev is forgotten
	uint64_t tx_phase_first_pn; // first packet number sent in the current tx phase
	uint64_t key_updates;       // phases entered, either side's doing

	// Handshake.
	uint8_t *token; // client: Retry token for later Initials
	size_t token_len;

	// Connection IDs.
	hw_qc_our_cid ours[HW_QC_OUR_CIDS];
	uint64_t our_next_seq;
	hw_qc_peer_cid peers[HW_QC_PEER_CIDS];
	uint64_t retire_q[HW_QC_RETIRE_MAX];
	size_t retire_n;
	uint64_t peer_retire_prior; // the largest retire_prior_to seen

	// Path. probe_*: a PATH_RESPONSE owed to an address that is not the path (a peer probing).
	struct sockaddr_storage peer, old_peer, probe_addr;
	uint64_t amp_rx, amp_tx;
	size_t nchallenges;
	uint64_t challenge_next, path_deadline;
	uint64_t probe_amp;

	// Recovery.
	hw_qc_rtt rtt;
	hw_qc_cc cc;
	uint64_t pto_anchor; // client before validation: base of the PTO with nothing in flight
	uint64_t pacer_wait; // the pacer holds data until then (0 = not holding)
	uint64_t mds;        // datagram size limit on this path
	// Datagram packetization layer PMTU discovery (RFC 9000 14.3, RFC 8899): mds starts at
	// HW_QUIC_MIN_DGRAM and rises only when a probe of a larger size is acknowledged.
	uint64_t pmtu_max;      // HW_QUIC_MAX_DGRAM, or the peer's max_udp_payload_size if smaller
	uint64_t pmtu_bad;      // the smallest size that failed HW_QC_PMTU_TRIES probes (0: none)
	uint64_t pmtu_probe;    // the size of the probe awaiting its answer (0: none)
	int out_alone;          // the datagram hw_quic_output returned last was a probe
	unsigned hs_resends;    // server: flights resent early for a client Initial's repeated CRYPTO
	uint64_t pmtu_pn;       // its packet number
	uint64_t pmtu_deadline; // it counts as lost if not acknowledged by then
	uint64_t pmtu_next;     // no probe before then
	unsigned pmtu_tries;    // probes of the current size lost
	// Black hole detection: packets above the base size declared lost since none at least as
	// large as the smallest of them was acknowledged, that smallest size, the newest of them, and
	// a smaller packet sent after them that was acknowledged (0: none yet).
	uint64_t bh_lost, bh_min, bh_last, bh_small;
	uint64_t pmtu_black_holes; // times the size fell back to the base
	uint64_t peer_max_ack_delay;
	uint64_t spurious_lost; // packets declared lost that were acknowledged later
	uint64_t rx_refused;    // packets left unacknowledged: a fragment in them could not be held
	uint64_t ack_steps;     // sent packets ACK processing has looked at (tests bound it)
	uint64_t pkt_threshold; // adaptive packet threshold (RFC 9002 6.1.1), raised by spurious losses
	unsigned time_shift;    // adaptive time threshold, see hw_qc_rtt_loss_delay

	// Flow control and streams.
	uint64_t tx_max_data, tx_data; // peer's MAX_DATA; bytes we wrote across streams
	uint64_t rx_max_data, rx_highest, rx_consumed;
	uint64_t db_value;
	size_t tx_buffered; // unacknowledged + unsent stream bytes
	size_t tx_unsent;   // stream bytes written and never sent (end - sent, over the streams)
	hw_qc_smap streams;
	hw_qc_stream *all, *send_cur, *ctl_head, *ctl_tail, *blk_head;
	uint64_t next_local[2];       // [bidi, uni] next index of our streams
	uint64_t peer_max_streams[2]; // the peer's MAX_STREAMS for ours
	uint64_t next_peer[2];        // next index of the peer's streams not yet opened
	uint64_t rx_max_streams[2];   // MAX_STREAMS we granted
	uint64_t peer_closed[2];      // the peer's streams freed
	size_t free_pending;

	// Datagrams.
	hw_qc_dgram *dq;
	size_t dq_cap, dq_head, dq_n;
	uint64_t dgram_frames_sent;

	// Close.
	uint64_t close_error, close_frame;
	uint64_t close_deadline;
	uint64_t closing_rx; // datagrams received while closing

	// Timers and activity.
	uint64_t idle_ms;       // effective idle timeout (0 = none)
	uint64_t last_activity; // us
	uint64_t last_sent;

	hw_quic_stats stats;
	uint64_t auth_failures; // packets for this connection that failed authentication
	size_t inject_len;      // tests
	int inject_spi;         // tests: the space the injected frames go out in

	int is_server;
	int state;
	int peer_tp_applied;
	int peer_cur; // index into peers of the DCID in use
	socklen_t peer_len, old_peer_len, probe_len;
	uint32_t pto_count;
	int close_app;

	// Key phases.
	uint8_t has_rx_prev, rx_phase, tx_phase;
	uint8_t tx_phase_acked; // a packet of the current tx phase was acknowledged
	// Handshake.
	uint8_t handshake_complete, handshake_confirmed, established_fired, hsd_pending;
	uint8_t hs_discard_pending;  // server: drop Handshake keys after the next datagram
	uint8_t peer_validated_addr; // client: the server has our Handshake packets or confirmed
	uint8_t got_server_scid, retried;
	uint8_t odcid_len, client_dcid_len, retry_scid_len, peer_scid_len;
	// Path.
	uint8_t has_old_peer, path_validated, challenge_pending, response_pending, probe_pending;
	// Flow control and streams.
	uint8_t ctl_max_data, ctl_data_blocked, ctl_sb_bidi, ctl_sb_uni;
	uint8_t ctl_max_streams[2];
	uint8_t writable_check;
	// Datagrams: alternate datagrams and stream data in front of a packet.
	uint8_t dgram_first;
	// Close.
	uint8_t close_pending; // send CONNECTION_CLOSE
	uint8_t closed_fire;   // the closed callback is due
	uint8_t closed_fired;
	// Timers.
	uint8_t idle_restart; // the next ack-eliciting send restarts the idle timer
	uint8_t ping_pending;
	uint8_t cid_fired; // the initial cid callback has run

	uint8_t odcid[20];       // the client's first DCID
	uint8_t client_dcid[20]; // server: the DCID the client's Initials carry
	uint8_t retry_scid[20];
	uint8_t peer_scid[20]; // the SCID the peer's first packets carried
	uint8_t challenges[HW_QC_CHALLENGES][8];
	uint8_t response[8];
	uint8_t probe_data[8];
	char close_reason[HW_QC_REASON_MAX];
	uint8_t tp_buf[256];
	uint8_t inject[256]; // tests
};

// Starts a key update (RFC 9001 6.1) when one may start: the handshake is confirmed and a
// packet of the current phase was acknowledged. Returns 0, or -1 when it may not.
int hw_qc_key_update(hw_quic_conn *q);
// hw_quic_connect in two steps, so that a test can reach the TLS client (q->tls) before its
// ClientHello is made: the connection, then the ClientHello (0, or -1 as hw_tls_start).
hw_quic_conn *hw_qc_connect_unstarted(const hw_quic_config *cfg, const hw_quic_callbacks *cb,
                                      const struct sockaddr *peer, socklen_t peer_len, uint64_t now_ms);
int hw_qc_start(hw_quic_conn *q);
// Tests only: bytes appended as frames to the next 1-RTT packet, unchecked (up to 256).
void hw_qc_test_inject(hw_quic_conn *q, const uint8_t *frames, size_t len);
// The same for the next ack-eliciting packet of space spi (HW_QC_SP_*), once it has keys.
void hw_qc_test_inject_at(hw_quic_conn *q, int spi, const uint8_t *frames, size_t len);

#endif
