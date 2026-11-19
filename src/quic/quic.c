/*
 * src/quic/quic.c - a QUIC version 1 connection (holywisp/quic.h): the handshake through
 * holywisp/tls13.h, three packet number spaces, frames in and out, loss detection and recovery
 * (quic_recovery.c), streams with flow control (quic_stream.c), datagrams, connection IDs, path
 * validation, key update and closing. The bytes under it are quic_wire.c's.
 *
 * Re-entrancy rule: callbacks run synchronously from hw_quic_input and hw_quic_on_timeout, and
 * may call any function of this file on the same connection but hw_quic_free. So:
 * - Nothing is freed while a callback can run. A stream that is done is only marked (s->freed)
 *   and freed by conn_gc, which runs where no callback is on the stack: at the end of input and
 *   on_timeout, and at the start of output. A stream pointer held across a callback stays
 *   valid; its fields may have changed (the callback may have reset it or written to it).
 * - A callback may close the connection. After any call that can run one (stream delivery,
 *   frame handling), the caller tests q->state >= HW_QC_ST_CLOSING and stops processing.
 * - The closed callback never runs inside the function that closed: it is due (closed_fire)
 *   and runs at the end of input or on_timeout (hw_quic_timeout says "now" while it is due).
 * - stream_writable and established run at the end of input and on_timeout, from lists built
 *   while processing, never from inside ACK or frame processing, so a write they make cannot
 *   change a list being walked.
 * - TLS calls back (emit, secret) only into this file, never into the application.
 *
 * AEAD limits (RFC 9001 6.6): packets that fail authentication are counted per connection,
 * across every key, and past HW_QC_AEAD_INTEGRITY_LIMIT (ChaCha20-Poly1305's 2^36) the
 * connection closes with AEAD_LIMIT_REACHED. ChaCha20-Poly1305's confidentiality limit is past
 * 2^62 packets, more than a packet number space holds. AES-128-GCM's is 2^23 packets per key,
 * 12 GB of full datagrams: where TLS chose it for 1-RTT, a key update starts after
 * HW_QC_AES_KEY_UPDATE_AT packets of a phase (pkt_header), and a phase that reaches the limit
 * sends nothing more until the update can start. Initial packets are a handful per connection.
 *
 * Datagram size (RFC 9000 14): every connection starts at HW_QUIC_MIN_DGRAM, which every QUIC
 * path carries, and probes for more once the handshake is confirmed (DPLPMTUD, RFC 8899): a PING
 * padded to the size, alone in its datagram. An acknowledged probe raises the size; a lost one is
 * tried HW_QC_PMTU_TRIES times, then the search halves the gap. A probe is never in flight and
 * never ack-eliciting in the books, so its loss is no congestion signal and no PTO. The ceiling is
 * HW_QUIC_MAX_DGRAM and the peer's max_udp_payload_size; a new path starts again at the floor.
 * Starting at 1452 instead lost every full-size packet on a path under 1480 (a VPN, PPPoE) whose
 * ICMP does not come back, and a datagram of that size is most of what a busy session sends.
 * A path whose MTU shrinks later (a route change, a tunnel) is noticed (RFC 8899 4.3, black hole
 * detection, pmtu_bh_acked): HW_QC_PMTU_BH_LOST packets above the base size lost, none at least
 * as large acknowledged since, a smaller packet sent after them acknowledged, and larger ones sent
 * after that lost too. The size falls back to the base and the search starts again under what
 * was lost. From the second PTO in a row on, probes go at the base size, or a session whose every
 * full-size packet is lost would never send the smaller packet that tells a black hole from a
 * dead path.
 *
 * Not implemented (docs/webtransport.md, "QUIC"): 0-RTT, active migration and preferred_address,
 * and ECN.
 */
#include "holywisp/quic.h"

#include "holywisp/hw.h"
#include "holywisp/sys.h"
#include "holywisp/tls13.h"

#include "quic_internal.h"

#include <stdlib.h>
#include <string.h>

#include <netinet/in.h>
#include <sys/socket.h>

#define DEFAULT_STREAM_SEND_MAX (1u << 20)
#define DEFAULT_CONN_SEND_MAX   (16u << 20)
#define DEFAULT_DGRAM_QUEUE     64u
#define PTO_INITIAL_US          (HW_QC_INITIAL_RTT_US + 4 * (HW_QC_INITIAL_RTT_US / 2))
#define LONG_HDR_LEN_FIELD      2 // the Length field is always written in two bytes

static void conn_gc(hw_quic_conn *q);
static void stream_maybe_free(hw_quic_conn *q, hw_qc_stream *s);

// ---- Small helpers ---------------------------------------------------------------------------

static int rnd(void *p, size_t n) {
	return hw_sys_random(p, n);
}

static int cid_eq(const uint8_t *a, size_t al, const uint8_t *b, size_t bl) {
	return al == bl && (al == 0 || memcmp(a, b, al) == 0);
}

// 1 when both name the same address and port; ip_only compares the address alone.
static int addr_eq(const struct sockaddr *a, const struct sockaddr_storage *b, int ip_only) {
	if (a->sa_family != b->ss_family) return 0;
	if (a->sa_family == AF_INET) {
		const struct sockaddr_in *x = (const struct sockaddr_in *)a;
		const struct sockaddr_in *y = (const struct sockaddr_in *)b;
		return x->sin_addr.s_addr == y->sin_addr.s_addr && (ip_only || x->sin_port == y->sin_port);
	}
	if (a->sa_family == AF_INET6) {
		const struct sockaddr_in6 *x = (const struct sockaddr_in6 *)a;
		const struct sockaddr_in6 *y = (const struct sockaddr_in6 *)b;
		return memcmp(&x->sin6_addr, &y->sin6_addr, sizeof(x->sin6_addr)) == 0 &&
		       (ip_only || x->sin6_port == y->sin6_port);
	}
	return 0;
}

static void addr_set(struct sockaddr_storage *dst, socklen_t *dst_len, const struct sockaddr *src, socklen_t len) {
	if (len > (socklen_t)sizeof(*dst)) len = (socklen_t)sizeof(*dst);
	memset(dst, 0, sizeof(*dst));
	memcpy(dst, src, (size_t)len);
	*dst_len = len;
}

static uint64_t pto_base(const hw_quic_conn *q) {
	return hw_qc_rtt_pto(&q->rtt);
}

static int stream_local(const hw_quic_conn *q, uint64_t id) {
	return (int)(id & 1) == (q->is_server ? 1 : 0);
}

// ---- Closing ---------------------------------------------------------------------------------

static void conn_set_reason(hw_quic_conn *q, const char *reason, size_t len) {
	if (!reason) len = 0;
	if (len >= sizeof(q->close_reason)) len = sizeof(q->close_reason) - 1;
	for (size_t i = 0; i < len; i++) {
		if (!reason[i]) {
			len = i;
			break;
		}
	}
	if (len) memcpy(q->close_reason, reason, len);
	q->close_reason[len] = 0;
}

// We close: CONNECTION_CLOSE goes out and the closing period starts.
static void conn_close_with(hw_quic_conn *q, uint64_t err, int app, uint64_t frame_type, const char *reason) {
	if (q->state >= HW_QC_ST_CLOSING) return;
	q->state = HW_QC_ST_CLOSING;
	q->close_error = err;
	q->close_app = app;
	q->close_frame = frame_type;
	conn_set_reason(q, reason, reason ? strlen(reason) : 0);
	q->close_pending = 1;
	q->closed_fire = 1;
	q->close_deadline = q->now + 3 * pto_base(q);
}

static void conn_error(hw_quic_conn *q, uint64_t err, uint64_t frame_type, const char *reason) {
	conn_close_with(q, err, 0, frame_type, reason);
}

// Gone without a word: the idle timeout, a stateless reset, a failed path. No draining wait:
// nothing will be sent and there is nothing to wait for.
static void conn_silent(hw_quic_conn *q, const char *reason) {
	if (q->state >= HW_QC_ST_CLOSING) {
		q->state = HW_QC_ST_DRAINED;
		return;
	}
	q->state = HW_QC_ST_DRAINED;
	q->close_error = HW_QUIC_NO_ERROR;
	q->close_app = 0;
	conn_set_reason(q, reason, strlen(reason));
	q->closed_fire = 1;
}

// ---- Streams ---------------------------------------------------------------------------------

static void send_list_add(hw_quic_conn *q, hw_qc_stream *s) {
	if (s->in_send) return;
	s->in_send = 1;
	if (!q->send_cur) {
		s->send_next = s->send_prev = s;
		q->send_cur = s;
		return;
	}
	// Last in the current round: just before the cursor.
	hw_qc_stream *c = q->send_cur;
	s->send_next = c;
	s->send_prev = c->send_prev;
	c->send_prev->send_next = s;
	c->send_prev = s;
}

static void send_list_remove(hw_quic_conn *q, hw_qc_stream *s) {
	if (!s->in_send) return;
	s->in_send = 0;
	if (s->send_next == s) {
		q->send_cur = NULL;
	} else {
		s->send_prev->send_next = s->send_next;
		s->send_next->send_prev = s->send_prev;
		if (q->send_cur == s) q->send_cur = s->send_next;
	}
	s->send_next = s->send_prev = NULL;
}

static void ctl_add(hw_quic_conn *q, hw_qc_stream *s) {
	if (s->in_ctl) return;
	s->in_ctl = 1;
	s->ctl_next = NULL;
	if (q->ctl_tail) {
		q->ctl_tail->ctl_next = s;
	} else {
		q->ctl_head = s;
	}
	q->ctl_tail = s;
}

static void blk_add(hw_quic_conn *q, hw_qc_stream *s) {
	if (s->in_blk) return;
	s->in_blk = 1;
	s->blk_next = q->blk_head;
	q->blk_head = s;
}

static hw_qc_stream *stream_new(hw_quic_conn *q, uint64_t id) {
	hw_qc_stream *s = calloc(1, sizeof(*s));
	if (!s) return NULL;
	s->id = id;
	int local = stream_local(q, id), bidi = !(id & 2);
	s->has_send = (uint8_t)(bidi || local);
	s->has_recv = (uint8_t)(bidi || !local);
	hw_qc_sendbuf_init(&s->sb);
	hw_qc_recvbuf_init(&s->rb, HW_QC_RECV_RANGES_MAX);
	if (s->has_recv) s->rx_max = q->cfg.initial_max_stream_data;
	if (s->has_send) {
		if (!local) {
			s->tx_max = q->peer_tp.initial_max_stream_data_bidi_local;
		} else {
			s->tx_max = bidi ? q->peer_tp.initial_max_stream_data_bidi_remote : q->peer_tp.initial_max_stream_data_uni;
		}
	}
	if (hw_qc_smap_put(&q->streams, s) < 0) {
		free(s);
		return NULL;
	}
	s->all_next = q->all;
	if (q->all) q->all->all_prev = s;
	q->all = s;
	return s;
}

// The stream a frame from the peer names. Opens it, and every lower one of its kind, when it is
// the peer's to open and new. NULL with *err 0 for a stream that existed and is gone (frames
// for it are ignored), NULL with *err set for a connection error.
static hw_qc_stream *stream_for_peer(hw_quic_conn *q, uint64_t id, uint64_t *err) {
	*err = 0;
	hw_qc_stream *s = hw_qc_smap_get(&q->streams, id);
	if (s) return s->freed ? NULL : s;
	int type = (id & 2) ? 1 : 0;
	uint64_t idx = id >> 2;
	if (stream_local(q, id)) {
		if (idx >= q->next_local[type]) *err = HW_QUIC_STREAM_STATE_ERROR;
		return NULL;
	}
	if (idx < q->next_peer[type]) return NULL;
	if (idx >= q->rx_max_streams[type]) {
		*err = HW_QUIC_STREAM_LIMIT_ERROR;
		return NULL;
	}
	for (uint64_t i = q->next_peer[type]; i <= idx; i++) {
		s = stream_new(q, (i << 2) | (q->is_server ? 0u : 1u) | (type ? 2u : 0u));
		if (!s) {
			*err = HW_QUIC_INTERNAL_ERROR;
			return NULL;
		}
		q->next_peer[type] = i + 1;
	}
	return s;
}

static int stream_send_pending(const hw_qc_stream *s) {
	return s->has_send && !s->tx_reset && hw_qc_sendbuf_pending(&s->sb);
}

static uint64_t stream_write_room(const hw_quic_conn *q, const hw_qc_stream *s, int *why) {
	uint64_t held = s->sb.end - s->sb.base;
	uint64_t room = q->cfg.stream_send_max > held ? q->cfg.stream_send_max - held : 0;
	*why = 0;
	uint64_t r = q->cfg.conn_send_max > q->tx_buffered ? q->cfg.conn_send_max - q->tx_buffered : 0;
	if (r < room) room = r;
	r = s->tx_max > s->sb.end ? s->tx_max - s->sb.end : 0;
	if (r <= room) {
		room = r;
		*why = 1; // the peer's stream credit
	}
	r = q->tx_max_data > q->tx_data ? q->tx_max_data - q->tx_data : 0;
	if (r <= room) {
		room = r;
		*why = 2; // the peer's connection credit
	}
	return room;
}

static void stream_reset_send(hw_quic_conn *q, hw_qc_stream *s, uint64_t err) {
	if (!s->has_send || s->tx_reset || hw_qc_sendbuf_done(&s->sb)) return;
	s->tx_reset = 1;
	s->tx_reset_err = err;
	s->tx_reset_final = s->sb.end;
	q->tx_buffered -= (size_t)(s->sb.end - s->sb.base);
	q->tx_unsent -= (size_t)(s->sb.end - s->sb.sent);
	uint64_t end = s->sb.end;
	hw_qc_sendbuf_clear(&s->sb);
	s->sb.base = s->sb.end = s->sb.sent = end;
	send_list_remove(q, s);
	s->ctl_reset = 1;
	s->ctl_sdb = 0;
	ctl_add(q, s);
}

static int stream_send_done(const hw_qc_stream *s) {
	if (!s->has_send) return 1;
	if (s->tx_reset) return s->tx_reset_acked;
	return hw_qc_sendbuf_done(&s->sb);
}

static int stream_recv_done(const hw_qc_stream *s) {
	return !s->has_recv || s->rx_reset || s->fin_delivered;
}

static void stream_maybe_free(hw_quic_conn *q, hw_qc_stream *s) {
	if (s->freed || !stream_send_done(s) || !stream_recv_done(s)) return;
	s->freed = 1;
	q->free_pending++;
}

// ---- Flow control credit -----------------------------------------------------------------------

static void grant_stream(hw_quic_conn *q, hw_qc_stream *s) {
	uint64_t w = q->cfg.initial_max_stream_data;
	if (!w || s->rb.final != HW_QC_NONE || s->rx_reset || s->rx_stopped) return;
	if (s->rx_max - s->rx_consumed <= w / 2) {
		s->rx_max = s->rx_consumed + w;
		s->ctl_msd = 1;
		ctl_add(q, s);
	}
}

static void grant_conn(hw_quic_conn *q) {
	uint64_t w = q->cfg.initial_max_data;
	if (!w) return;
	if (q->rx_max_data - q->rx_consumed <= w / 2) {
		q->rx_max_data = q->rx_consumed + w;
		q->ctl_max_data = 1;
	}
}

static void grant_streams(hw_quic_conn *q, int type) {
	uint64_t w = type ? q->cfg.initial_max_streams_uni : q->cfg.initial_max_streams_bidi;
	if (!w) return;
	uint64_t half = w / 2 ? w / 2 : 1;
	if (q->peer_closed[type] + w >= q->rx_max_streams[type] + half) {
		uint64_t v = q->peer_closed[type] + w;
		if (v > HW_QC_STREAMS_MAX_VALUE) v = HW_QC_STREAMS_MAX_VALUE;
		if (v > q->rx_max_streams[type]) {
			q->rx_max_streams[type] = v;
			q->ctl_max_streams[type] = 1;
		}
	}
}

// Bytes of the connection that the application will never see (a reset stream's rest, data
// after STOP_SENDING) count as consumed at once.
static void conn_consume(hw_quic_conn *q, uint64_t n) {
	q->rx_consumed += n;
	if (q->rx_consumed > q->rx_highest) q->rx_consumed = q->rx_highest;
	grant_conn(q);
}

// ---- Keys and spaces -------------------------------------------------------------------------

static void space_init(hw_qc_space *sp) {
	memset(sp, 0, sizeof(*sp));
	hw_qc_ranges_init(&sp->recv, HW_QC_ACK_RANGES_MAX, 1);
	hw_qc_ranges_init(&sp->seen, HW_QC_SEEN_RANGES_MAX, 1);
	sp->largest_rx = -1;
	sp->largest_acked = -1;
	sp->ack_deadline = HW_QC_NONE;
	hw_qc_ring_init(&sp->ring);
	hw_qc_sendbuf_init(&sp->crypto_tx);
	hw_qc_recvbuf_init(&sp->crypto_rx, HW_QC_RECV_RANGES_MAX);
}

static void space_free(hw_qc_space *sp) {
	hw_qw_keys_clear(&sp->rx);
	hw_qw_keys_clear(&sp->tx);
	hw_qc_ranges_clear(&sp->recv);
	hw_qc_ranges_clear(&sp->seen);
	hw_qc_ring_clear(&sp->ring);
	hw_qc_sendbuf_clear(&sp->crypto_tx);
	hw_qc_recvbuf_clear(&sp->crypto_rx);
}

// Forget a space's packets as if they had never been in flight (keys discarded, or Retry).
static void space_forget_flight(hw_quic_conn *q, hw_qc_space *sp) {
	for (uint64_t pn = sp->ring.base; pn < sp->ring.next; pn++) {
		hw_qc_sent *s = hw_qc_ring_get(&sp->ring, pn);
		if (s->flags & (HW_QC_SENT_ACKED | HW_QC_SENT_LOST)) continue;
		if (s->flags & HW_QC_SENT_IN_FLIGHT) hw_qc_cc_remove(&q->cc, s->size);
		s->flags |= HW_QC_SENT_LOST;
	}
	hw_qc_ring_trim(&sp->ring, HW_QC_NONE);
	sp->ae_in_flight = 0;
	sp->loss_time = 0;
	sp->last_ae_time = 0;
	sp->probes = 0;
}

static void space_discard(hw_quic_conn *q, int spi) {
	hw_qc_space *sp = &q->sp[spi];
	if (sp->discarded) return;
	space_forget_flight(q, sp);
	sp->discarded = 1;
	sp->has_rx = sp->has_tx = 0;
	hw_qw_keys_clear(&sp->rx);
	hw_qw_keys_clear(&sp->tx);
	hw_qc_sendbuf_clear(&sp->crypto_tx);
	hw_qc_recvbuf_clear(&sp->crypto_rx);
	hw_qc_ranges_clear(&sp->recv);
	hw_qc_ranges_clear(&sp->seen);
	sp->ack_new = sp->ack_now = 0;
	sp->ae_unacked = 0;
	q->pto_count = 0;
}

static int tls_emit(void *ud, hw_tls_level level, const uint8_t *data, size_t len) {
	hw_quic_conn *q = ud;
	hw_qc_space *sp = &q->sp[level];
	if (sp->discarded) return -1;
	return hw_qc_sendbuf_write(&sp->crypto_tx, data, len);
}

static int tls_secret(void *ud, hw_tls_level level, int write, uint16_t cipher, const uint8_t secret[32]) {
	hw_quic_conn *q = ud;
	hw_qc_space *sp = &q->sp[level];
	if (write) {
		hw_qw_keys_from_secret(&sp->tx, cipher, secret);
		sp->has_tx = 1;
		if (level == HW_TLS_APP) {
			q->key_update_at = cipher == HW_TLS_CIPHER_AES128GCM ? HW_QC_AES_KEY_UPDATE_AT : UINT64_MAX;
		}
	} else {
		hw_qw_keys_from_secret(&sp->rx, cipher, secret);
		sp->has_rx = 1;
		if (level == HW_TLS_APP) hw_qw_keys_update(&q->rx_next, &sp->rx);
	}
	return 0;
}

int hw_qc_key_update(hw_quic_conn *q) {
	if (!q->handshake_confirmed || !q->tx_phase_acked || q->tx_phase != q->rx_phase) return -1;
	if (q->state != HW_QC_ST_ACTIVE) return -1;
	hw_qw_keys next;
	hw_qw_keys_update(&next, &q->sp[HW_QC_SP_APP].tx);
	q->sp[HW_QC_SP_APP].tx = next;
	hw_qw_keys_clear(&next);
	q->tx_phase ^= 1;
	q->tx_phase_first_pn = q->sp[HW_QC_SP_APP].ring.next;
	q->tx_phase_acked = 0;
	q->key_updates++;
	return 0;
}

void hw_qc_test_inject_at(hw_quic_conn *q, int spi, const uint8_t *frames, size_t len) {
	if (len > sizeof(q->inject)) len = sizeof(q->inject);
	memcpy(q->inject, frames, len);
	q->inject_len = len;
	q->inject_spi = spi;
}

void hw_qc_test_inject(hw_quic_conn *q, const uint8_t *frames, size_t len) {
	hw_qc_test_inject_at(q, HW_QC_SP_APP, frames, len);
}

// ---- Connection IDs --------------------------------------------------------------------------

static int cid_make(hw_quic_conn *q, hw_qc_our_cid *c) {
	c->cid[0] = q->cfg.cid_prefix;
	if (rnd(c->cid + 1, HW_QUIC_CID_LEN - 1) < 0) return -1;
	if (q->cfg.reset_key) {
		hw_qw_reset_token(q->cfg.reset_key, c->cid, HW_QUIC_CID_LEN, c->token);
	} else if (rnd(c->token, HW_QUIC_RESET_LEN) < 0) {
		return -1;
	}
	return 0;
}

// Issue CIDs up to the peer's active_connection_id_limit (at most HW_QC_OUR_CIDS).
static void cid_issue(hw_quic_conn *q) {
	if (!q->peer_tp_applied || q->state >= HW_QC_ST_CLOSING) return;
	uint64_t limit = HW_MIN(q->peer_tp.active_connection_id_limit, (uint64_t)HW_QC_OUR_CIDS);
	size_t active = 0;
	for (size_t i = 0; i < HW_QC_OUR_CIDS; i++) active += q->ours[i].active;
	for (size_t i = 0; i < HW_QC_OUR_CIDS && active < limit; i++) {
		hw_qc_our_cid *c = &q->ours[i];
		if (c->active) continue;
		if (cid_make(q, c) < 0) return;
		c->seq = q->our_next_seq++;
		c->active = 1;
		c->ncid_pending = 1;
		active++;
		if (q->cb.cid) q->cb.cid(q->cb.ud, c->cid, 0);
	}
}

static int cid_ours(const hw_quic_conn *q, const uint8_t *cid, size_t len) {
	if (len != HW_QUIC_CID_LEN) return 0;
	for (size_t i = 0; i < HW_QC_OUR_CIDS; i++) {
		if (q->ours[i].active && memcmp(q->ours[i].cid, cid, HW_QUIC_CID_LEN) == 0) return 1;
	}
	return 0;
}

static hw_qc_peer_cid *peer_cid_cur(hw_quic_conn *q) {
	return &q->peers[q->peer_cur];
}

static void retire_queue(hw_quic_conn *q, uint64_t seq) {
	if (q->retire_n >= HW_QC_RETIRE_MAX) {
		conn_error(q, HW_QC_CONNECTION_ID_LIMIT, HW_QC_F_NEW_CONNECTION_ID, "too many retirements");
		return;
	}
	q->retire_q[q->retire_n++] = seq;
}

static void handle_new_cid(hw_quic_conn *q, const hw_qc_frame *f) {
	if (q->peer_scid_len == 0) {
		conn_error(q, HW_QUIC_PROTOCOL_VIOLATION, f->type, "NEW_CONNECTION_ID to a zero-length CID");
		return;
	}
	uint64_t seq = f->value, rpt = f->value2;
	if (seq < q->peer_retire_prior) {
		retire_queue(q, seq);
		return;
	}
	int have = 0;
	for (size_t i = 0; i < HW_QC_PEER_CIDS; i++) {
		hw_qc_peer_cid *p = &q->peers[i];
		if (!p->used) continue;
		int same_cid = cid_eq(p->cid, p->len, f->data, f->len);
		if (p->seq == seq) {
			if (!same_cid || (p->has_token && memcmp(p->token, f->token, HW_QUIC_RESET_LEN) != 0)) {
				conn_error(q, HW_QUIC_PROTOCOL_VIOLATION, f->type, "NEW_CONNECTION_ID changed");
				return;
			}
			have = 1;
		} else if (same_cid) {
			conn_error(q, HW_QUIC_PROTOCOL_VIOLATION, f->type, "NEW_CONNECTION_ID reused");
			return;
		}
	}
	if (!have) {
		hw_qc_peer_cid *slot = NULL;
		for (size_t i = 0; i < HW_QC_PEER_CIDS && !slot; i++) {
			if (!q->peers[i].used) slot = &q->peers[i];
		}
		if (!slot) {
			conn_error(q, HW_QC_CONNECTION_ID_LIMIT, f->type, "connection ID limit");
			return;
		}
		slot->used = 1;
		slot->seq = seq;
		slot->len = (uint8_t)f->len;
		memcpy(slot->cid, f->data, f->len);
		memcpy(slot->token, f->token, HW_QUIC_RESET_LEN);
		slot->has_token = 1;
	}
	if (rpt > q->peer_retire_prior) {
		q->peer_retire_prior = rpt;
		for (size_t i = 0; i < HW_QC_PEER_CIDS; i++) {
			hw_qc_peer_cid *p = &q->peers[i];
			if (!p->used || p->seq >= rpt) continue;
			retire_queue(q, p->seq);
			p->used = 0;
		}
		if (!q->peers[q->peer_cur].used) {
			int best = -1;
			for (size_t i = 0; i < HW_QC_PEER_CIDS; i++) {
				if (q->peers[i].used && (best < 0 || q->peers[i].seq < q->peers[best].seq)) best = (int)i;
			}
			if (best < 0) {
				conn_error(q, HW_QUIC_PROTOCOL_VIOLATION, f->type, "every connection ID retired");
				return;
			}
			q->peer_cur = best;
		}
	}
	size_t used = 0;
	for (size_t i = 0; i < HW_QC_PEER_CIDS; i++) used += q->peers[i].used;
	if (used > HW_QC_PEER_CID_LIMIT) conn_error(q, HW_QC_CONNECTION_ID_LIMIT, f->type, "connection ID limit");
}

static void handle_retire_cid(hw_quic_conn *q, const hw_qc_frame *f, const uint8_t *dcid, size_t dcid_len) {
	if (f->value >= q->our_next_seq) {
		conn_error(q, HW_QUIC_PROTOCOL_VIOLATION, f->type, "RETIRE_CONNECTION_ID of an unissued sequence");
		return;
	}
	for (size_t i = 0; i < HW_QC_OUR_CIDS; i++) {
		hw_qc_our_cid *c = &q->ours[i];
		if (!c->active || c->seq != f->value) continue;
		if (cid_eq(c->cid, HW_QUIC_CID_LEN, dcid, dcid_len)) {
			conn_error(q, HW_QUIC_PROTOCOL_VIOLATION, f->type, "RETIRE_CONNECTION_ID of the packet's CID");
			return;
		}
		c->active = 0;
		c->ncid_pending = 0;
		if (q->cb.cid) q->cb.cid(q->cb.ud, c->cid, 1);
		cid_issue(q);
		return;
	}
}

// ---- Transport parameters ----------------------------------------------------------------------

static int tp_build(hw_quic_conn *q) {
	hw_qw_tp tp;
	hw_qw_tp_defaults(&tp);
	tp.max_idle_timeout = q->cfg.max_idle_ms;
	tp.max_udp_payload_size = HW_QUIC_MAX_DGRAM;
	tp.initial_max_data = q->cfg.initial_max_data;
	tp.initial_max_stream_data_bidi_local = q->cfg.initial_max_stream_data;
	tp.initial_max_stream_data_bidi_remote = q->cfg.initial_max_stream_data;
	tp.initial_max_stream_data_uni = q->cfg.initial_max_stream_data;
	tp.initial_max_streams_bidi = q->cfg.initial_max_streams_bidi;
	tp.initial_max_streams_uni = q->cfg.initial_max_streams_uni;
	tp.active_connection_id_limit = HW_QC_PEER_CID_LIMIT;
	tp.max_datagram_frame_size = q->cfg.max_datagram_frame_size;
	tp.has_initial_scid = 1;
	tp.initial_scid_len = HW_QUIC_CID_LEN;
	memcpy(tp.initial_scid, q->ours[0].cid, HW_QUIC_CID_LEN);
	if (q->is_server) {
		tp.has_original_dcid = 1;
		tp.original_dcid_len = q->odcid_len;
		memcpy(tp.original_dcid, q->odcid, q->odcid_len);
		if (q->retry_scid_len) {
			tp.has_retry_scid = 1;
			tp.retry_scid_len = q->retry_scid_len;
			memcpy(tp.retry_scid, q->retry_scid, q->retry_scid_len);
		}
		tp.has_reset_token = 1;
		memcpy(tp.reset_token, q->ours[0].token, HW_QUIC_RESET_LEN);
	}
	q->tp_len = hw_qw_tp_encode(&tp, q->is_server, q->tp_buf, sizeof(q->tp_buf));
	return q->tp_len ? 0 : -1;
}

static void tp_apply(hw_quic_conn *q) {
	if (q->peer_tp_applied) return;
	size_t len = 0;
	const uint8_t *p = hw_tls_peer_transport_params(q->tls, &len);
	if (!p) return;
	hw_qw_tp tp;
	if (hw_qw_tp_decode(p, len, !q->is_server, &tp) < 0) {
		conn_error(q, HW_QUIC_TRANSPORT_PARAMETER_ERROR, HW_QC_F_CRYPTO, "transport parameters");
		return;
	}
	// RFC 9000 7.3: the CIDs each side used are authenticated here.
	int ok = tp.has_initial_scid && cid_eq(tp.initial_scid, tp.initial_scid_len, q->peer_scid, q->peer_scid_len);
	if (!q->is_server) {
		ok = ok && tp.has_original_dcid && cid_eq(tp.original_dcid, tp.original_dcid_len, q->odcid, q->odcid_len);
		if (q->retried) {
			ok = ok && tp.has_retry_scid && cid_eq(tp.retry_scid, tp.retry_scid_len, q->retry_scid, q->retry_scid_len);
		} else {
			ok = ok && !tp.has_retry_scid;
		}
	}
	if (!ok) {
		conn_error(q, HW_QUIC_TRANSPORT_PARAMETER_ERROR, HW_QC_F_CRYPTO, "connection IDs in transport parameters");
		return;
	}
	q->peer_tp = tp;
	q->peer_tp_applied = 1;
	uint64_t ours = q->cfg.max_idle_ms, theirs = tp.max_idle_timeout;
	q->idle_ms = !ours ? theirs : !theirs ? ours : HW_MIN(ours, theirs);
	q->pmtu_max = HW_MIN((uint64_t)HW_QUIC_MAX_DGRAM, tp.max_udp_payload_size);
	if (q->pmtu_max < q->mds) {
		q->mds = q->pmtu_max;
		q->cc.mds = q->mds;
	}
	q->tx_max_data = tp.initial_max_data;
	q->peer_max_streams[0] = tp.initial_max_streams_bidi;
	q->peer_max_streams[1] = tp.initial_max_streams_uni;
	q->peer_max_ack_delay = tp.max_ack_delay * 1000;
	if (!q->is_server && tp.has_reset_token) {
		memcpy(q->peers[0].token, tp.reset_token, HW_QUIC_RESET_LEN);
		q->peers[0].has_token = 1;
	}
	cid_issue(q);
}

// ---- Recovery ------------------------------------------------------------------------------------

static int peer_validated(const hw_quic_conn *q) {
	return q->is_server || q->peer_validated_addr || q->handshake_confirmed;
}

static void frame_acked(hw_quic_conn *q, hw_qc_space *sp, const hw_qc_frec *r) {
	hw_qc_stream *s;
	switch (r->type) {
	case HW_QC_R_STREAM:
		s = hw_qc_smap_get(&q->streams, r->id);
		if (!s || s->tx_reset) break;
		size_t freed = hw_qc_sendbuf_ack(&s->sb, r->off, r->len, r->fin);
		if (freed) {
			q->tx_buffered -= freed;
			q->writable_check = 1;
		}
		if (hw_qc_sendbuf_done(&s->sb)) stream_maybe_free(q, s);
		break;
	case HW_QC_R_CRYPTO:
		if (!sp->discarded) hw_qc_sendbuf_ack(&sp->crypto_tx, r->off, r->len, 0);
		break;
	case HW_QC_R_ACK:
		hw_qc_ranges_forget_below(&sp->recv, r->id);
		break;
	case HW_QC_R_RESET_STREAM:
		s = hw_qc_smap_get(&q->streams, r->id);
		if (s) {
			s->tx_reset_acked = 1;
			stream_maybe_free(q, s);
		}
		break;
	default:
		break;
	}
}

static void frame_lost(hw_quic_conn *q, hw_qc_space *sp, const hw_qc_frec *r) {
	hw_qc_stream *s = NULL;
	switch (r->type) {
	case HW_QC_R_STREAM:
		s = hw_qc_smap_get(&q->streams, r->id);
		if (!s || s->tx_reset) break;
		hw_qc_sendbuf_lost(&s->sb, r->off, r->len, r->fin);
		if (stream_send_pending(s)) send_list_add(q, s);
		break;
	case HW_QC_R_CRYPTO:
		if (!sp->discarded) hw_qc_sendbuf_lost(&sp->crypto_tx, r->off, r->len, 0);
		break;
	case HW_QC_R_MAX_DATA:
		q->ctl_max_data = 1;
		break;
	case HW_QC_R_MAX_STREAM_DATA:
		s = hw_qc_smap_get(&q->streams, r->id);
		if (s && !s->freed && s->rb.final == HW_QC_NONE && !s->rx_reset && !s->rx_stopped) {
			s->ctl_msd = 1;
			ctl_add(q, s);
		}
		break;
	case HW_QC_R_MAX_STREAMS_BIDI:
	case HW_QC_R_MAX_STREAMS_UNI:
		q->ctl_max_streams[r->type == HW_QC_R_MAX_STREAMS_UNI] = 1;
		break;
	case HW_QC_R_RESET_STREAM:
		s = hw_qc_smap_get(&q->streams, r->id);
		if (s && !s->tx_reset_acked) {
			s->ctl_reset = 1;
			ctl_add(q, s);
		}
		break;
	case HW_QC_R_STOP_SENDING:
		s = hw_qc_smap_get(&q->streams, r->id);
		if (s && !s->freed && !s->fin_delivered && !s->rx_reset) {
			s->ctl_stop = 1;
			ctl_add(q, s);
		}
		break;
	case HW_QC_R_NEW_CID:
		for (size_t i = 0; i < HW_QC_OUR_CIDS; i++) {
			if (q->ours[i].active && q->ours[i].seq == r->id) q->ours[i].ncid_pending = 1;
		}
		break;
	case HW_QC_R_RETIRE_CID:
		if (q->retire_n < HW_QC_RETIRE_MAX) q->retire_q[q->retire_n++] = r->id;
		break;
	case HW_QC_R_HANDSHAKE_DONE:
		if (q->handshake_confirmed && q->is_server) q->hsd_pending = 1;
		break;
	default:
		break;
	}
}

static void cc_init(hw_quic_conn *q) {
	hw_qc_cc_init(&q->cc, q->mds, q->now);
	if (q->cfg.timer_tick_us) hw_qc_pacer_set_tick(&q->cc, q->cfg.timer_tick_us);
	if (q->cfg.congestion == HW_QUIC_CC_BBR2) {
		hw_qc_cc_use_bbr2(&q->cc, q->now);
	} else if (q->cfg.congestion != HW_QUIC_CC_NEWRENO) {
		hw_qc_cc_use_bbr(&q->cc, q->now);
	}
}

static void pmtu_result(hw_quic_conn *q, int passed);

static void packet_resolve(hw_quic_conn *q, hw_qc_space *sp, hw_qc_sent *s, int acked) {
	if ((s->flags & HW_QC_SENT_PMTU) && q->pmtu_probe && hw_qc_ring_get(&sp->ring, q->pmtu_pn) == s) {
		pmtu_result(q, acked);
	}
	for (uint16_t i = 0; i < s->nframes; i++) {
		const hw_qc_frec *r = hw_qc_ring_frame(&sp->ring, s->frame0 + i);
		if (acked) {
			frame_acked(q, sp, r);
		} else {
			frame_lost(q, sp, r);
		}
	}
	if (s->flags & HW_QC_SENT_ACK_ELICITING) sp->ae_in_flight--;
	if (acked) {
		if (s->flags & HW_QC_SENT_IN_FLIGHT) {
			if (s->flags & HW_QC_SENT_LIMITED) q->stats.acked_limited += s->size;
			hw_qc_rs_on_acked(&q->cc, s, q->now);
			hw_qc_cc_on_acked(&q->cc, s->size, s->time, (s->flags & HW_QC_SENT_LIMITED) != 0);
		}
		s->flags |= HW_QC_SENT_ACKED;
	} else {
		if (s->flags & HW_QC_SENT_IN_FLIGHT) {
			hw_qc_cc_remove(&q->cc, s->size);
			q->stats.packets_lost++;
		}
		s->flags |= HW_QC_SENT_LOST;
	}
}

// ---- PMTU black holes ----------------------------------------------------------------------------

static void pmtu_bh_clear(hw_quic_conn *q) {
	q->bh_lost = 0;
	q->bh_min = 0;
	q->bh_last = 0;
	q->bh_small = 0;
}

// A 1-RTT packet above the base size was declared lost.
static void pmtu_bh_lost(hw_quic_conn *q, uint64_t pn, uint64_t size) {
	if (!q->bh_lost || size < q->bh_min) q->bh_min = size;
	if (pn > q->bh_last) q->bh_last = pn;
	q->bh_lost++;
}

// An ACK frame newly acknowledged 1-RTT packets, the largest of them at most `largest_size` bytes
// and the newest `top_pn` of `top_size`, and (declared) its losses have been declared. A packet
// as large as the smallest one lost shows the path carries that size: the losses were the path's
// ordinary ones. With none such, a smaller packet sent after every one of them that arrived says
// the size may be what the path lost, and large packets sent after that one and lost too say it
// is: the size falls to the base, and the search starts again below what failed. Random loss
// never takes HW_QC_PMTU_BH_LOST large packets with no large one acknowledged between. After an
// outage the first packet through is often a small probe (HW_QC_PMTU_BH_PTOS), which is why one
// small packet is not enough: what follows it arrives, large or small, and clears the suspicion.
static void pmtu_bh_acked(hw_quic_conn *q, uint64_t largest_size, uint64_t top_pn, uint64_t top_size, int declared) {
	if (!q->bh_lost) return;
	if (largest_size >= q->bh_min) {
		pmtu_bh_clear(q);
		return;
	}
	if (!declared || q->bh_lost < HW_QC_PMTU_BH_LOST || top_pn <= q->bh_last || top_size >= q->bh_min) return;
	if (!q->bh_small || q->bh_last < q->bh_small) {
		q->bh_small = top_pn;
		return;
	}
	if (q->mds <= HW_QUIC_MIN_DGRAM) {
		pmtu_bh_clear(q);
		return;
	}
	q->pmtu_bad = q->bh_min;
	q->mds = HW_QUIC_MIN_DGRAM;
	q->cc.mds = HW_QUIC_MIN_DGRAM;
	q->pmtu_probe = 0;
	q->pmtu_deadline = 0;
	q->pmtu_tries = 0;
	q->pmtu_next = q->now + pto_base(q);
	q->pmtu_black_holes++;
	pmtu_bh_clear(q);
}

// How long a packet declared lost is remembered for a late acknowledgment to prove the loss
// spurious: packets sent since the returned time are kept. Two PTOs cover a reordering delay
// that the adaptive thresholds have not caught up with yet, and the peer's ACK delay.
static uint64_t lost_keep_since(const hw_quic_conn *q) {
	uint64_t keep = 2 * (hw_qc_rtt_pto(&q->rtt) + q->peer_max_ack_delay);
	return q->now > keep ? q->now - keep : 0;
}

static void detect_lost(hw_quic_conn *q, int spi) {
	hw_qc_space *sp = &q->sp[spi];
	sp->loss_time = 0;
	if (sp->largest_acked < 0) return;
	uint64_t now = q->now;
	uint64_t delay = hw_qc_rtt_loss_delay(&q->rtt, q->time_shift);
	uint64_t largest = (uint64_t)sp->largest_acked;
	uint64_t latest_lost = 0, run_start = 0, run_end = 0, nlost = 0, first_lost = 0, last_lost = 0;
	int run = 0, persistent = 0;
	uint64_t pc_dur = (hw_qc_rtt_pto(&q->rtt) + q->peer_max_ack_delay) * HW_QC_PERSISTENT_FACTOR;
	// Lost packets are kept in the ring a while (lost_keep_since), so its base can be far
	// behind; what is resolved from there on is skipped once, not on every ACK.
	uint64_t pn = HW_MAX(sp->ring.base, sp->scan_from);
	while (pn < sp->ring.next && (hw_qc_ring_get(&sp->ring, pn)->flags & (HW_QC_SENT_ACKED | HW_QC_SENT_LOST))) pn++;
	sp->scan_from = pn;
	for (; pn <= largest && pn < sp->ring.next; pn++) {
		hw_qc_sent *s = hw_qc_ring_get(&sp->ring, pn);
		if (s->flags & HW_QC_SENT_ACKED) {
			run = 0;
			continue;
		}
		if (s->flags & HW_QC_SENT_LOST) continue;
		if (s->time + delay <= now || largest >= pn + q->pkt_threshold) {
			if (s->flags & HW_QC_SENT_IN_FLIGHT) {
				if (!nlost++) first_lost = pn;
				last_lost = pn;
				if (s->time > latest_lost) latest_lost = s->time;
				hw_qc_cc_on_lost(&q->cc, s, pn);
				if (spi == HW_QC_SP_APP && s->size > HW_QUIC_MIN_DGRAM) pmtu_bh_lost(q, pn, s->size);
			}
			if (s->flags & HW_QC_SENT_ACK_ELICITING) {
				if (!run) {
					run = 1;
					run_start = s->time;
				}
				run_end = s->time;
				if (q->rtt.has_sample && run_start >= q->rtt.first_sample_time && run_end - run_start > pc_dur) {
					persistent = 1;
				}
			}
			packet_resolve(q, sp, s, 0);
		} else {
			uint64_t t = s->time + delay;
			if (!sp->loss_time || t < sp->loss_time) sp->loss_time = t;
		}
	}
	if (nlost) {
		hw_qc_cc_congestion_event(&q->cc, latest_lost, nlost, now);
		// Stamp what this call declared lost with the period it now belongs to: in
		// [first_lost, last_lost], the packets lost in flight that no earlier call stamped.
		for (uint64_t i = first_lost; i <= last_lost; i++) {
			hw_qc_sent *s = hw_qc_ring_get(&sp->ring, i);
			if (s && (s->flags & (HW_QC_SENT_LOST | HW_QC_SENT_ACKED | HW_QC_SENT_IN_FLIGHT | HW_QC_SENT_STAMPED)) ==
			             (HW_QC_SENT_LOST | HW_QC_SENT_IN_FLIGHT)) {
				s->loss_epoch = q->cc.epoch;
				s->flags |= HW_QC_SENT_STAMPED;
			}
		}
		if (persistent) hw_qc_cc_persistent(&q->cc);
	}
	hw_qc_ring_trim(&sp->ring, lost_keep_since(q));
}

// A packet declared lost was acknowledged: the loss was spurious. The thresholds grow so that
// the same reordering would not have been taken for a loss (RFC 9002 6.1: RACK's adaptation, as
// Chromium's QUIC does it), the frames count as acknowledged (a retransmission still queued
// is dropped), and the congestion response is undone when its whole period was spurious.
static void on_spurious(hw_quic_conn *q, hw_qc_space *sp, hw_qc_sent *s, uint64_t pn, uint64_t largest) {
	q->spurious_lost++;
	s->flags |= HW_QC_SENT_ACKED;
	uint64_t dist = largest - pn + 1;
	if (dist > q->pkt_threshold) q->pkt_threshold = HW_MIN(dist, (uint64_t)HW_QC_PACKET_THRESH_MAX);
	uint64_t needed = q->now > s->time ? q->now - s->time : 0;
	uint64_t rtt = HW_MAX(q->rtt.latest, q->rtt.smoothed);
	while (q->time_shift > 0 && rtt + (rtt >> q->time_shift) < needed) q->time_shift--;
	for (uint16_t i = 0; i < s->nframes; i++) frame_acked(q, sp, hw_qc_ring_frame(&sp->ring, s->frame0 + i));
	if (s->flags & HW_QC_SENT_STAMPED) hw_qc_cc_spurious(&q->cc, s->loss_epoch);
}

// Whether an ACK can still change a sent packet: one not acknowledged, and not one declared lost
// that was never in flight. A packet lost in flight stays open: acknowledged late, it shows its
// loss spurious. Once closed, a packet stays closed (no flag that opens it is ever set again).
static int sent_open(const hw_qc_sent *s) {
	if (s->flags & HW_QC_SENT_ACKED) return 0;
	return !(s->flags & HW_QC_SENT_LOST) || (s->flags & HW_QC_SENT_IN_FLIGHT);
}

// The packet a closed packet at pn sends the search on to: every packet between it and pn is closed.
static uint64_t sent_below(const hw_qc_sent *s, uint64_t pn) {
	return s->below < pn ? s->below : pn - 1;
}

// The highest open packet in [lo, pn] (sent_open), in *out; 0 when there is none. A closed
// packet points below itself (hw_qc_sent.below), and every packet the search passes is then
// pointed at where it ended, so a stretch already acknowledged costs a step or two however long
// it is (a union-find with path compression). A peer that names the same ranges in every ACK
// frame, as Chrome does while a loss is remembered and as anyone can with one packet left
// unacknowledged at the base of the ring, costs what each frame newly acknowledges, not what the
// ring holds: walking each range packet by packet was quadratic in the packets sent meanwhile.
static int ack_next_open(hw_quic_conn *q, hw_qc_ring *r, uint64_t pn, uint64_t lo, uint64_t *out) {
	uint64_t end = pn;
	int found = 0;
	for (;;) {
		const hw_qc_sent *s = hw_qc_ring_get(r, end);
		if (!s) break; // below the ring: nothing tracked is left there
		q->ack_steps++;
		if (sent_open(s)) {
			found = 1;
			break;
		}
		if (end == 0) break;
		end = sent_below(s, end);
		if (end < lo) break;
	}
	// Every closed packet passed has only closed ones down to end, end itself excluded.
	for (uint64_t x = pn; x > end;) {
		hw_qc_sent *s = hw_qc_ring_get(r, x);
		uint64_t next = sent_below(s, x);
		s->below = end;
		x = next;
	}
	*out = end;
	return found && end >= lo;
}

static void on_ack(hw_quic_conn *q, int spi, const hw_qc_frame *f) {
	hw_qc_space *sp = &q->sp[spi];
	if (f->ack_largest >= sp->ring.next) {
		conn_error(q, HW_QUIC_PROTOCOL_VIOLATION, HW_QC_F_ACK, "ACK of an unsent packet");
		return;
	}
	if ((int64_t)f->ack_largest > sp->largest_acked) sp->largest_acked = (int64_t)f->ack_largest;
	hw_qc_ack_iter it;
	hw_qc_ack_iter_init(&it, f);
	int newly = 0, ae_newly = 0;
	uint64_t largest_time = 0;
	int largest_newly = 0;
	uint64_t acked_size = 0, top_pn = 0, top_size = 0; // 1-RTT: for black hole detection
	do {
		uint64_t lo = HW_MAX(it.lo, sp->ring.base);
		if (it.hi < lo) continue;
		uint64_t hi = HW_MIN(it.hi, sp->ring.next - 1);
		uint64_t pn;
		for (uint64_t top = hi; ack_next_open(q, &sp->ring, top, lo, &pn); top = pn - 1) {
			hw_qc_sent *s = hw_qc_ring_get(&sp->ring, pn);
			if (s->size > acked_size) acked_size = s->size;
			if (!top_size) {
				top_pn = pn; // the walk goes down from the largest
				top_size = s->size;
			}
			if (s->flags & HW_QC_SENT_LOST) {
				on_spurious(q, sp, s, pn, f->ack_largest); // lost in flight: sent_open says no other
			} else {
				if (pn == f->ack_largest) {
					largest_newly = 1;
					largest_time = s->time;
				}
				if (s->flags & HW_QC_SENT_ACK_ELICITING) ae_newly = 1;
				if (spi == HW_QC_SP_APP && ((s->flags & HW_QC_SENT_PHASE) ? 1 : 0) == q->tx_phase &&
				    pn >= q->tx_phase_first_pn) {
					q->tx_phase_acked = 1;
				}
				newly = 1;
				packet_resolve(q, sp, s, 1);
			}
			if (pn == lo) break;
		}
	} while (hw_qc_ack_iter_next(&it));
	if (spi == HW_QC_SP_APP) pmtu_bh_acked(q, acked_size, top_pn, top_size, 0);
	if (!newly) return;
	uint64_t rtt_sample = 0;
	if (largest_newly && ae_newly) {
		uint64_t latest = q->now > largest_time ? q->now - largest_time : 0;
		uint64_t ack_delay = 0;
		if (spi == HW_QC_SP_APP) {
			uint64_t exp = q->peer_tp_applied ? q->peer_tp.ack_delay_exponent : HW_QC_ACK_DELAY_EXP;
			ack_delay = f->ack_delay < (1ull << 40) ? f->ack_delay << exp : UINT64_MAX / 2;
			if (q->handshake_confirmed && ack_delay > q->peer_max_ack_delay) ack_delay = q->peer_max_ack_delay;
		}
		hw_qc_rtt_sample(&q->rtt, latest, ack_delay, q->now);
		rtt_sample = latest ? latest : 1; // 0 is "no sample"; BBR floors its own model
	}
	if (!q->is_server && spi == HW_QC_SP_HANDSHAKE) q->peer_validated_addr = 1;
	detect_lost(q, spi);
	if (spi == HW_QC_SP_APP) pmtu_bh_acked(q, acked_size, top_pn, top_size, 1);
	hw_qc_cc_on_ack_done(&q->cc, rtt_sample, q->now);
	if (peer_validated(q)) q->pto_count = 0;
	hw_qc_ring_trim(&sp->ring, lost_keep_since(q));
	q->writable_check = 1;
}

static uint64_t pto_period(const hw_quic_conn *q, int spi) {
	uint64_t d = pto_base(q);
	if (spi == HW_QC_SP_APP) d += q->peer_max_ack_delay;
	return d << HW_MIN(q->pto_count, 16u);
}

static int amp_blocked(const hw_quic_conn *q) {
	return q->is_server && !q->path_validated && q->amp_tx + HW_QUIC_MIN_DGRAM / 4 > 3 * q->amp_rx;
}

// The loss detection timer (RFC 9002 A.8): the earliest loss time, else the PTO.
static uint64_t loss_timer(const hw_quic_conn *q, int *space, int *is_loss) {
	uint64_t best = HW_QC_NONE;
	*is_loss = 0;
	*space = HW_QC_SP_INITIAL;
	for (int i = 0; i < HW_QC_SPACES; i++) {
		if (q->sp[i].loss_time && q->sp[i].loss_time < best) {
			best = q->sp[i].loss_time;
			*space = i;
			*is_loss = 1;
		}
	}
	if (*is_loss) return best;
	if (amp_blocked(q)) return HW_QC_NONE;
	int any = 0;
	for (int i = 0; i < HW_QC_SPACES; i++) any |= q->sp[i].ae_in_flight != 0;
	if (!any) {
		if (peer_validated(q) || q->state != HW_QC_ST_HANDSHAKE) return HW_QC_NONE;
		*space = q->sp[HW_QC_SP_HANDSHAKE].has_tx ? HW_QC_SP_HANDSHAKE : HW_QC_SP_INITIAL;
		return q->pto_anchor + pto_period(q, *space);
	}
	for (int i = 0; i < HW_QC_SPACES; i++) {
		const hw_qc_space *sp = &q->sp[i];
		if (!sp->ae_in_flight) continue;
		if (i == HW_QC_SP_APP && !q->handshake_confirmed) continue;
		uint64_t t = sp->last_ae_time + pto_period(q, i);
		if (t < best) {
			best = t;
			*space = i;
		}
	}
	return best;
}

// A PTO fired: send the oldest unacknowledged data again (or a PING) as probes.
static void pto_fire(hw_quic_conn *q, int spi) {
	hw_qc_space *sp = &q->sp[spi];
	if (spi != HW_QC_SP_APP) {
		if (sp->crypto_tx.sent > sp->crypto_tx.base) {
			hw_qc_sendbuf_lost(&sp->crypto_tx, sp->crypto_tx.base, (size_t)(sp->crypto_tx.sent - sp->crypto_tx.base),
			                   0);
		}
		sp->probes = 1;
		return;
	}
	int n = 0;
	for (uint64_t pn = sp->ring.base; pn < sp->ring.next && n < 2; pn++) {
		hw_qc_sent *s = hw_qc_ring_get(&sp->ring, pn);
		if (!(s->flags & HW_QC_SENT_ACK_ELICITING) || (s->flags & (HW_QC_SENT_ACKED | HW_QC_SENT_LOST))) continue;
		for (uint16_t i = 0; i < s->nframes; i++) frame_lost(q, sp, hw_qc_ring_frame(&sp->ring, s->frame0 + i));
		n++;
	}
	sp->probes = 2;
}

static void on_loss_timeout(hw_quic_conn *q) {
	int spi, is_loss;
	uint64_t t = loss_timer(q, &spi, &is_loss);
	if (t == HW_QC_NONE || t > q->now) return;
	if (is_loss) {
		detect_lost(q, spi);
		q->writable_check = 1;
		return;
	}
	int any = 0;
	for (int i = 0; i < HW_QC_SPACES; i++) any |= q->sp[i].ae_in_flight != 0;
	if (!any) {
		// A client the server cannot answer yet (amplification): a probe to give it room.
		q->sp[spi].probes = 1;
		q->pto_anchor = q->now;
	} else {
		pto_fire(q, spi);
	}
	q->pto_count++;
	q->stats.ptos++;
}

// ---- Receiving: frames -----------------------------------------------------------------------

static void stream_deliver(hw_quic_conn *q, hw_qc_stream *s, const uint8_t *direct, size_t dlen) {
	hw_qc_recvbuf *rb = &s->rb;
	const uint8_t *p = direct;
	size_t n = dlen;
	for (;;) {
		if (n) {
			hw_qc_recvbuf_advance(rb, n);
			int fin = rb->final != HW_QC_NONE && rb->off == rb->final && !s->fin_delivered;
			if (fin) s->fin_delivered = 1;
			if (q->cb.stream_data) q->cb.stream_data(q->cb.ud, s->id, p, n, fin);
			if (q->state >= HW_QC_ST_CLOSING) return;
		}
		n = hw_qc_recvbuf_peek(rb, &p);
		if (!n) break;
	}
	if (!s->fin_delivered && rb->final != HW_QC_NONE && rb->off == rb->final) {
		s->fin_delivered = 1;
		if (q->cb.stream_data) q->cb.stream_data(q->cb.ud, s->id, (const uint8_t *)"", 0, 1);
		if (q->state >= HW_QC_ST_CLOSING) return;
	}
	if (s->fin_delivered) {
		hw_qc_recvbuf_clear(rb);
		stream_maybe_free(q, s);
	}
}

// The new bytes a frame ending at end_off adds to the connection's receive window; 0 when it
// fits, -1 (closed FLOW_CONTROL_ERROR) when it does not.
static int stream_rx_account(hw_quic_conn *q, hw_qc_stream *s, uint64_t end_off, uint64_t frame_type) {
	if (end_off > s->rx_max) {
		conn_error(q, HW_QUIC_FLOW_CONTROL_ERROR, frame_type, "stream data past its credit");
		return -1;
	}
	if (end_off > s->rb.highest) {
		uint64_t delta = end_off - s->rb.highest;
		if (q->rx_highest + delta > q->rx_max_data) {
			conn_error(q, HW_QUIC_FLOW_CONTROL_ERROR, frame_type, "stream data past the connection's credit");
			return -1;
		}
		q->rx_highest += delta;
		if (s->rx_stopped) conn_consume(q, delta);
	}
	return 0;
}

typedef struct {
	int ae;         // an ack-eliciting frame
	int nonprobing; // a frame other than PATH_*, NEW_CONNECTION_ID, PADDING
	int challenge;  // a PATH_CHALLENGE (its data in challenge_data)
	uint8_t challenge_data[8];
	const uint8_t *dcid;
	size_t dcid_len;
	// A STREAM or CRYPTO fragment in it could not be held (too many gaps, or no memory): the packet
	// is not acknowledged, so the peer sends its frames again. Every frame is safe to receive twice.
	int refused;
} rx_info;

static void handle_stream(hw_quic_conn *q, const hw_qc_frame *f, rx_info *ri) {
	uint64_t err;
	hw_qc_stream *s = stream_for_peer(q, f->stream_id, &err);
	if (err) {
		conn_error(q, err, f->type, "STREAM");
		return;
	}
	if (!s) return;
	if (!s->has_recv) {
		conn_error(q, HW_QUIC_STREAM_STATE_ERROR, f->type, "STREAM on a send-only stream");
		return;
	}
	if (s->rx_reset || s->fin_delivered) return;
	hw_qc_recvbuf *rb = &s->rb;
	uint64_t end_off = f->offset + f->len;
	if (rb->final != HW_QC_NONE && (end_off > rb->final || (f->fin && end_off != rb->final))) {
		conn_error(q, HW_QUIC_FINAL_SIZE_ERROR, f->type, "final size changed");
		return;
	}
	if (f->fin && end_off < rb->highest) {
		conn_error(q, HW_QUIC_FINAL_SIZE_ERROR, f->type, "final size below data received");
		return;
	}
	if (stream_rx_account(q, s, end_off, f->type) < 0) return;
	if (f->fin) rb->final = end_off;
	if (s->rx_stopped) {
		if (end_off > rb->highest) rb->highest = end_off;
		if (f->fin) {
			s->fin_delivered = 1;
			stream_maybe_free(q, s);
		}
		return;
	}
	const uint8_t *direct;
	size_t dlen;
	if (hw_qc_recvbuf_push(rb, f->offset, f->data, f->len, &direct, &dlen) < 0) {
		// Nothing of it was delivered (only a fragment ahead of the delivered offset is held), and
		// the one at that offset never needs a range, so the stream still advances.
		ri->refused = 1;
		return;
	}
	stream_deliver(q, s, direct, dlen);
}

static void handle_reset_stream(hw_quic_conn *q, const hw_qc_frame *f) {
	uint64_t err;
	hw_qc_stream *s = stream_for_peer(q, f->stream_id, &err);
	if (err) {
		conn_error(q, err, f->type, "RESET_STREAM");
		return;
	}
	if (!s) return;
	if (!s->has_recv) {
		conn_error(q, HW_QUIC_STREAM_STATE_ERROR, f->type, "RESET_STREAM on a send-only stream");
		return;
	}
	hw_qc_recvbuf *rb = &s->rb;
	uint64_t final = f->value;
	if ((rb->final != HW_QC_NONE && final != rb->final) || final < rb->highest) {
		conn_error(q, HW_QUIC_FINAL_SIZE_ERROR, f->type, "RESET_STREAM final size");
		return;
	}
	if (stream_rx_account(q, s, final, f->type) < 0) return;
	rb->highest = final;
	rb->final = final;
	if (s->rx_reset || s->fin_delivered) return;
	s->rx_reset = 1;
	// The application never sees the rest: it counts as consumed now.
	if (!s->rx_stopped) conn_consume(q, final - rb->off);
	hw_qc_recvbuf_clear(rb);
	s->ctl_msd = s->ctl_stop = 0;
	if (q->cb.stream_reset) q->cb.stream_reset(q->cb.ud, s->id, f->error);
	if (q->state >= HW_QC_ST_CLOSING) return;
	stream_maybe_free(q, s);
}

static void handle_stop_sending(hw_quic_conn *q, const hw_qc_frame *f) {
	uint64_t err;
	hw_qc_stream *s = stream_for_peer(q, f->stream_id, &err);
	if (err) {
		conn_error(q, err, f->type, "STOP_SENDING");
		return;
	}
	if (!s) return;
	if (!s->has_send) {
		conn_error(q, HW_QUIC_STREAM_STATE_ERROR, f->type, "STOP_SENDING on a receive-only stream");
		return;
	}
	if (s->tx_reset || hw_qc_sendbuf_done(&s->sb)) return;
	stream_reset_send(q, s, f->error);
	if (q->cb.stream_stop) q->cb.stream_stop(q->cb.ud, s->id, f->error);
}

static void after_tls(hw_quic_conn *q) {
	if (q->state >= HW_QC_ST_CLOSING) return;
	tp_apply(q);
	if (q->state >= HW_QC_ST_CLOSING) return;
	if (!q->handshake_complete && hw_tls_done(q->tls)) {
		q->handshake_complete = 1;
		if (q->is_server) {
			q->handshake_confirmed = 1;
			// The first probe waits a PTO: what follows the handshake (HANDSHAKE_DONE, SETTINGS,
			// the CONNECT's answer) is what the session is waiting for.
			q->pmtu_next = q->now + pto_base(q);
			q->hsd_pending = 1;
			q->hs_discard_pending = 1;
			q->state = HW_QC_ST_ACTIVE;
		}
	}
}

// RFC 9002 6.2.3: a client Initial that carries CRYPTO bytes the server already has is a client
// that has not heard the server's Initial, so the server's flight was lost. It goes again now,
// within the amplification limit, instead of at the PTO: without a round trip measured that is
// a second, and on the edge it made the 3 to 6 s sessions. Twice at most per connection, and only
// for the frame at offset 0: a ClientHello in two Initials (a post-quantum key share is more than
// one datagram) or in several frames is one retransmission, not several.
#define HW_QC_HS_RESENDS 2u

static int space_can_send(const hw_quic_conn *q, int spi);

static void handshake_resend(hw_quic_conn *q) {
	if (q->hs_resends >= HW_QC_HS_RESENDS) return;
	int any = 0;
	for (int spi = HW_QC_SP_INITIAL; spi <= HW_QC_SP_HANDSHAKE; spi++) {
		hw_qc_space *sp = &q->sp[spi];
		if (!space_can_send(q, spi) || sp->crypto_tx.sent <= sp->crypto_tx.base) continue;
		pto_fire(q, spi);
		any = 1;
	}
	if (any) q->hs_resends++;
}

static void handle_crypto(hw_quic_conn *q, int spi, const hw_qc_frame *f, rx_info *ri) {
	hw_qc_space *sp = &q->sp[spi];
	hw_qc_recvbuf *rb = &sp->crypto_rx;
	if (q->is_server && spi == HW_QC_SP_INITIAL && f->len && f->offset + f->len <= rb->off && !q->handshake_complete) {
		if (f->offset == 0) handshake_resend(q);
		return; // nothing in it is new
	}
	if (f->offset + f->len > rb->off + HW_QC_CRYPTO_MAX) {
		conn_error(q, HW_QUIC_CRYPTO_BUFFER_EXCEEDED, f->type, "CRYPTO past the buffer");
		return;
	}
	const uint8_t *p;
	size_t n;
	if (hw_qc_recvbuf_push(rb, f->offset, f->data, f->len, &p, &n) < 0) {
		ri->refused = 1;
		return;
	}
	while (n) {
		hw_qc_recvbuf_advance(rb, n);
		if (hw_tls_input(q->tls, (hw_tls_level)spi, p, n) < 0) {
			uint8_t alert = hw_tls_alert(q->tls);
			conn_error(q, HW_QUIC_CRYPTO_ERROR(alert ? alert : HW_TLS_ALERT_INTERNAL_ERROR), f->type, "TLS");
			return;
		}
		if (sp->discarded) return; // the TLS step discarded this level (cannot happen today)
		n = hw_qc_recvbuf_peek(rb, &p);
	}
	after_tls(q);
}

static void handle_path_response(hw_quic_conn *q, const hw_qc_frame *f) {
	if (q->path_validated) return;
	for (size_t i = 0; i < q->nchallenges; i++) {
		if (memcmp(q->challenges[i], f->data, 8) == 0) {
			q->path_validated = 1;
			q->has_old_peer = 0;
			q->nchallenges = 0;
			q->challenge_pending = 0;
			q->path_deadline = 0;
			return;
		}
	}
}

static void handle_close_frame(hw_quic_conn *q, const hw_qc_frame *f) {
	if (q->state >= HW_QC_ST_CLOSING) return;
	q->state = HW_QC_ST_DRAINING;
	q->close_error = f->error;
	q->close_app = f->type == HW_QC_F_CONNECTION_CLOSE_APP;
	conn_set_reason(q, (const char *)f->data, f->len);
	q->closed_fire = 1;
	q->close_deadline = q->now + 3 * pto_base(q);
}

static void handle_handshake_done(hw_quic_conn *q) {
	if (q->handshake_confirmed) return;
	q->handshake_confirmed = 1;
	q->pmtu_next = q->now + pto_base(q); // as the server's: the session's first packets go first
	q->peer_validated_addr = 1;
	q->state = HW_QC_ST_ACTIVE;
	space_discard(q, HW_QC_SP_INITIAL);
	space_discard(q, HW_QC_SP_HANDSHAKE);
}

// RFC 9000 table 3 (Initial and Handshake carry only these), and the frames only one side may
// send.
static int frame_allowed(const hw_quic_conn *q, int spi, uint64_t type) {
	if (spi != HW_QC_SP_APP) {
		return type == HW_QC_F_PADDING || type == HW_QC_F_PING || type == HW_QC_F_ACK || type == HW_QC_F_CRYPTO ||
		       type == HW_QC_F_CONNECTION_CLOSE;
	}
	if (q->is_server && (type == HW_QC_F_HANDSHAKE_DONE || type == HW_QC_F_NEW_TOKEN)) return 0;
	return 1;
}

static void handle_frame(hw_quic_conn *q, int spi, const hw_qc_frame *f, rx_info *ri) {
	uint64_t err;
	hw_qc_stream *s;
	switch (f->type) {
	case HW_QC_F_PADDING:
	case HW_QC_F_PING:
	case HW_QC_F_NEW_TOKEN:
	case HW_QC_F_DATA_BLOCKED:
	case HW_QC_F_STREAMS_BLOCKED_BIDI:
	case HW_QC_F_STREAMS_BLOCKED_UNI:
		break;
	case HW_QC_F_ACK:
		on_ack(q, spi, f);
		break;
	case HW_QC_F_RESET_STREAM:
		handle_reset_stream(q, f);
		break;
	case HW_QC_F_STOP_SENDING:
		handle_stop_sending(q, f);
		break;
	case HW_QC_F_CRYPTO:
		handle_crypto(q, spi, f, ri);
		break;
	case HW_QC_F_STREAM:
		handle_stream(q, f, ri);
		break;
	case HW_QC_F_MAX_DATA:
		if (f->value > q->tx_max_data) {
			q->tx_max_data = f->value;
			q->writable_check = 1;
		}
		break;
	case HW_QC_F_MAX_STREAM_DATA:
		s = stream_for_peer(q, f->stream_id, &err);
		if (err) {
			conn_error(q, err, f->type, "MAX_STREAM_DATA");
			break;
		}
		if (!s) break;
		if (!s->has_send) {
			conn_error(q, HW_QUIC_STREAM_STATE_ERROR, f->type, "MAX_STREAM_DATA on a receive-only stream");
			break;
		}
		if (f->value > s->tx_max) {
			s->tx_max = f->value;
			q->writable_check = 1;
		}
		break;
	case HW_QC_F_MAX_STREAMS_BIDI:
	case HW_QC_F_MAX_STREAMS_UNI: {
		int t = f->type == HW_QC_F_MAX_STREAMS_UNI;
		if (f->value > q->peer_max_streams[t]) q->peer_max_streams[t] = f->value;
		break;
	}
	case HW_QC_F_STREAM_DATA_BLOCKED:
		s = stream_for_peer(q, f->stream_id, &err);
		if (err) {
			conn_error(q, err, f->type, "STREAM_DATA_BLOCKED");
		} else if (s && !s->has_recv) {
			conn_error(q, HW_QUIC_STREAM_STATE_ERROR, f->type, "STREAM_DATA_BLOCKED on a send-only stream");
		}
		break;
	case HW_QC_F_NEW_CONNECTION_ID:
		handle_new_cid(q, f);
		break;
	case HW_QC_F_RETIRE_CONNECTION_ID:
		handle_retire_cid(q, f, ri->dcid, ri->dcid_len);
		break;
	case HW_QC_F_PATH_CHALLENGE:
		ri->challenge = 1;
		memcpy(ri->challenge_data, f->data, 8);
		break;
	case HW_QC_F_PATH_RESPONSE:
		handle_path_response(q, f);
		break;
	case HW_QC_F_CONNECTION_CLOSE:
	case HW_QC_F_CONNECTION_CLOSE_APP:
		handle_close_frame(q, f);
		break;
	case HW_QC_F_HANDSHAKE_DONE:
		handle_handshake_done(q);
		break;
	case HW_QC_F_DATAGRAM:
		if (!q->cfg.max_datagram_frame_size || f->len + 1 > q->cfg.max_datagram_frame_size) {
			conn_error(q, HW_QUIC_PROTOCOL_VIOLATION, f->type, "DATAGRAM not accepted");
			break;
		}
		if (q->cb.datagram) q->cb.datagram(q->cb.ud, f->data, f->len);
		break;
	default:
		break;
	}
}

static void frames_process(hw_quic_conn *q, int spi, const uint8_t *p, size_t len, rx_info *ri) {
	const uint8_t *end = p + len;
	if (!len) {
		conn_error(q, HW_QUIC_PROTOCOL_VIOLATION, 0, "packet without frames");
		return;
	}
	while (p < end) {
		hw_qc_frame f;
		size_t n = hw_qc_frame_parse(p, end, &f);
		if (!n) {
			conn_error(q, HW_QUIC_FRAME_ENCODING_ERROR, f.type == UINT64_MAX ? 0 : f.type, "frame encoding");
			return;
		}
		p += n;
		if (!frame_allowed(q, spi, f.type)) {
			conn_error(q, HW_QUIC_PROTOCOL_VIOLATION, f.type, "frame not allowed here");
			return;
		}
		if (f.type != HW_QC_F_PADDING && f.type != HW_QC_F_ACK && f.type != HW_QC_F_CONNECTION_CLOSE &&
		    f.type != HW_QC_F_CONNECTION_CLOSE_APP) {
			ri->ae = 1;
		}
		if (f.type != HW_QC_F_PADDING && f.type != HW_QC_F_PATH_CHALLENGE && f.type != HW_QC_F_PATH_RESPONSE &&
		    f.type != HW_QC_F_NEW_CONNECTION_ID) {
			ri->nonprobing = 1;
		}
		handle_frame(q, spi, &f, ri);
		if (q->state >= HW_QC_ST_CLOSING) return;
	}
}

// ---- Receiving: packets ----------------------------------------------------------------------

static void handle_retry(hw_quic_conn *q, const hw_qw_hdr *h, const uint8_t *pkt, size_t len) {
	if (q->is_server || q->retried || q->got_server_scid) return;
	if (!h->token_len || !cid_ours(q, h->dcid, h->dcid_len)) return;
	if (cid_eq(h->scid, h->scid_len, q->odcid, q->odcid_len)) return;
	if (hw_qw_retry_verify(q->odcid, q->odcid_len, pkt, len) != 1) return;
	uint8_t *tok = malloc(h->token_len);
	if (!tok) return;
	memcpy(tok, h->token, h->token_len);
	free(q->token);
	q->token = tok;
	q->token_len = h->token_len;
	q->retried = 1;
	q->retry_scid_len = h->scid_len;
	memcpy(q->retry_scid, h->scid, h->scid_len);
	q->peers[0].len = h->scid_len;
	memcpy(q->peers[0].cid, h->scid, h->scid_len);
	hw_qc_space *sp = &q->sp[HW_QC_SP_INITIAL];
	hw_qw_keys client, server;
	hw_qw_initial_keys(h->scid, h->scid_len, &client, &server);
	sp->tx = client;
	sp->rx = server;
	hw_qw_keys_clear(&client);
	hw_qw_keys_clear(&server);
	// Everything sent so far went nowhere: send it again under the new keys.
	space_forget_flight(q, sp);
	if (sp->crypto_tx.sent) hw_qc_sendbuf_lost(&sp->crypto_tx, 0, (size_t)sp->crypto_tx.sent, 0);
}

static void handle_version_negotiation(hw_quic_conn *q, const hw_qw_hdr *h, const uint8_t *pkt, size_t len) {
	if (q->is_server || q->got_server_scid || q->retried) return;
	if (!cid_ours(q, h->dcid, h->dcid_len)) return;
	size_t off = 7 + (size_t)h->dcid_len + h->scid_len;
	if (off >= len) return;
	for (; off + 4 <= len; off += 4) {
		uint32_t v = (uint32_t)pkt[off] << 24 | (uint32_t)pkt[off + 1] << 16 | (uint32_t)pkt[off + 2] << 8 |
		             pkt[off + 3];
		if (v == HW_QUIC_VERSION_1) return; // must be ignored (RFC 9000 6.2)
	}
	conn_silent(q, "version negotiation");
}

// 1-RTT: choose the key phase by the (still protected) key phase bit, then open with the
// same mask (one header-protection key serves every phase).
static int open_short(hw_quic_conn *q, uint8_t *pkt, size_t plen, size_t pn_offset, uint64_t *pn, uint8_t **payload,
                      size_t *payload_len, int *which) {
	hw_qc_space *sp = &q->sp[HW_QC_SP_APP];
	if (plen < pn_offset + 20) return -1;
	uint8_t mask[5];
	if (hw_qw_hp_mask(&sp->rx, pkt + pn_offset + 4, mask) < 0) return -1;
	uint8_t first = pkt[0] ^ (mask[0] & 0x1f);
	int phase = (first >> 2) & 1;
	size_t pnl = (size_t)(first & 3) + 1;
	uint64_t trunc = 0;
	for (size_t i = 0; i < pnl; i++) trunc = (trunc << 8) | (uint8_t)(pkt[pn_offset + i] ^ mask[1 + i]);
	uint64_t guess = hw_qw_pn_decode(sp->largest_rx, trunc, pnl);
	const hw_qw_keys *k = &sp->rx;
	*which = 0;
	if (phase != q->rx_phase) {
		if (q->has_rx_prev && guess < q->rx_phase_first_pn) {
			k = &q->rx_prev;
			*which = 1;
		} else {
			k = &q->rx_next;
			*which = 2;
		}
	}
	int kp;
	return hw_qw_unprotect_masked(k, mask, pkt, plen, pn_offset, sp->largest_rx, pn, payload, payload_len, &kp);
}

static void rx_phase_advance(hw_quic_conn *q, uint64_t pn) {
	hw_qc_space *sp = &q->sp[HW_QC_SP_APP];
	q->rx_prev = sp->rx;
	q->has_rx_prev = 1;
	sp->rx = q->rx_next;
	hw_qw_keys_update(&q->rx_next, &sp->rx);
	q->rx_phase ^= 1;
	q->rx_phase_first_pn = pn;
	q->rx_prev_discard = q->now + 3 * pto_base(q);
	if (q->tx_phase != q->rx_phase) {
		// The peer started it: answer with ours (RFC 9001 6.2).
		hw_qw_keys next;
		hw_qw_keys_update(&next, &sp->tx);
		sp->tx = next;
		hw_qw_keys_clear(&next);
		q->tx_phase = q->rx_phase;
		q->tx_phase_first_pn = sp->ring.next;
		q->tx_phase_acked = 0;
		q->key_updates++;
	}
}

// One packet of a datagram. Returns 1 when it decrypted (duplicates too), 0 when dropped.
static int packet_input(hw_quic_conn *q, const hw_qw_hdr *h, uint8_t *pkt, size_t plen, size_t dgram_len, int *migrate,
                        rx_info *ri_out) {
	if (h->type != HW_QW_SHORT && h->version != HW_QUIC_VERSION_1) {
		if (h->version == 0) handle_version_negotiation(q, h, pkt, plen);
		return 0;
	}
	if (h->type == HW_QW_RETRY) {
		handle_retry(q, h, pkt, plen);
		return 0;
	}
	if (h->type == HW_QW_0RTT) return 0;
	int ok_dcid = cid_ours(q, h->dcid, h->dcid_len);
	if (!ok_dcid && q->is_server && h->type != HW_QW_SHORT) {
		ok_dcid = cid_eq(h->dcid, h->dcid_len, q->client_dcid, q->client_dcid_len);
	}
	if (!ok_dcid) return 0;
	int spi = h->type == HW_QW_INITIAL     ? HW_QC_SP_INITIAL
	          : h->type == HW_QW_HANDSHAKE ? HW_QC_SP_HANDSHAKE
	                                       : HW_QC_SP_APP;
	hw_qc_space *sp = &q->sp[spi];
	if (!sp->has_rx || sp->discarded) return 0;
	if (spi == HW_QC_SP_APP && q->is_server && !q->handshake_complete) return 0;
	if (spi == HW_QC_SP_INITIAL && q->is_server && dgram_len < HW_QUIC_MIN_DGRAM) return 0;
	if (!q->is_server && spi != HW_QC_SP_APP && q->got_server_scid &&
	    !cid_eq(h->scid, h->scid_len, q->peer_scid, q->peer_scid_len)) {
		return 0;
	}
	// Too short for a header-protection sample: not a packet, rather than one that failed.
	if (h->pn_offset > plen || plen - h->pn_offset < 4 + 16) return 0;
	uint64_t pn;
	uint8_t *payload;
	size_t payload_len;
	int which = 0, kp;
	int r = spi == HW_QC_SP_APP
	            ? open_short(q, pkt, plen, h->pn_offset, &pn, &payload, &payload_len, &which)
	            : hw_qw_unprotect(&sp->rx, pkt, plen, h->pn_offset, sp->largest_rx, &pn, &payload, &payload_len, &kp);
	if (r < 0) {
		if (++q->auth_failures > HW_QC_AEAD_INTEGRITY_LIMIT) {
			conn_error(q, HW_QUIC_AEAD_LIMIT_REACHED, 0, "AEAD integrity limit");
		}
		return 0;
	}
	if (pkt[0] & (h->type == HW_QW_SHORT ? 0x18 : 0x0c)) {
		conn_error(q, HW_QUIC_PROTOCOL_VIOLATION, 0, "reserved header bits");
		return 1;
	}
	if (which == 2) rx_phase_advance(q, pn);
	if (hw_qc_ranges_contains(&sp->seen, pn)) return 1;
	if (!q->is_server && !q->got_server_scid && spi == HW_QC_SP_INITIAL) {
		q->got_server_scid = 1;
		q->peer_scid_len = h->scid_len;
		memcpy(q->peer_scid, h->scid, h->scid_len);
		q->peers[0].len = h->scid_len;
		memcpy(q->peers[0].cid, h->scid, h->scid_len);
	}
	if (q->is_server && spi == HW_QC_SP_HANDSHAKE) {
		// RFC 9001 4.9.1, RFC 9000 8.1: a Handshake packet validates the client's address.
		space_discard(q, HW_QC_SP_INITIAL);
		q->path_validated = 1;
	}
	rx_info ri;
	memset(&ri, 0, sizeof(ri));
	ri.dcid = h->dcid;
	ri.dcid_len = h->dcid_len;
	frames_process(q, spi, payload, payload_len, &ri);
	if (q->state >= HW_QC_ST_CLOSING) return 1;
	if (sp->discarded) return 1; // HANDSHAKE_DONE discarded this very space
	if (ri.refused) {
		// Not acknowledged, as if lost: the peer declares it so and sends its frames again.
		q->rx_refused++;
		return 1;
	}
	hw_qc_ranges_add(&sp->recv, pn, pn + 1);
	hw_qc_ranges_add(&sp->seen, pn, pn + 1);
	int64_t prev = sp->largest_rx;
	if ((int64_t)pn > sp->largest_rx) {
		sp->largest_rx = (int64_t)pn;
		sp->largest_rx_time = q->now;
		if (prev >= 0 && pn > (uint64_t)prev + 1) sp->ack_now = 1; // a gap
		if (spi == HW_QC_SP_APP && ri.nonprobing) *migrate = 1;
	} else {
		sp->ack_now = 1; // out of order
	}
	sp->ack_new = 1;
	if (ri.ae) {
		sp->ae_unacked++;
		if (spi != HW_QC_SP_APP || sp->ae_unacked >= 2) sp->ack_now = 1;
		if (sp->ack_deadline == HW_QC_NONE) sp->ack_deadline = q->now + HW_QC_MAX_ACK_DELAY_US;
	}
	q->last_activity = q->now;
	q->idle_restart = 1;
	q->stats.packets_received++;
	if (ri.challenge) {
		ri_out->challenge = 1;
		memcpy(ri_out->challenge_data, ri.challenge_data, 8);
	}
	return 1;
}

static int stateless_reset_match(const hw_quic_conn *q, const uint8_t *d, size_t len) {
	if (len < 21 || (d[0] & 0x80)) return 0;
	const uint8_t *tail = d + len - HW_QUIC_RESET_LEN;
	int hit = 0;
	for (size_t i = 0; i < HW_QC_PEER_CIDS; i++) {
		if (q->peers[i].used && q->peers[i].has_token) hit |= hw_ct_equal(tail, q->peers[i].token, HW_QUIC_RESET_LEN);
	}
	return hit;
}

// A new path's MTU is unknown: back to the floor, and the search starts over.
static void pmtu_restart(hw_quic_conn *q) {
	q->mds = HW_QUIC_MIN_DGRAM;
	q->pmtu_bad = 0;
	q->pmtu_probe = 0;
	q->pmtu_deadline = 0;
	q->pmtu_next = 0;
	q->pmtu_tries = 0;
	pmtu_bh_clear(q);
}

static void path_migrate(hw_quic_conn *q, const struct sockaddr *from, socklen_t from_len, size_t dgram_len) {
	int ip_changed = !addr_eq(from, &q->peer, 1);
	if (q->path_validated) {
		q->old_peer = q->peer;
		q->old_peer_len = q->peer_len;
		q->has_old_peer = 1;
	}
	addr_set(&q->peer, &q->peer_len, from, from_len);
	q->path_validated = 0;
	q->amp_rx = dgram_len;
	q->amp_tx = 0;
	if (ip_changed) {
		// A new path: its own window, RTT and reordering. The epoch goes on, so that packets
		// the old path's periods declared lost are never taken for the new one's.
		uint16_t epoch = q->cc.epoch;
		pmtu_restart(q);
		cc_init(q);
		q->cc.epoch = (uint16_t)(epoch + 1);
		hw_qc_rtt_init(&q->rtt);
		q->pkt_threshold = HW_QC_PACKET_THRESHOLD;
		q->time_shift = HW_QC_TIME_SHIFT;
	}
	q->nchallenges = 0;
	if (rnd(q->challenges[0], 8) == 0) q->nchallenges = 1;
	q->challenge_pending = 1;
	q->challenge_next = q->now + pto_base(q);
	q->path_deadline = q->now + 3 * HW_MAX(pto_base(q), (uint64_t)PTO_INITIAL_US);
}

static void fire_cid_initial(hw_quic_conn *q) {
	if (q->cid_fired) return;
	q->cid_fired = 1;
	if (q->cb.cid) q->cb.cid(q->cb.ud, q->ours[0].cid, 0);
}

static void notify_writable(hw_quic_conn *q) {
	if (!q->writable_check) return;
	q->writable_check = 0;
	hw_qc_stream *list = q->blk_head;
	q->blk_head = NULL;
	while (list) {
		hw_qc_stream *s = list;
		list = s->blk_next;
		s->in_blk = 0;
		s->blk_next = NULL;
		if (s->freed || s->tx_reset || !s->has_send || s->sb.fin) continue;
		if (q->state >= HW_QC_ST_CLOSING) continue;
		int why;
		if (stream_write_room(q, s, &why) > 0) {
			if (q->cb.stream_writable) q->cb.stream_writable(q->cb.ud, s->id);
		} else {
			blk_add(q, s);
		}
	}
}

// The end of every entry point that may have run callbacks or may run them now.
static void after_events(hw_quic_conn *q) {
	if (q->handshake_confirmed && !q->established_fired && q->state < HW_QC_ST_CLOSING) {
		q->established_fired = 1;
		if (q->cb.established) q->cb.established(q->cb.ud);
	}
	if (q->state < HW_QC_ST_CLOSING) notify_writable(q);
	if (q->closed_fire && !q->closed_fired) {
		q->closed_fired = 1;
		if (q->cb.closed) q->cb.closed(q->cb.ud, q->close_error, q->close_app, q->close_reason);
	}
	conn_gc(q);
}

int hw_quic_input(hw_quic_conn *q, uint8_t *dgram, size_t len, const struct sockaddr *from, socklen_t from_len,
                  uint64_t now_ms) {
	return hw_quic_input_us(q, dgram, len, from, from_len, now_ms * 1000);
}

int hw_quic_input_us(hw_quic_conn *q, uint8_t *dgram, size_t len, const struct sockaddr *from, socklen_t from_len,
                     uint64_t now_us) {
	int any = 0, migrate = 0, new_addr = 0;
	rx_info ri;
	memset(&ri, 0, sizeof(ri));
	q->now = now_us;
	fire_cid_initial(q);
	if (q->state >= HW_QC_ST_DRAINING) goto done;
	if (q->state == HW_QC_ST_CLOSING) {
		// Answer with CONNECTION_CLOSE again, less and less often, within 3x of what came.
		if (q->is_server && !q->path_validated && from && addr_eq(from, &q->peer, 0)) q->amp_rx += len;
		q->closing_rx++;
		if ((q->closing_rx & (q->closing_rx - 1)) == 0) q->close_pending = 1;
		goto done;
	}
	new_addr = q->is_server && from && !addr_eq(from, &q->peer, 0);
	if (new_addr && !q->handshake_confirmed) goto done;
	q->stats.bytes_received += len;
	for (size_t off = 0; off < len && q->state < HW_QC_ST_CLOSING;) {
		hw_qw_hdr h;
		if (hw_qw_parse(dgram + off, len - off, HW_QUIC_CID_LEN, &h) < 0) break;
		size_t plen = h.packet_len;
		if (!plen || plen > len - off) break;
		any |= packet_input(q, &h, dgram + off, plen, len, &migrate, &ri);
		off += plen;
	}
	if (!any) {
		if (q->state < HW_QC_ST_CLOSING && stateless_reset_match(q, dgram, len)) conn_silent(q, "stateless reset");
		goto done;
	}
	// The 3x budget counts this datagram even when it closed the connection: the
	// CONNECTION_CLOSE that answers it is sent within it.
	if (!new_addr && !q->path_validated) q->amp_rx += len;
	if (q->state >= HW_QC_ST_CLOSING) goto done;
	if (new_addr) {
		if (migrate) {
			path_migrate(q, from, from_len, len);
		} else if (ri.challenge) {
			// A probe from another address: answer there, within 3x of what it sent.
			addr_set(&q->probe_addr, &q->probe_len, from, from_len);
			memcpy(q->probe_data, ri.challenge_data, 8);
			q->probe_pending = 1;
			q->probe_amp = 3 * len;
			ri.challenge = 0;
		}
	}
	if (ri.challenge) {
		memcpy(q->response, ri.challenge_data, 8);
		q->response_pending = 1;
	}
done:
	after_events(q);
	return 0;
}

// ---- Sending -------------------------------------------------------------------------------------

typedef struct {
	int spi;
	uint8_t *start;
	size_t hdr_len; // through the packet number
	size_t pn_len;
	uint64_t pn;
	size_t payload_len;
	size_t room; // payload bytes still free (the tag is reserved apart)
	int long_hdr;
	int ae, padded, challenge;
	uint64_t frame0;
	uint16_t nframes;
} pkt_build;

static void rec_frame(hw_quic_conn *q, pkt_build *b, uint8_t type, uint64_t id, uint64_t off, size_t len, int fin) {
	hw_qc_frec r = {.type = type, .fin = (uint8_t)fin, .len = (uint16_t)len, .id = id, .off = off};
	hw_qc_ring_add_frame(&q->sp[b->spi].ring, &r);
	b->nframes++;
}

static int frames_full(const pkt_build *b) {
	return b->nframes >= HW_QC_PKT_FRAMES_MAX - 1;
}

static uint8_t *pkt_cur(pkt_build *b) {
	return b->start + b->hdr_len + b->payload_len;
}

static void pkt_put(pkt_build *b, size_t n, int ae) {
	b->payload_len += n;
	b->room -= n;
	if (ae) b->ae = 1;
}

static size_t pkt_header(hw_quic_conn *q, int spi, uint8_t *p, size_t room, pkt_build *b) {
	hw_qc_space *sp = &q->sp[spi];
	const hw_qc_peer_cid *d = peer_cid_cur(q);
	uint64_t pn = sp->ring.next;
	size_t pn_len = hw_qw_pn_len(pn, sp->largest_acked);
	size_t need;
	if (spi == HW_QC_SP_APP) {
		need = 1 + d->len + pn_len;
	} else {
		need = 7 + d->len + HW_QUIC_CID_LEN + LONG_HDR_LEN_FIELD + pn_len;
		if (spi == HW_QC_SP_INITIAL) need += hw_qc_vlen(q->token_len) + q->token_len;
	}
	if (need + HW_AEAD_TAG + 8 > room) return 0;
	if (spi == HW_QC_SP_APP && pn - q->tx_phase_first_pn >= q->key_update_at) {
		// The key has protected its share (AES-128-GCM's confidentiality limit): a new one, and
		// none past the limit while the update waits for this phase's acknowledgement.
		if (hw_qc_key_update(q) != 0 && pn - q->tx_phase_first_pn >= 2 * q->key_update_at) return 0;
	}
	uint8_t *h = p;
	if (spi == HW_QC_SP_APP) {
		*h++ = (uint8_t)(0x40 | (q->tx_phase << 2));
		memcpy(h, d->cid, d->len);
		h += d->len;
	} else {
		*h++ = (uint8_t)(0xc0 | ((spi == HW_QC_SP_INITIAL ? HW_QW_INITIAL : HW_QW_HANDSHAKE) << 4));
		*h++ = 0;
		*h++ = 0;
		*h++ = 0;
		*h++ = 1;
		*h++ = d->len;
		memcpy(h, d->cid, d->len);
		h += d->len;
		*h++ = HW_QUIC_CID_LEN;
		memcpy(h, q->ours[0].cid, HW_QUIC_CID_LEN);
		h += HW_QUIC_CID_LEN;
		if (spi == HW_QC_SP_INITIAL) {
			h = hw_qc_vput(h, q->token_len);
			if (q->token_len) memcpy(h, q->token, q->token_len);
			h += q->token_len;
		}
		h += LONG_HDR_LEN_FIELD; // written once the payload is known
	}
	memset(h, 0, pn_len);
	h += pn_len;
	memset(b, 0, sizeof(*b));
	b->spi = spi;
	b->start = p;
	b->hdr_len = (size_t)(h - p);
	b->pn_len = pn_len;
	b->pn = pn;
	b->long_hdr = spi != HW_QC_SP_APP;
	b->room = room - b->hdr_len - HW_AEAD_TAG;
	b->frame0 = sp->ring.fhead;
	return b->hdr_len;
}

static int ack_wanted(const hw_qc_space *sp, uint64_t now) {
	if (!sp->ack_new || !sp->recv.n) return 0;
	return sp->ack_now || sp->ae_unacked >= 2 || (sp->ae_unacked && sp->ack_deadline <= now);
}

static int app_ctl_pending(const hw_quic_conn *q) {
	if (q->hsd_pending || q->response_pending || q->challenge_pending || q->ctl_max_data || q->ctl_data_blocked) {
		return 1;
	}
	if (q->ctl_max_streams[0] || q->ctl_max_streams[1] || q->ctl_sb_bidi || q->ctl_sb_uni) return 1;
	if (q->retire_n || q->ctl_head || q->ping_pending) return 1;
	if (q->inject_len && q->inject_spi == HW_QC_SP_APP) return 1;
	for (size_t i = 0; i < HW_QC_OUR_CIDS; i++) {
		if (q->ours[i].active && q->ours[i].ncid_pending) return 1;
	}
	return 0;
}

// Whether a space has anything ack-eliciting to send.
static int space_ae_pending(const hw_quic_conn *q, int spi) {
	const hw_qc_space *sp = &q->sp[spi];
	if (sp->probes) return 1;
	if (hw_qc_sendbuf_pending(&sp->crypto_tx)) return 1;
	if (q->inject_len && q->inject_spi == spi) return 1;
	if (spi != HW_QC_SP_APP) return 0;
	return app_ctl_pending(q) || q->send_cur || q->dq_n;
}

static int space_can_send(const hw_quic_conn *q, int spi) {
	const hw_qc_space *sp = &q->sp[spi];
	if (!sp->has_tx || sp->discarded) return 0;
	if (spi == HW_QC_SP_APP && q->is_server && !q->handshake_complete) return 0;
	return 1;
}

static void put_crypto(hw_quic_conn *q, pkt_build *b) {
	hw_qc_sendbuf *cb = &q->sp[b->spi].crypto_tx;
	while (!frames_full(b)) {
		uint64_t off;
		size_t len;
		int fin;
		if (!hw_qc_sendbuf_next(cb, SIZE_MAX, &off, &len, &fin) || !len) return;
		size_t over = 1 + hw_qc_vlen(off) + 2;
		if (b->room <= over + 16) return;
		size_t max = b->room - over;
		if (len > max) len = max;
		size_t h = hw_qc_put_crypto_header(pkt_cur(b), b->room, off, len);
		if (!h) return;
		pkt_put(b, h, 1);
		hw_qc_sendbuf_copy(cb, off, len, pkt_cur(b));
		pkt_put(b, len, 1);
		hw_qc_sendbuf_sent(cb, off, len, 0);
		rec_frame(q, b, HW_QC_R_CRYPTO, 0, off, len, 0);
	}
}

static void put_ctl_streams(hw_quic_conn *q, pkt_build *b) {
	while (q->ctl_head && !frames_full(b)) {
		hw_qc_stream *s = q->ctl_head;
		size_t n;
		if (s->ctl_reset) {
			n = hw_qc_put_reset_stream(pkt_cur(b), b->room, s->id, s->tx_reset_err, s->tx_reset_final);
			if (!n) return;
			pkt_put(b, n, 1);
			rec_frame(q, b, HW_QC_R_RESET_STREAM, s->id, 0, 0, 0);
			s->ctl_reset = 0;
		}
		if (s->ctl_stop) {
			n = hw_qc_put_pair(pkt_cur(b), b->room, HW_QC_F_STOP_SENDING, s->id, s->stop_err);
			if (!n) return;
			pkt_put(b, n, 1);
			rec_frame(q, b, HW_QC_R_STOP_SENDING, s->id, 0, 0, 0);
			s->ctl_stop = 0;
		}
		if (s->ctl_msd) {
			n = hw_qc_put_pair(pkt_cur(b), b->room, HW_QC_F_MAX_STREAM_DATA, s->id, s->rx_max);
			if (!n) return;
			pkt_put(b, n, 1);
			rec_frame(q, b, HW_QC_R_MAX_STREAM_DATA, s->id, 0, 0, 0);
			s->ctl_msd = 0;
		}
		if (s->ctl_sdb) {
			n = hw_qc_put_pair(pkt_cur(b), b->room, HW_QC_F_STREAM_DATA_BLOCKED, s->id, s->sdb_value);
			if (!n) return;
			pkt_put(b, n, 1);
			s->ctl_sdb = 0;
		}
		q->ctl_head = s->ctl_next;
		if (!q->ctl_head) q->ctl_tail = NULL;
		s->in_ctl = 0;
		s->ctl_next = NULL;
	}
}

// One frame of a fixed shape, when it fits: n is what the writer returned.
static int pkt_took(pkt_build *b, size_t n) {
	if (!n) return 0;
	pkt_put(b, n, 1);
	return 1;
}

// Tests: the injected frames, in the space they were meant for.
static void put_inject(hw_quic_conn *q, pkt_build *b) {
	if (!q->inject_len || q->inject_spi != b->spi || q->inject_len > b->room) return;
	memcpy(pkt_cur(b), q->inject, q->inject_len);
	pkt_put(b, q->inject_len, 1);
	q->inject_len = 0;
}

static void put_app_ctl(hw_quic_conn *q, pkt_build *b) {
	if (q->hsd_pending && b->room >= 1) {
		*pkt_cur(b) = HW_QC_F_HANDSHAKE_DONE;
		pkt_put(b, 1, 1);
		rec_frame(q, b, HW_QC_R_HANDSHAKE_DONE, 0, 0, 0, 0);
		q->hsd_pending = 0;
	}
	if (q->response_pending && pkt_took(b, hw_qc_put_path(pkt_cur(b), b->room, HW_QC_F_PATH_RESPONSE, q->response))) {
		q->response_pending = 0;
	}
	if (q->challenge_pending && q->nchallenges &&
	    pkt_took(b, hw_qc_put_path(pkt_cur(b), b->room, HW_QC_F_PATH_CHALLENGE, q->challenges[q->nchallenges - 1]))) {
		q->challenge_pending = 0;
		b->challenge = 1;
	}
	if (q->ctl_max_data && pkt_took(b, hw_qc_put_simple(pkt_cur(b), b->room, HW_QC_F_MAX_DATA, q->rx_max_data))) {
		rec_frame(q, b, HW_QC_R_MAX_DATA, 0, 0, 0, 0);
		q->ctl_max_data = 0;
	}
	for (int t = 0; t < 2; t++) {
		uint64_t type = t ? HW_QC_F_MAX_STREAMS_UNI : HW_QC_F_MAX_STREAMS_BIDI;
		if (q->ctl_max_streams[t] && pkt_took(b, hw_qc_put_simple(pkt_cur(b), b->room, type, q->rx_max_streams[t]))) {
			rec_frame(q, b, t ? HW_QC_R_MAX_STREAMS_UNI : HW_QC_R_MAX_STREAMS_BIDI, 0, 0, 0, 0);
			q->ctl_max_streams[t] = 0;
		}
	}
	if (q->ctl_data_blocked && pkt_took(b, hw_qc_put_simple(pkt_cur(b), b->room, HW_QC_F_DATA_BLOCKED, q->db_value))) {
		q->ctl_data_blocked = 0;
	}
	if (q->ctl_sb_bidi &&
	    pkt_took(b, hw_qc_put_simple(pkt_cur(b), b->room, HW_QC_F_STREAMS_BLOCKED_BIDI, q->peer_max_streams[0]))) {
		q->ctl_sb_bidi = 0;
	}
	if (q->ctl_sb_uni &&
	    pkt_took(b, hw_qc_put_simple(pkt_cur(b), b->room, HW_QC_F_STREAMS_BLOCKED_UNI, q->peer_max_streams[1]))) {
		q->ctl_sb_uni = 0;
	}
	size_t n;
	for (size_t i = 0; i < HW_QC_OUR_CIDS && !frames_full(b); i++) {
		hw_qc_our_cid *c = &q->ours[i];
		if (!c->active || !c->ncid_pending) continue;
		n = hw_qc_put_new_cid(pkt_cur(b), b->room, c->seq, 0, c->cid, HW_QUIC_CID_LEN, c->token);
		if (!n) break;
		pkt_put(b, n, 1);
		rec_frame(q, b, HW_QC_R_NEW_CID, c->seq, 0, 0, 0);
		c->ncid_pending = 0;
	}
	while (q->retire_n && !frames_full(b)) {
		n = hw_qc_put_simple(pkt_cur(b), b->room, HW_QC_F_RETIRE_CONNECTION_ID, q->retire_q[0]);
		if (!n) break;
		pkt_put(b, n, 1);
		rec_frame(q, b, HW_QC_R_RETIRE_CID, q->retire_q[0], 0, 0, 0);
		memmove(&q->retire_q[0], &q->retire_q[1], (q->retire_n - 1) * sizeof(q->retire_q[0]));
		q->retire_n--;
	}
	put_ctl_streams(q, b);
	put_inject(q, b);
}

static void put_datagrams(hw_quic_conn *q, pkt_build *b) {
	while (q->dq_n && !frames_full(b)) {
		hw_qc_dgram *d = &q->dq[q->dq_head];
		size_t n = hw_qc_put_datagram(pkt_cur(b), b->room, d->data, d->len);
		if (!n) {
			// It may fit an empty packet; one that never can (the path shrank) is dropped.
			if (b->payload_len > 8) return;
		} else {
			pkt_put(b, n, 1);
			q->dgram_frames_sent++;
		}
		free(d->data);
		d->data = NULL;
		q->dq_head = (q->dq_head + 1) % q->dq_cap;
		q->dq_n--;
	}
}

static void put_streams(hw_quic_conn *q, pkt_build *b) {
	while (q->send_cur && !frames_full(b)) {
		hw_qc_stream *s = q->send_cur;
		if (!stream_send_pending(s)) {
			send_list_remove(q, s);
			continue;
		}
		uint64_t off;
		size_t len;
		int fin;
		hw_qc_sendbuf_next(&s->sb, SIZE_MAX, &off, &len, &fin);
		size_t over = 1 + hw_qc_vlen(s->id) + (off ? hw_qc_vlen(off) : 0) + 2;
		if (b->room < over + (len ? 1 : 0)) return;
		size_t max = b->room - over;
		if (len > max) {
			if (max < 32 && b->payload_len > 0) return; // not worth a sliver: next packet
			hw_qc_sendbuf_next(&s->sb, max, &off, &len, &fin);
		}
		size_t h = hw_qc_put_stream_header(pkt_cur(b), b->room, s->id, off, len, fin);
		if (!h) return;
		pkt_put(b, h, 1);
		hw_qc_sendbuf_copy(&s->sb, off, len, pkt_cur(b));
		pkt_put(b, len, 1);
		uint64_t sent_before = s->sb.sent;
		hw_qc_sendbuf_sent(&s->sb, off, len, fin);
		q->tx_unsent -= (size_t)(s->sb.sent - sent_before);
		rec_frame(q, b, HW_QC_R_STREAM, s->id, off, len, fin);
		// Round robin: the next frame is the next stream's.
		q->send_cur = s->send_next;
		if (!stream_send_pending(s)) send_list_remove(q, s);
	}
}

static void put_close(hw_quic_conn *q, pkt_build *b) {
	int app = q->close_app;
	uint64_t err = q->close_error;
	const char *reason = q->close_reason;
	size_t rlen = strlen(reason);
	if (app && b->spi != HW_QC_SP_APP) {
		// An application close cannot be told before 1-RTT (RFC 9000 10.2.3).
		app = 0;
		err = HW_QC_APPLICATION_ERROR;
		rlen = 0;
	}
	size_t n = hw_qc_put_close(pkt_cur(b), b->room, app, err, q->close_frame, reason, rlen);
	if (n) pkt_put(b, n, 0);
}

// Fill one packet of space spi. Returns 1 when it carries frames.
static int build_space(hw_quic_conn *q, int spi, uint8_t *p, size_t room, int allow_ae, pkt_build *b) {
	hw_qc_space *sp = &q->sp[spi];
	int closing = q->state == HW_QC_ST_CLOSING;
	int want_ack = ack_wanted(sp, q->now);
	int ae = !closing && allow_ae && space_ae_pending(q, spi);
	if (closing) {
		if (!q->close_pending) return 0;
	} else if (!want_ack && !ae) {
		return 0;
	}
	if (hw_qc_ring_reserve(&sp->ring, HW_QC_PKT_FRAMES_MAX) < 0) return 0;
	if (!pkt_header(q, spi, p, room, b)) return 0;
	if (closing) {
		put_close(q, b);
		return b->payload_len > 0;
	}
	if (sp->ack_new && sp->recv.n) {
		uint64_t delay = q->now > sp->largest_rx_time ? (q->now - sp->largest_rx_time) >> HW_QC_ACK_DELAY_EXP : 0;
		size_t n = hw_qc_put_ack(pkt_cur(b), b->room, &sp->recv, delay, NULL);
		if (n) {
			pkt_put(b, n, 0);
			rec_frame(q, b, HW_QC_R_ACK, (uint64_t)sp->largest_rx, 0, 0, 0);
			sp->ack_new = 0;
			sp->ack_now = 0;
			sp->ae_unacked = 0;
			sp->ack_deadline = HW_QC_NONE;
		}
	}
	if (ae) {
		put_crypto(q, b);
		if (spi != HW_QC_SP_APP) put_inject(q, b);
		if (spi == HW_QC_SP_APP) {
			put_app_ctl(q, b);
			if (q->dgram_first) {
				put_datagrams(q, b);
				put_streams(q, b);
			} else {
				put_streams(q, b);
				put_datagrams(q, b);
			}
			q->dgram_first ^= 1;
		}
		int ping = sp->probes || (spi == HW_QC_SP_APP && (q->ping_pending || sp->ack_only_run >= HW_QC_ACK_ONLY_PING));
		if (!b->ae && ping && b->room >= 1) {
			// A probe, a keepalive, or ACKs that would never be acknowledged: make it ack-eliciting.
			*pkt_cur(b) = HW_QC_F_PING;
			pkt_put(b, 1, 1);
		}
		if (spi == HW_QC_SP_APP && b->ae) q->ping_pending = 0;
	}
	// Room for the header-protection sample, here rather than in pkt_finish: a packet that is
	// not the datagram's last cannot grow once the next one is written behind it.
	while (b->payload_len && b->payload_len + b->pn_len < 4 && b->room) {
		*pkt_cur(b) = HW_QC_F_PADDING;
		pkt_put(b, 1, 0);
	}
	return b->payload_len > 0;
}

// Finish a packet: pad it to the sample length, write the Length field, seal it, record it.
static size_t pkt_finish(hw_quic_conn *q, pkt_build *b, size_t pad_to_total) {
	size_t total = b->hdr_len + b->payload_len + HW_AEAD_TAG;
	size_t pad = pad_to_total > total ? pad_to_total - total : 0;
	if (pad) {
		memset(pkt_cur(b), 0, pad);
		b->payload_len += pad;
		b->padded = 1;
	}
	if (b->long_hdr) {
		uint64_t v = b->pn_len + b->payload_len + HW_AEAD_TAG;
		uint8_t *lf = b->start + b->hdr_len - b->pn_len - LONG_HDR_LEN_FIELD;
		lf[0] = (uint8_t)(0x40 | (v >> 8));
		lf[1] = (uint8_t)v;
	}
	hw_qc_space *sp = &q->sp[b->spi];
	size_t n = hw_qw_protect(&sp->tx, b->start, b->hdr_len - b->pn_len, b->pn_len, b->pn, b->payload_len);
	if (!n) return 0;
	hw_qc_sent s;
	memset(&s, 0, sizeof(s));
	s.time = q->now;
	s.frame0 = b->frame0;
	s.nframes = b->nframes;
	s.size = (uint16_t)n;
	if (b->ae) s.flags |= HW_QC_SENT_ACK_ELICITING;
	if (b->ae || b->padded) s.flags |= HW_QC_SENT_IN_FLIGHT;
	if (b->spi == HW_QC_SP_APP && q->tx_phase) s.flags |= HW_QC_SENT_PHASE;
	hw_qc_ring_add_packet(&sp->ring, &s);
	if (s.flags & HW_QC_SENT_IN_FLIGHT) {
		hw_qc_sent *rec = hw_qc_ring_get(&sp->ring, b->pn);
		hw_qc_rs_on_sent(&q->cc, rec, q->now);
		hw_qc_cc_on_sent(&q->cc, n);
		if (q->cc.in_flight * 2 < q->cc.cwnd) rec->flags |= HW_QC_SENT_LIMITED;
	}
	if (b->ae) {
		sp->last_ae_time = q->now;
		sp->ae_in_flight++;
		sp->ack_only_run = 0;
		if (sp->probes) sp->probes--;
		hw_qc_pacer_on_sent(&q->cc, n);
		if (q->idle_restart) {
			q->last_activity = q->now;
			q->idle_restart = 0;
		}
	} else {
		sp->ack_only_run++;
	}
	q->stats.packets_sent++;
	return n;
}

// A PATH_RESPONSE to an address that is not the path (a peer probing a new one), alone in a
// datagram padded within 3x of what that address sent.
static size_t output_probe_response(hw_quic_conn *q, uint8_t *out, size_t cap, struct sockaddr_storage *to,
                                    socklen_t *to_len) {
	q->probe_pending = 0;
	if (!space_can_send(q, HW_QC_SP_APP)) return 0;
	hw_qc_space *sp = &q->sp[HW_QC_SP_APP];
	if (hw_qc_ring_reserve(&sp->ring, 1) < 0) return 0;
	size_t room = (size_t)HW_MIN((uint64_t)cap, HW_MIN(q->mds, q->probe_amp));
	pkt_build b;
	if (!pkt_header(q, HW_QC_SP_APP, out, room, &b)) return 0;
	size_t n = hw_qc_put_path(pkt_cur(&b), b.room, HW_QC_F_PATH_RESPONSE, q->probe_data);
	if (!n) return 0;
	pkt_put(&b, n, 0); // never retransmitted and not tracked as in flight on our path
	size_t len = pkt_finish(q, &b, HW_MIN(room, (size_t)HW_QUIC_MIN_DGRAM));
	if (!len) return 0;
	hw_qc_sent *rec = hw_qc_ring_get(&sp->ring, b.pn);
	if (rec->flags & HW_QC_SENT_IN_FLIGHT) {
		hw_qc_cc_remove(&q->cc, rec->size);
		rec->flags &= (uint8_t)~HW_QC_SENT_IN_FLIGHT;
	}
	*to = q->probe_addr;
	*to_len = q->probe_len;
	q->stats.bytes_sent += len;
	return len;
}

// ---- PMTU discovery ------------------------------------------------------------------------------

// The size to probe next, or 0 when the search is over: the ceiling first (most paths carry it),
// then halfway between what passed and what failed.
static uint64_t pmtu_candidate(const hw_quic_conn *q) {
	if (q->mds >= q->pmtu_max) return 0;
	if (!q->pmtu_bad) return q->pmtu_max;
	if (q->pmtu_bad <= q->mds + HW_QC_PMTU_STEP) return 0;
	return (q->mds + q->pmtu_bad) / 2;
}

static void pmtu_result(hw_quic_conn *q, int passed) {
	uint64_t size = q->pmtu_probe;
	q->pmtu_probe = 0;
	q->pmtu_deadline = 0;
	if (passed) {
		if (size > q->mds) {
			q->mds = size;
			q->cc.mds = size;
		}
		q->pmtu_tries = 0;
		q->pmtu_next = q->now;
		return;
	}
	if (++q->pmtu_tries >= HW_QC_PMTU_TRIES) {
		q->pmtu_bad = size;
		q->pmtu_tries = 0;
	}
	// The next one after a round trip: a probe lost to a burst of loss is not a verdict.
	q->pmtu_next = q->now + pto_base(q);
}

static int pmtu_due(const hw_quic_conn *q, size_t cap) {
	if (!q->handshake_confirmed || !q->path_validated || q->state != HW_QC_ST_ACTIVE) return 0;
	if (q->pmtu_probe || q->now < q->pmtu_next) return 0;
	uint64_t size = pmtu_candidate(q);
	return size && size <= cap && space_can_send(q, HW_QC_SP_APP) && hw_qc_cc_can_send(&q->cc);
}

// A PING padded to the candidate size, alone in a datagram. The record keeps neither IN_FLIGHT
// nor ACK_ELICITING: the probe is answered by its own ACK or by pmtu_deadline, never by the
// congestion controller or the PTO.
static size_t output_pmtu_probe(hw_quic_conn *q, uint8_t *out, struct sockaddr_storage *to, socklen_t *to_len) {
	hw_qc_space *sp = &q->sp[HW_QC_SP_APP];
	size_t size = (size_t)pmtu_candidate(q);
	if (hw_qc_ring_reserve(&sp->ring, 1) < 0) return 0;
	pkt_build b;
	if (!pkt_header(q, HW_QC_SP_APP, out, size, &b) || b.room < 1) return 0;
	*pkt_cur(&b) = HW_QC_F_PING;
	pkt_put(&b, 1, 1);
	size_t len = pkt_finish(q, &b, size);
	if (!len) return 0;
	hw_qc_sent *rec = hw_qc_ring_get(&sp->ring, b.pn);
	if (rec->flags & HW_QC_SENT_IN_FLIGHT) hw_qc_cc_remove(&q->cc, rec->size);
	if (rec->flags & HW_QC_SENT_ACK_ELICITING) sp->ae_in_flight--;
	rec->flags = (uint8_t)((rec->flags & ~(HW_QC_SENT_IN_FLIGHT | HW_QC_SENT_ACK_ELICITING)) | HW_QC_SENT_PMTU);
	q->pmtu_probe = len;
	q->pmtu_pn = b.pn;
	q->pmtu_deadline = q->now + 3 * (pto_base(q) + q->peer_max_ack_delay);
	q->stats.bytes_sent += len;
	q->last_sent = q->now;
	*to = q->peer;
	*to_len = q->peer_len;
	return len;
}

size_t hw_quic_output(hw_quic_conn *q, uint8_t *out, size_t cap, struct sockaddr_storage *to, socklen_t *to_len,
                      uint64_t now_ms) {
	return hw_quic_output_us(q, out, cap, to, to_len, now_ms * 1000);
}

size_t hw_quic_output_us(hw_quic_conn *q, uint8_t *out, size_t cap, struct sockaddr_storage *to, socklen_t *to_len,
                         uint64_t now_us) {
	q->now = now_us;
	q->out_alone = 0;
	conn_gc(q);
	if (q->state >= HW_QC_ST_DRAINING) return 0;
	if (q->probe_pending) {
		size_t n = output_probe_response(q, out, cap, to, to_len);
		if (n) return n;
	}
	if (pmtu_due(q, cap)) {
		size_t n = output_pmtu_probe(q, out, to, to_len);
		if (n) {
			q->out_alone = 1;
			return n;
		}
	}
	size_t dmax = (size_t)HW_MIN((uint64_t)cap, q->mds);
	// Probes after a PTO went unanswered go at the base size: if larger packets are what the path
	// drops (black hole detection, pmtu_bh_acked), this one gets through and says so.
	if (q->sp[HW_QC_SP_APP].probes && q->pto_count >= HW_QC_PMTU_BH_PTOS && dmax > HW_QUIC_MIN_DGRAM) {
		dmax = HW_QUIC_MIN_DGRAM;
	}
	if (q->is_server && !q->path_validated) {
		uint64_t left = 3 * q->amp_rx > q->amp_tx ? 3 * q->amp_rx - q->amp_tx : 0;
		if (left < dmax) dmax = (size_t)left;
	}
	if (dmax < 64) return 0;
	// May ack-eliciting packets go? The window, then the pacer; probes go regardless.
	int cc_ok = hw_qc_cc_can_send(&q->cc);
	int pace_ok = 1;
	if (cc_ok) {
		uint64_t t = hw_qc_pacer_next(&q->cc, &q->rtt, q->now);
		if (t > q->now) {
			pace_ok = 0;
			q->pacer_wait = t;
		} else {
			q->pacer_wait = 0;
		}
	} else {
		q->pacer_wait = 0;
	}
	pkt_build pk[HW_QC_SPACES];
	int np = 0, has_initial = 0, initial_ae = 0, has_handshake = 0, challenge = 0;
	size_t pos = 0;
	for (int spi = 0; spi < HW_QC_SPACES; spi++) {
		if (!space_can_send(q, spi)) continue;
		hw_qc_space *sp = &q->sp[spi];
		int allow = sp->probes > 0 || (cc_ok && pace_ok);
		// A server pads every datagram with an ack-eliciting Initial to 1200 bytes, so it holds
		// those back while the amplification limit leaves less.
		if (spi == HW_QC_SP_INITIAL && q->is_server && dmax < HW_QUIC_MIN_DGRAM) allow = 0;
		if (dmax - pos < 64) break;
		if (!build_space(q, spi, out + pos, dmax - pos, allow, &pk[np])) continue;
		pkt_build *b = &pk[np++];
		if (spi == HW_QC_SP_INITIAL) {
			has_initial = 1;
			initial_ae = b->ae;
		}
		if (spi == HW_QC_SP_HANDSHAKE) has_handshake = 1;
		challenge |= b->challenge;
		pos += b->hdr_len + b->payload_len + HW_AEAD_TAG;
	}
	if (!np) {
		if (!(cc_ok && pace_ok)) {
			int pending = 0;
			for (int spi = 0; spi < HW_QC_SPACES; spi++) pending |= space_can_send(q, spi) && space_ae_pending(q, spi);
			if (!pending) q->pacer_wait = 0;
		} else {
			// Room in the window and the pacer, and nothing to send: the application is the limit,
			// unless a stream is waiting for room (blk_head), which is this send buffer or the
			// peer's credit, a limit of the path's kind. Marked app-limited, every sample of a bulk
			// download behind a full buffer was thrown away: BBR never left startup (paced at 2.89x
			// the path, a third of it lost) and its filter went stale.
			q->pacer_wait = 0;
			if (!q->blk_head) hw_qc_cc_app_limited(&q->cc);
		}
		return 0;
	}
	// Padding goes into the last packet of the datagram.
	size_t pad_total = 0;
	if (has_initial && (!q->is_server || initial_ae)) pad_total = HW_QUIC_MIN_DGRAM;
	if (challenge) pad_total = HW_QUIC_MIN_DGRAM;
	if (pad_total > dmax) pad_total = dmax;
	size_t total = 0;
	for (int i = 0; i < np; i++) {
		size_t want = 0;
		if (i == np - 1 && pad_total > pos) want = pad_total - total;
		size_t n = pkt_finish(q, &pk[i], want);
		if (!n) return 0;
		total += n;
	}
	if (!q->is_server && has_handshake) space_discard(q, HW_QC_SP_INITIAL);
	if (q->hs_discard_pending) {
		q->hs_discard_pending = 0;
		space_discard(q, HW_QC_SP_HANDSHAKE);
	}
	if (q->state == HW_QC_ST_CLOSING) q->close_pending = 0;
	if (q->is_server && !q->path_validated) q->amp_tx += total;
	q->stats.bytes_sent += total;
	q->last_sent = q->now;
	if (!peer_validated(q)) q->pto_anchor = q->now;
	*to = q->peer;
	*to_len = q->peer_len;
	return total;
}

// ---- Timers ------------------------------------------------------------------------------------

static uint64_t idle_period(const hw_quic_conn *q) {
	if (!q->idle_ms) return 0;
	return HW_MAX(q->idle_ms * 1000, 3 * pto_base(q));
}

static uint64_t timeout_us(const hw_quic_conn *q) {
	if (q->state == HW_QC_ST_DRAINED) return HW_QC_NONE;
	if (q->closed_fire && !q->closed_fired) return q->now;
	if (q->state >= HW_QC_ST_CLOSING) return q->close_deadline;
	uint64_t t = HW_QC_NONE;
	int spi, is_loss;
	uint64_t lt = loss_timer(q, &spi, &is_loss);
	if (lt < t) t = lt;
	const hw_qc_space *app = &q->sp[HW_QC_SP_APP];
	if (app->ae_unacked && app->ack_deadline != HW_QC_NONE && app->ack_deadline < t) t = app->ack_deadline;
	if (q->pacer_wait && q->pacer_wait < t) t = q->pacer_wait;
	uint64_t idle = idle_period(q);
	if (idle && q->last_activity + idle < t) t = q->last_activity + idle;
	if (q->cfg.keepalive_ms && q->handshake_confirmed) {
		uint64_t k = q->last_sent + q->cfg.keepalive_ms * 1000;
		if (k < t) t = k;
	}
	if (!q->path_validated && q->nchallenges) {
		if (q->challenge_next && q->challenge_next < t) t = q->challenge_next;
		if (q->path_deadline && q->path_deadline < t) t = q->path_deadline;
	}
	if (q->has_rx_prev && q->rx_prev_discard < t) t = q->rx_prev_discard;
	if (q->pmtu_probe && q->pmtu_deadline < t) t = q->pmtu_deadline;
	// A probe that is due now waits for the next output, as data does: a timer for it would fire
	// again and again while the window holds it back.
	if (!q->pmtu_probe && q->pmtu_next > q->now && q->pmtu_next < t && pmtu_candidate(q)) t = q->pmtu_next;
	return t;
}

uint64_t hw_quic_timeout(const hw_quic_conn *q) {
	uint64_t t = timeout_us(q);
	if (t == HW_QC_NONE) return UINT64_MAX;
	return (t + 999) / 1000;
}

uint64_t hw_quic_timeout_us(const hw_quic_conn *q) {
	uint64_t t = timeout_us(q);
	return t == HW_QC_NONE ? UINT64_MAX : t;
}

void hw_quic_on_timeout(hw_quic_conn *q, uint64_t now_ms) {
	hw_quic_on_timeout_us(q, now_ms * 1000);
}

void hw_quic_on_timeout_us(hw_quic_conn *q, uint64_t now_us) {
	q->now = now_us;
	uint64_t now = q->now;
	fire_cid_initial(q);
	if (q->state == HW_QC_ST_DRAINED) goto done;
	if (q->state >= HW_QC_ST_CLOSING) {
		if (now >= q->close_deadline) q->state = HW_QC_ST_DRAINED;
		goto done;
	}
	uint64_t idle = idle_period(q);
	if (idle && now >= q->last_activity + idle) {
		conn_silent(q, "idle timeout");
		goto done;
	}
	on_loss_timeout(q);
	hw_qc_space *app = &q->sp[HW_QC_SP_APP];
	if (app->ae_unacked && app->ack_deadline <= now) {
		// Due now: from here on it waits for output alone, so that a send held back (the
		// amplification limit on a new path) does not make the timer fire again and again.
		app->ack_now = 1;
		app->ack_deadline = HW_QC_NONE;
	}
	if (q->cfg.keepalive_ms && q->handshake_confirmed && now >= q->last_sent + q->cfg.keepalive_ms * 1000) {
		q->ping_pending = 1;
		q->last_sent = now; // one PING per period, even while the window holds it back
	}
	if (!q->path_validated && q->nchallenges) {
		if (q->path_deadline && now >= q->path_deadline) {
			if (q->has_old_peer) {
				q->peer = q->old_peer;
				q->peer_len = q->old_peer_len;
				q->has_old_peer = 0;
				q->path_validated = 1;
				q->nchallenges = 0;
				q->challenge_pending = 0;
				q->path_deadline = 0;
			} else {
				conn_silent(q, "path validation failed");
				goto done;
			}
		} else if (q->challenge_next && now >= q->challenge_next) {
			size_t i = q->nchallenges < HW_QC_CHALLENGES ? q->nchallenges : HW_QC_CHALLENGES - 1;
			if (i == HW_QC_CHALLENGES - 1) memmove(q->challenges[0], q->challenges[1], 8 * (HW_QC_CHALLENGES - 1));
			if (rnd(q->challenges[i], 8) == 0 && q->nchallenges < HW_QC_CHALLENGES) q->nchallenges++;
			q->challenge_pending = 1;
			q->challenge_next = now + 2 * pto_base(q);
		}
	}
	if (q->has_rx_prev && now >= q->rx_prev_discard) {
		hw_qw_keys_clear(&q->rx_prev);
		q->has_rx_prev = 0;
	}
	if (q->pacer_wait && now >= q->pacer_wait) q->pacer_wait = 0;
	if (q->pmtu_probe && now >= q->pmtu_deadline) pmtu_result(q, 0);
done:
	after_events(q);
}

// ---- Garbage --------------------------------------------------------------------------------------

static void stream_free(hw_qc_stream *s) {
	hw_qc_sendbuf_clear(&s->sb);
	hw_qc_recvbuf_clear(&s->rb);
	free(s);
}

static void conn_gc(hw_quic_conn *q) {
	if (!q->free_pending) return;
	q->free_pending = 0;
	// Unlink freed streams from the singly linked lists first.
	hw_qc_stream **pp = &q->ctl_head;
	q->ctl_tail = NULL;
	while (*pp) {
		if ((*pp)->freed) {
			(*pp)->in_ctl = 0;
			*pp = (*pp)->ctl_next;
		} else {
			q->ctl_tail = *pp;
			pp = &(*pp)->ctl_next;
		}
	}
	pp = &q->blk_head;
	while (*pp) {
		if ((*pp)->freed) {
			(*pp)->in_blk = 0;
			*pp = (*pp)->blk_next;
		} else {
			pp = &(*pp)->blk_next;
		}
	}
	int closed[2] = {0, 0};
	hw_qc_stream *s = q->all;
	while (s) {
		hw_qc_stream *next = s->all_next;
		if (s->freed) {
			if (s->all_prev) {
				s->all_prev->all_next = s->all_next;
			} else {
				q->all = s->all_next;
			}
			if (s->all_next) s->all_next->all_prev = s->all_prev;
			send_list_remove(q, s);
			hw_qc_smap_remove(&q->streams, s->id);
			if (!stream_local(q, s->id)) {
				int t = (s->id & 2) ? 1 : 0;
				q->peer_closed[t]++;
				closed[t] = 1;
			}
			stream_free(s);
		}
		s = next;
	}
	for (int t = 0; t < 2; t++) {
		if (closed[t]) grant_streams(q, t);
	}
}

// ---- Construction ----------------------------------------------------------------------------------

static hw_quic_conn *conn_new(const hw_quic_config *cfg, const hw_quic_callbacks *cb, int is_server,
                              const struct sockaddr *peer, socklen_t peer_len, uint64_t now_ms) {
	hw_quic_conn *q = calloc(1, sizeof(*q));
	if (!q) return NULL;
	q->cfg = *cfg;
	q->cfg.is_server = is_server;
	if (!q->cfg.stream_send_max) q->cfg.stream_send_max = DEFAULT_STREAM_SEND_MAX;
	if (!q->cfg.conn_send_max) q->cfg.conn_send_max = DEFAULT_CONN_SEND_MAX;
	if (!q->cfg.datagram_queue_max) q->cfg.datagram_queue_max = DEFAULT_DGRAM_QUEUE;
	if (cb) q->cb = *cb;
	q->is_server = is_server;
	q->key_update_at = UINT64_MAX; // until TLS names the 1-RTT suite
	q->now = now_ms * 1000;
	for (int i = 0; i < HW_QC_SPACES; i++) space_init(&q->sp[i]);
	hw_qw_tp_defaults(&q->peer_tp);
	q->peer_max_ack_delay = HW_QC_MAX_ACK_DELAY_US;
	q->mds = HW_QUIC_MIN_DGRAM;
	q->pmtu_max = HW_QUIC_MAX_DGRAM;
	hw_qc_rtt_init(&q->rtt);
	cc_init(q);
	q->pkt_threshold = HW_QC_PACKET_THRESHOLD;
	q->time_shift = HW_QC_TIME_SHIFT;
	hw_qc_smap_init(&q->streams);
	addr_set(&q->peer, &q->peer_len, peer, peer_len);
	q->rx_max_data = q->cfg.initial_max_data;
	q->rx_max_streams[0] = q->cfg.initial_max_streams_bidi;
	q->rx_max_streams[1] = q->cfg.initial_max_streams_uni;
	q->idle_ms = q->cfg.max_idle_ms;
	q->last_activity = q->now;
	q->last_sent = q->now;
	q->pto_anchor = q->now;
	q->dq_cap = q->cfg.datagram_queue_max;
	q->dq = calloc(q->dq_cap, sizeof(*q->dq));
	if (!q->dq) goto fail;
	if (cid_make(q, &q->ours[0]) < 0) goto fail;
	q->ours[0].active = 1;
	q->ours[0].seq = 0;
	q->our_next_seq = 1;
	q->peers[0].used = 1;
	q->peers[0].seq = 0;
	return q;
fail:
	free(q->dq);
	free(q);
	return NULL;
}

static int conn_tls(hw_quic_conn *q) {
	if (tp_build(q) < 0) return -1;
	hw_tls_config tc = q->cfg.tls;
	tc.is_server = q->is_server;
	tc.transport_params = q->tp_buf;
	tc.transport_params_len = q->tp_len;
	hw_tls_callbacks tcb = {.ud = q, .emit = tls_emit, .secret = tls_secret};
	q->tls = hw_tls_new(&tc, &tcb);
	// The config's pointers were copied by hw_tls_new: none of them is kept.
	memset(&q->cfg.tls, 0, sizeof(q->cfg.tls));
	return q->tls ? 0 : -1;
}

static void initial_keys(hw_quic_conn *q, const uint8_t *dcid, size_t len) {
	hw_qw_keys client, server;
	hw_qw_initial_keys(dcid, len, &client, &server);
	hw_qc_space *sp = &q->sp[HW_QC_SP_INITIAL];
	sp->tx = q->is_server ? server : client;
	sp->rx = q->is_server ? client : server;
	sp->has_tx = sp->has_rx = 1;
	hw_qw_keys_clear(&client);
	hw_qw_keys_clear(&server);
}

hw_quic_conn *hw_quic_accept(const hw_quic_config *cfg, const hw_quic_callbacks *cb, const hw_quic_header *h,
                             const struct sockaddr *peer, socklen_t peer_len, int validated, const uint8_t *odcid,
                             uint8_t odcid_len, uint64_t now_ms) {
	if (!h->long_header || h->dcid_len > 20 || h->scid_len > 20 || (validated && (!odcid || odcid_len > 20))) {
		return NULL;
	}
	hw_quic_conn *q = conn_new(cfg, cb, 1, peer, peer_len, now_ms);
	if (!q) return NULL;
	q->client_dcid_len = h->dcid_len;
	memcpy(q->client_dcid, h->dcid, h->dcid_len);
	if (validated) {
		q->odcid_len = odcid_len;
		memcpy(q->odcid, odcid, odcid_len);
		q->retry_scid_len = h->dcid_len;
		memcpy(q->retry_scid, h->dcid, h->dcid_len);
	} else {
		q->odcid_len = h->dcid_len;
		memcpy(q->odcid, h->dcid, h->dcid_len);
	}
	q->peer_scid_len = h->scid_len;
	memcpy(q->peer_scid, h->scid, h->scid_len);
	q->peers[0].len = h->scid_len;
	memcpy(q->peers[0].cid, h->scid, h->scid_len);
	q->path_validated = (uint8_t)(validated != 0);
	initial_keys(q, h->dcid, h->dcid_len);
	if (conn_tls(q) < 0) {
		hw_quic_free(q);
		return NULL;
	}
	return q;
}

hw_quic_conn *hw_qc_connect_unstarted(const hw_quic_config *cfg, const hw_quic_callbacks *cb,
                                      const struct sockaddr *peer, socklen_t peer_len, uint64_t now_ms) {
	hw_quic_conn *q = conn_new(cfg, cb, 0, peer, peer_len, now_ms);
	if (!q) return NULL;
	q->path_validated = 1;
	q->odcid_len = HW_QUIC_CID_LEN;
	if (rnd(q->odcid, q->odcid_len) < 0) {
		hw_quic_free(q);
		return NULL;
	}
	q->peers[0].len = q->odcid_len;
	memcpy(q->peers[0].cid, q->odcid, q->odcid_len);
	initial_keys(q, q->odcid, q->odcid_len);
	if (conn_tls(q) < 0) {
		hw_quic_free(q);
		return NULL;
	}
	return q;
}

int hw_qc_start(hw_quic_conn *q) {
	return hw_tls_start(q->tls);
}

hw_quic_conn *hw_quic_connect(const hw_quic_config *cfg, const hw_quic_callbacks *cb, const struct sockaddr *peer,
                              socklen_t peer_len, uint64_t now_ms) {
	hw_quic_conn *q = hw_qc_connect_unstarted(cfg, cb, peer, peer_len, now_ms);
	if (q && hw_qc_start(q) < 0) {
		hw_quic_free(q);
		return NULL;
	}
	return q;
}

void hw_quic_free(hw_quic_conn *q) {
	if (!q) return;
	hw_qc_stream *s = q->all;
	while (s) {
		hw_qc_stream *next = s->all_next;
		stream_free(s);
		s = next;
	}
	hw_qc_smap_clear(&q->streams);
	for (int i = 0; i < HW_QC_SPACES; i++) space_free(&q->sp[i]);
	hw_qw_keys_clear(&q->rx_prev);
	hw_qw_keys_clear(&q->rx_next);
	if (q->dq) {
		for (size_t i = 0; i < q->dq_cap; i++) free(q->dq[i].data);
		free(q->dq);
	}
	hw_tls_free(q->tls);
	free(q->token);
	free(q);
}

// ---- Streams API -----------------------------------------------------------------------------------

int64_t hw_quic_stream_open(hw_quic_conn *q, int bidi) {
	if (q->state >= HW_QC_ST_CLOSING || !q->peer_tp_applied) return -1;
	int t = bidi ? 0 : 1;
	uint64_t idx = q->next_local[t];
	if (idx >= q->peer_max_streams[t]) {
		if (t) {
			q->ctl_sb_uni = 1;
		} else {
			q->ctl_sb_bidi = 1;
		}
		return -1;
	}
	uint64_t id = (idx << 2) | (q->is_server ? 1u : 0u) | (bidi ? 0u : 2u);
	if (!stream_new(q, id)) return -1;
	q->next_local[t]++;
	return (int64_t)id;
}

int64_t hw_quic_stream_write(hw_quic_conn *q, uint64_t id, const uint8_t *data, size_t len, int fin) {
	if (q->state >= HW_QC_ST_CLOSING) return -1;
	hw_qc_stream *s = hw_qc_smap_get(&q->streams, id);
	if (!s || s->freed || !s->has_send || s->tx_reset || s->sb.fin) return -1;
	int why;
	uint64_t room = stream_write_room(q, s, &why);
	size_t n = (size_t)HW_MIN((uint64_t)len, room);
	if (n && hw_qc_sendbuf_write(&s->sb, data, n) < 0) n = 0;
	q->tx_data += n;
	q->tx_buffered += n;
	q->tx_unsent += n;
	if (n < len) {
		blk_add(q, s);
		if (why == 1 && room == n) {
			if (s->sdb_value != s->tx_max || !s->ctl_sdb) {
				s->sdb_value = s->tx_max;
				s->ctl_sdb = 1;
				ctl_add(q, s);
			}
		} else if (why == 2 && room == n) {
			q->db_value = q->tx_max_data;
			q->ctl_data_blocked = 1;
		}
	}
	if (fin && n == len) s->sb.fin = 1;
	if (n || (fin && n == len)) send_list_add(q, s);
	return (int64_t)n;
}

void hw_quic_stream_consumed(hw_quic_conn *q, uint64_t id, size_t n) {
	hw_qc_stream *s = hw_qc_smap_get(&q->streams, id);
	uint64_t m = n;
	if (s && s->has_recv && !s->freed) {
		uint64_t room = s->rb.off - s->rx_consumed;
		if (s->rx_reset || s->fin_delivered) {
			room = (s->rb.final != HW_QC_NONE ? s->rb.final : s->rb.off) - s->rx_consumed;
		}
		if (m > room) m = room;
		s->rx_consumed += m;
		grant_stream(q, s);
	}
	if (q->rx_highest - q->rx_consumed < m) m = q->rx_highest - q->rx_consumed;
	q->rx_consumed += m;
	grant_conn(q);
}

void hw_quic_stream_reset(hw_quic_conn *q, uint64_t id, uint64_t app_error) {
	hw_qc_stream *s = hw_qc_smap_get(&q->streams, id);
	if (!s || s->freed || q->state >= HW_QC_ST_CLOSING) return;
	stream_reset_send(q, s, app_error);
}

void hw_quic_stream_stop(hw_quic_conn *q, uint64_t id, uint64_t app_error) {
	hw_qc_stream *s = hw_qc_smap_get(&q->streams, id);
	if (!s || s->freed || !s->has_recv || s->rx_stopped || s->rx_reset || s->fin_delivered) return;
	if (q->state >= HW_QC_ST_CLOSING) return;
	s->rx_stopped = 1;
	s->stop_err = app_error;
	s->ctl_stop = 1;
	s->ctl_msd = 0;
	ctl_add(q, s);
	// Whatever is buffered and still to come will never be read: credit it now.
	uint64_t pending = s->rb.highest - s->rb.off;
	hw_qc_recvbuf_clear(&s->rb);
	s->rb.off = s->rb.highest;
	conn_consume(q, pending);
}

// ---- Datagrams, close, queries -----------------------------------------------------------------------

size_t hw_quic_datagram_max(const hw_quic_conn *q) {
	if (!q->peer_tp_applied || !q->peer_tp.max_datagram_frame_size || !q->cfg.datagram_queue_max) return 0;
	size_t over = 1 + q->peers[q->peer_cur].len + 4 + HW_AEAD_TAG + 1 + 2;
	size_t room = q->mds > over ? (size_t)q->mds - over : 0;
	uint64_t frame = q->peer_tp.max_datagram_frame_size;
	size_t fmax = frame > 3 ? (size_t)HW_MIN(frame - 3, (uint64_t)SIZE_MAX) : 0;
	return HW_MIN(room, fmax);
}

int hw_quic_datagram_send(hw_quic_conn *q, const uint8_t *data, size_t len) {
	if (q->state >= HW_QC_ST_CLOSING || len > hw_quic_datagram_max(q) || q->dq_n >= q->dq_cap) return -1;
	uint8_t *copy = malloc(len ? len : 1);
	if (!copy) return -1;
	if (len) memcpy(copy, data, len);
	hw_qc_dgram *d = &q->dq[(q->dq_head + q->dq_n) % q->dq_cap];
	d->data = copy;
	d->len = len;
	q->dq_n++;
	return 0;
}

void hw_quic_close(hw_quic_conn *q, uint64_t app_error, const char *reason) {
	conn_close_with(q, app_error, 1, 0, reason);
}

size_t hw_quic_queued(const hw_quic_conn *q) {
	return q->tx_buffered;
}

size_t hw_quic_unsent(const hw_quic_conn *q) {
	return q->tx_unsent;
}

size_t hw_quic_stream_unsent(const hw_quic_conn *q, uint64_t id) {
	const hw_qc_stream *s = hw_qc_smap_get(&q->streams, id);
	if (!s || s->freed || !s->has_send || s->tx_reset) return 0;
	return (size_t)(s->sb.end - s->sb.sent);
}

int hw_quic_output_alone(const hw_quic_conn *q) {
	return q->out_alone;
}

int hw_quic_is_drained(const hw_quic_conn *q) {
	return q->state == HW_QC_ST_DRAINED;
}

const char *hw_quic_alpn(const hw_quic_conn *q) {
	return q->tls ? hw_tls_alpn(q->tls) : NULL;
}

const char *hw_quic_server_name(const hw_quic_conn *q) {
	return q->tls ? hw_tls_server_name(q->tls) : NULL;
}

const struct sockaddr *hw_quic_peer(const hw_quic_conn *q, socklen_t *len) {
	if (!q->path_validated && q->has_old_peer) {
		if (len) *len = q->old_peer_len;
		return (const struct sockaddr *)&q->old_peer;
	}
	if (len) *len = q->peer_len;
	return (const struct sockaddr *)&q->peer;
}

void hw_quic_get_stats(const hw_quic_conn *q, hw_quic_stats *out) {
	*out = q->stats;
	out->srtt_us = q->rtt.smoothed;
	out->cwnd = q->cc.cwnd;
	out->mds = q->mds;
	out->ssthresh = q->cc.ssthresh;
	out->congestion_events = q->cc.epoch;
	out->spurious_lost = q->spurious_lost;
	out->bandwidth = q->cc.bbr ? q->cc.b.bw : 0;
	out->pmtu_black_holes = q->pmtu_black_holes;
	out->cipher = q->tls ? hw_tls_cipher(q->tls) : 0;
}
