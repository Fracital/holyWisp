/*
 * The WebTransport listener (docs/webtransport.md): the UDP sockets, one per worker where the
 * kernel can steer datagrams by connection ID (hw_sys_udp_steer, one socket on worker 0
 * elsewhere), and on each worker the QUIC connections it owns. A connection has its hw_wt
 * session on top and, once the CONNECT is admitted, its hw_conn, which from then on is a Wisp
 * connection like a WebSocket one: conn.c's packet dispatch and everything after it are the same.
 *
 * Threads: everything here runs on the loop of the worker that owns the socket, except
 * wt_listener_init (hw_server_new, before the loops run), wt_cert_tick (the maintenance thread,
 * which makes a new self-signed certificate or reads the operator's files again when they have
 * changed, and gives each worker its own copy by a posted task, as warp_publish does) and
 * wt_worker_free (shutdown, after the loops stopped). A worker's sessions, its tables
 * and its sockets are touched by that worker alone; steering is what makes every datagram of a
 * connection arrive there.
 *
 * Re-entrancy: QUIC and hw_wt call back into this file from inside hw_quic_input,
 * hw_quic_on_timeout and hw_wt_pause, and those callbacks reach conn.c, which may close the
 * connection or ask for its output to be written. Nothing here acts on such a request while a
 * call into the stack is under way (s->busy): it marks the session dirty, and session_settle does
 * it once the call has returned, at the end of the socket or timer callback, or from a timer of
 * its own when the request came from elsewhere (a remote's bytes). Only session_settle and
 * shutdown free a session.
 *
 * Address validation comes before cost: until an Initial carries a Retry token or its handshake
 * completes, a source address is a claim, and nothing is charged to its limits. Handshakes in
 * progress are capped per worker and per address and expire after WT_HS_EXPIRY_MS; past
 * webtransport-retry-threshold (or the address's share) a new Initial gets a Retry.
 */
#include "holywisp/base64.h"
#include "holywisp/cert.h"
#include "holywisp/ecc.h"
#include "holywisp/hw.h"
#include "holywisp/log.h"
#include "holywisp/net.h"
#include "holywisp/quic.h"
#include "holywisp/sha256.h"
#include "holywisp/sys.h"
#include "holywisp/webtransport.h"

#include "internal.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>

#define WT_RX_SLOT      4096  // receive room per datagram; a longer one is dropped (QUIC's are 1200 to 1500)
#define WT_RX_GRO_SLOTS 16    // receive slots with GRO, HW_SYS_GRO_SLOT each: a slot is up to 45 datagrams
#define WT_RX_ROUNDS    8     // receive batches per readiness event, so one busy socket cannot hold the loop
#define WT_HS_EXPIRY_MS 10000 // a handshake not complete by then is dropped
#define WT_HS_PER_ADDR  16    // handshakes in progress per source address, validated and not counted apart
#define WT_TOKEN_AGE_MS 30000 // how long a Retry token is good for
#define WT_REFUSE_MS    2000  // a refused CONNECT's answer gets this long to be delivered before the close
#define WT_CLOSE_MS     3000  // after the server's close capsule, this long for the client's answer, then QUIC goes
#define WT_KEEPALIVE_MS 20000 // a PING after this long without sending: divide's conntrack keeps a flow 30 s
#define WT_CERT_LIFE_S  (13 * 86400)
#define WT_CERT_RENEW_S (6 * 86400)
#define WT_CERT_EARLY_S 3600 // valid from an hour ago, for clocks that are a little behind
#define WT_CERT_CN      "holywisp"
#define WT_PEM_MAX      (256 * 1024)
#define WT_WHY_LEN      1200 // why a pair did not load: both paths (512 each) and what is wrong
#define WT_KEY_HEX      41   // hex of a CID of up to 20 bytes, NUL included
// The UDP socket buffers unless socket-buffer-size says otherwise. A QUIC flight is many datagrams
// at once, and with GRO one queued read is up to 64 KiB: measured on loopback, the kernel's
// default (net.core.rmem_max 212992) dropped bursts and held one session at 230 MiB/s, 4 MiB
// dropped nothing.
#define WT_SOCKET_BUFFER (4 * 1024 * 1024)

struct wt_session {
	wt_worker *ww;
	hw_quic_conn *q;
	hw_wt *wt;
	hw_conn *c; // NULL until the CONNECT is admitted, and again once the connection has gone
	struct wt_session *prev, *next;
	struct wt_session *dprev, *dnext; // the worker's dirty list
	int dirty;
	int busy; // a call into QUIC or hw_wt is under way: callbacks only record what to do
	hw_timer *timer;
	uint64_t timer_at;
	uint64_t created_ms;
	int established;
	int hs_counted;   // counts toward the worker's and the address's handshakes in progress
	int hs_validated; // ... as a validated one
	int counted;      // counts toward the server's active sessions
	int opened;       // conn_wt_open has run
	int refused;      // the CONNECT was answered with an error: close once that is delivered
	uint64_t refuse_at;
	int quic_closing; // hw_quic_close has been called, or the connection closed by itself
	int close_pending;
	uint32_t close_code;
	// After hw_wt_close the client answers with its FIN, and hw_wt closes QUIC then. One that never
	// answers and keeps the connection busy (the idle timeout never comes) is closed at this time.
	uint64_t close_by;
	// The client's Wisp stream, once hw_wt has taken it as such (-1 until then), and whether the
	// client has ended it: with nothing more to come on it, the session has no more use.
	int64_t wisp_id;
	int64_t connect_id; // the CONNECT's stream, which is never the Wisp stream
	int64_t in_stream;  // the stream q_stream_data is handing hw_wt, -1 outside it
	int wisp_ended;
	int pause_want, paused;
	size_t last_queued; // hw_wt_queued at the last settle, to tell the sweep that the client reads
	char ip[HW_IP_STR_LEN];
	char odcid_key[WT_KEY_HEX]; // the client's first DCID, which finds this until it uses ours; "" once gone
	uint8_t (*cids)[HW_QUIC_CID_LEN];
	size_t ncids, cids_cap;
	char protocol[256]; // the wt-protocol answer: the first protocol the client offered
};

struct wt_worker {
	hw_worker *w;
	int fd;       // -1: this worker has no UDP socket
	hw_smap cids; // hex(cid) -> wt_session: the CIDs issued, and each handshake's client-chosen DCID
	// Source address -> handshakes in progress from it: the low 16 bits unvalidated ones, the rest
	// validated ones.
	hw_smap hs_addr;
	wt_session *sessions;
	wt_session *dirty;
	hw_timer *settle_timer;
	int in_io; // a socket or timer callback is running and settles the dirty list at its end
	int handshakes;
	wt_cert *cert;   // NULL until one is published
	wt_hosts *hosts; // webtransport-cert-dir's, NULL for none (a reference of this worker's)
	uint8_t *rx;     // rx_slots slots of rx_cap bytes
	size_t rx_slots; // HW_SYS_BATCH_MAX of WT_RX_SLOT, or with GRO WT_RX_GRO_SLOTS of HW_SYS_GRO_SLOT
	size_t rx_cap;
	uint8_t *tx; // HW_SYS_BATCH_MAX slots of HW_QUIC_MAX_DGRAM
	hw_sys_dgram rxd[HW_SYS_BATCH_MAX];
	hw_sys_dgram txd[HW_SYS_BATCH_MAX];
	size_t ntx;   // datagrams in txd not sent yet
	int blocked;  // the socket was full: txd waits for HW_EV_WRITE
	uint8_t *pkt; // HW_WT_SCRATCH_LEN bytes for conn.c to lay a packet out in
};

static void session_settle(wt_session *s);

// ---------------------------------------------------------------------------------- helpers

static void cid_key(const uint8_t *cid, size_t len, char out[WT_KEY_HEX]) {
	static const char hex[] = "0123456789abcdef";
	if (len > 20) len = 20;
	for (size_t i = 0; i < len; i++) {
		out[2 * i] = hex[cid[i] >> 4];
		out[2 * i + 1] = hex[cid[i] & 15];
	}
	out[2 * len] = '\0';
}

// ---------------------------------------------------------------------------------- sending

// Send what is batched. On a full socket the rest waits for HW_EV_WRITE; a datagram the kernel
// refuses for any other reason (no route to that peer, say) is dropped, as the network would.
static void tx_flush(wt_worker *ww) {
	while (ww->ntx > 0 && !ww->blocked) {
		int r = hw_sys_send_batch(ww->fd, ww->txd, ww->ntx);
		size_t k;
		if (r > 0) {
			k = (size_t)r;
		} else if (errno == EAGAIN || errno == EWOULDBLOCK) {
			ww->blocked = 1;
			hw_loop_mod_fd(ww->w->loop, ww->fd, HW_EV_READ | HW_EV_WRITE);
			return;
		} else {
			HW_DEBUG("wt", "worker %d: send: %s", ww->w->index, strerror(errno));
			k = 1;
		}
		// The slots sent go to the back, with their buffers.
		hw_sys_dgram done[HW_SYS_BATCH_MAX];
		memcpy(done, ww->txd, k * sizeof(done[0]));
		memmove(ww->txd, ww->txd + k, (ww->ntx - k) * sizeof(done[0]));
		memcpy(ww->txd + (ww->ntx - k), done, k * sizeof(done[0]));
		ww->ntx -= k;
	}
}

// The next free send slot, flushing a full batch first. NULL while the socket is full.
static hw_sys_dgram *tx_slot(wt_worker *ww) {
	if (ww->ntx == HW_SYS_BATCH_MAX) tx_flush(ww);
	if (ww->blocked || ww->ntx == HW_SYS_BATCH_MAX) return NULL;
	return &ww->txd[ww->ntx];
}

static void tx_commit(wt_worker *ww, size_t len, const struct sockaddr *to, socklen_t to_len) {
	hw_sys_dgram *d = &ww->txd[ww->ntx];
	d->len = len;
	if (to) {
		memcpy(&d->addr, to, to_len);
		d->addr_len = to_len;
	}
	ww->ntx++;
}

// Everything QUIC will send now for this connection, into the batch.
static void session_output(wt_session *s) {
	wt_worker *ww = s->ww;
	uint64_t now = hw_now_ms();
	for (;;) {
		hw_sys_dgram *d = tx_slot(ww);
		if (!d) return; // the socket is full; wt_writable comes back for it
		size_t n = hw_quic_output(s->q, d->buf, HW_QUIC_MAX_DGRAM, &d->addr, &d->addr_len, now);
		if (n == 0) return;
		tx_commit(ww, n, NULL, 0);
	}
}

// ---------------------------------------------------------------------------------- sessions

static void hs_addr_add(wt_worker *ww, const char *ip, int validated, int delta) {
	uintptr_t v = (uintptr_t)hw_smap_get(&ww->hs_addr, ip);
	uintptr_t unit = validated ? (uintptr_t)1 << 16 : 1;
	if (delta > 0) {
		v += unit;
	} else {
		v -= unit;
	}
	if (v == 0) {
		hw_smap_remove(&ww->hs_addr, ip);
	} else if (hw_smap_put(&ww->hs_addr, ip, (void *)v) == 1) {
		hw_smap_remove(&ww->hs_addr, ip);
		if (hw_smap_put(&ww->hs_addr, ip, (void *)v) < 0) return; // out of memory: the count is lost, not wrong
	}
}

// The handshake is over, one way or the other: it no longer counts as in progress.
static void session_hs_done(wt_session *s) {
	if (!s->hs_counted) return;
	s->hs_counted = 0;
	s->ww->handshakes--;
	hs_addr_add(s->ww, s->ip, s->hs_validated, -1);
	atomic_fetch_sub(&s->ww->w->server->wt_handshakes, 1);
	if (s->odcid_key[0]) {
		if (hw_smap_get(&s->ww->cids, s->odcid_key) == s) hw_smap_remove(&s->ww->cids, s->odcid_key);
		s->odcid_key[0] = '\0';
	}
}

static void session_touch(wt_session *s) {
	wt_worker *ww = s->ww;
	if (!s->dirty) {
		s->dirty = 1;
		s->dprev = NULL;
		s->dnext = ww->dirty;
		if (ww->dirty) ww->dirty->dprev = s;
		ww->dirty = s;
	}
}

static void dirty_unlink(wt_session *s) {
	wt_worker *ww = s->ww;
	if (!s->dirty) return;
	if (s->dprev) {
		s->dprev->dnext = s->dnext;
	} else {
		ww->dirty = s->dnext;
	}
	if (s->dnext) s->dnext->dprev = s->dprev;
	s->dirty = 0;
	s->dprev = s->dnext = NULL;
}

static void settle_dirty(wt_worker *ww) {
	while (ww->dirty) {
		wt_session *s = ww->dirty;
		dirty_unlink(s);
		session_settle(s);
	}
}

static void settle_timer_cb(hw_loop *loop, void *ud) {
	wt_worker *ww = ud;
	ww->settle_timer = NULL;
	ww->in_io = 1;
	settle_dirty(ww);
	ww->in_io = 0;
	tx_flush(ww);
}

// Mark the session for session_settle, and make sure one runs soon when no callback of this file
// is under way to do it at its end.
static void session_defer(wt_session *s) {
	session_touch(s);
	wt_worker *ww = s->ww;
	if (!ww->in_io && !ww->settle_timer) ww->settle_timer = hw_loop_add_timer(ww->w->loop, 0, 0, settle_timer_cb, ww);
}

static void session_free(wt_session *s) {
	wt_worker *ww = s->ww;
	hw_server *srv = ww->w->server;
	dirty_unlink(s);
	if (s->timer) hw_loop_cancel_timer(ww->w->loop, s->timer);
	if (s->q && s->counted) {
		hw_quic_stats st;
		hw_quic_get_stats(s->q, &st);
		HW_DEBUG("wt",
		         "%s: session over: %llu packets sent, %llu lost (%llu spurious), %llu received; srtt %llu us, "
		         "cwnd %llu, ssthresh %lld, %llu congestion events, %llu PTOs, %llu bytes acknowledged app-limited, "
		         "datagrams of %llu",
		         s->ip, (unsigned long long)st.packets_sent, (unsigned long long)st.packets_lost,
		         (unsigned long long)st.spurious_lost, (unsigned long long)st.packets_received,
		         (unsigned long long)st.srtt_us, (unsigned long long)st.cwnd,
		         st.ssthresh == UINT64_MAX ? -1LL : (long long)st.ssthresh, (unsigned long long)st.congestion_events,
		         (unsigned long long)st.ptos, (unsigned long long)st.acked_limited, (unsigned long long)st.mds);
	}
	session_hs_done(s);
	for (size_t i = 0; i < s->ncids; i++) {
		char key[WT_KEY_HEX];
		cid_key(s->cids[i], HW_QUIC_CID_LEN, key);
		if (hw_smap_get(&ww->cids, key) == s) hw_smap_remove(&ww->cids, key);
	}
	free(s->cids);
	if (s->c) {
		hw_conn *c = s->c;
		s->c = NULL;
		c->wt = NULL;
		conn_close(c);
	}
	if (s->counted) atomic_fetch_sub(&srv->wt_sessions_active, 1);
	if (s->wt) hw_wt_free(s->wt);
	if (s->q) hw_quic_free(s->q);
	if (s->prev) {
		s->prev->next = s->next;
	} else {
		ww->sessions = s->next; // every session is on the list from the moment it exists
	}
	if (s->next) s->next->prev = s->prev;
	free(s);
}

static void session_timer_cb(hw_loop *loop, void *ud) {
	wt_session *s = ud;
	wt_worker *ww = s->ww;
	s->timer = NULL;
	uint64_t now = hw_now_ms();
	ww->in_io = 1;
	if (now >= hw_quic_timeout(s->q)) {
		s->busy++;
		hw_quic_on_timeout(s->q, now);
		s->busy--;
	}
	session_settle(s);
	settle_dirty(ww);
	ww->in_io = 0;
	tx_flush(ww);
}

// One timer per session, at the earliest of QUIC's deadline, the handshake's expiry and a refusal's
// close. A timer that is already due no later than that is left alone: when it fires early it
// finds nothing due and is armed again, which is cheaper than moving it on every packet.
static void session_arm(wt_session *s) {
	uint64_t at = hw_quic_timeout(s->q);
	if (!s->established && s->created_ms + WT_HS_EXPIRY_MS < at) at = s->created_ms + WT_HS_EXPIRY_MS;
	if (s->refused && !s->quic_closing && s->refuse_at < at) at = s->refuse_at;
	if (s->close_by && !s->quic_closing && s->close_by < at) at = s->close_by;
	if (at == UINT64_MAX) return;
	if (s->timer && s->timer_at <= at) return;
	hw_loop *loop = s->ww->w->loop;
	if (s->timer) hw_loop_cancel_timer(loop, s->timer);
	uint64_t now = hw_now_ms();
	s->timer = hw_loop_add_timer(loop, at > now ? at - now : 0, 0, session_timer_cb, s);
	s->timer_at = at;
}

static void session_quic_close(wt_session *s, uint64_t code, const char *reason) {
	if (s->quic_closing) return;
	s->quic_closing = 1;
	s->busy++;
	hw_quic_close(s->q, code, reason);
	s->busy--;
}

// Everything a callback asked for, now that no call into the stack is under way; then the output,
// the timer, and the session's end once QUIC has drained it.
static void session_settle(wt_session *s) {
	if (s->busy) {
		session_touch(s);
		return;
	}
	s->busy++;
	uint64_t now = hw_now_ms();
	if (s->paused && !s->pause_want) {
		s->paused = 0;
		hw_wt_pause(s->wt, 0); // may hand over packets it held, and the connection may close on them
	}
	if (s->c && !s->opened && hw_wt_ready(s->wt)) {
		s->opened = 1;
		conn_wt_open(s->c);
	}
	if (s->c) {
		size_t q = hw_wt_queued(s->wt);
		if (q < s->last_queued) s->c->wrote = 1; // what conn_sweep takes for a client that reads
		s->last_queued = q;
		conn_wt_progress(s->c);
	}
	if (s->c && s->wisp_ended && !s->pause_want && !s->paused) {
		// Every packet before the Wisp stream's end has been handed over (none is held while the
		// session reads), as a WebSocket's EOF comes after its last frame: the connection closes as
		// it would at that EOF, and the session with it.
		HW_DEBUG("wt", "%s: the client ended its Wisp stream", s->ip);
		conn_close(s->c); // wt_conn_detach: close_pending, just below
	}
	if (s->close_pending) {
		s->close_pending = 0;
		if (!s->quic_closing) {
			hw_wt_close(s->wt, s->close_code, "");
			s->close_by = now + WT_CLOSE_MS;
		}
	}
	if (s->close_by && !s->quic_closing && now >= s->close_by) {
		HW_DEBUG("wt", "%s: no answer to the session's close in %d ms", s->ip, WT_CLOSE_MS);
		session_quic_close(s, HW_H3_NO_ERROR, "");
	}
	if (s->refused && !s->quic_closing && (hw_quic_queued(s->q) == 0 || now >= s->refuse_at)) {
		session_quic_close(s, HW_H3_NO_ERROR, "refused");
	}
	s->busy--;
	if (s->busy) return; // settled from inside a callback after all: the outer call finishes
	if (!s->established && now >= s->created_ms + WT_HS_EXPIRY_MS) {
		HW_DEBUG("wt", "%s: handshake not complete after %d ms, dropped", s->ip, WT_HS_EXPIRY_MS);
		session_free(s);
		return;
	}
	session_output(s);
	if (hw_quic_is_drained(s->q)) {
		session_free(s);
		return;
	}
	session_arm(s);
}

// ---- QUIC callbacks (inside hw_quic_input / hw_quic_on_timeout: record, do not free)

static void q_established(void *ud) {
	wt_session *s = ud;
	s->established = 1;
	session_hs_done(s);
	if (s->wt) hw_wt_on_established(s->wt);
}

// hw_wt says nothing when the client ends its Wisp stream (to it, only the CONNECT stream ends a
// session), so the end is seen here. The Wisp stream is the client's bidirectional stream, other
// than the CONNECT's, that made the session ready or that a packet came from; its FIN or reset is
// the client's last word on it.
static void wisp_candidate(wt_session *s, int64_t id) {
	if (s->wisp_id < 0 && id >= 0 && id != s->connect_id && (id & 3) == 0) s->wisp_id = id;
}

static void q_stream_data(void *ud, uint64_t id, const uint8_t *data, size_t len, int fin) {
	wt_session *s = ud;
	if (!s->wt) return;
	int was_ready = hw_wt_ready(s->wt);
	s->in_stream = (int64_t)id;
	hw_wt_on_stream_data(s->wt, id, data, len, fin);
	s->in_stream = -1;
	if (!was_ready && hw_wt_ready(s->wt)) wisp_candidate(s, (int64_t)id);
	if (fin && s->wisp_id == (int64_t)id && !s->wisp_ended) {
		s->wisp_ended = 1;
		session_touch(s);
	}
}

static void q_stream_reset(void *ud, uint64_t id, uint64_t app_error) {
	wt_session *s = ud;
	if (!s->wt) return;
	hw_wt_on_stream_reset(s->wt, id, app_error);
	if (s->wisp_id == (int64_t)id && !s->wisp_ended) {
		s->wisp_ended = 1;
		session_touch(s);
	}
}

static void q_stream_stop(void *ud, uint64_t id, uint64_t app_error) {
	wt_session *s = ud;
	if (s->wt) hw_wt_on_stream_stop(s->wt, id, app_error);
}

static void q_stream_writable(void *ud, uint64_t id) {
	wt_session *s = ud;
	if (s->wt) hw_wt_on_stream_writable(s->wt, id);
}

static void q_datagram(void *ud, const uint8_t *data, size_t len) {
	wt_session *s = ud;
	if (s->wt) hw_wt_on_datagram(s->wt, data, len);
}

static void q_cid(void *ud, const uint8_t cid[HW_QUIC_CID_LEN], int retire) {
	wt_session *s = ud;
	wt_worker *ww = s->ww;
	char key[WT_KEY_HEX];
	cid_key(cid, HW_QUIC_CID_LEN, key);
	if (retire) {
		if (hw_smap_get(&ww->cids, key) == s) hw_smap_remove(&ww->cids, key);
		for (size_t i = 0; i < s->ncids; i++) {
			if (memcmp(s->cids[i], cid, HW_QUIC_CID_LEN) == 0) {
				memcpy(s->cids[i], s->cids[--s->ncids], HW_QUIC_CID_LEN);
				break;
			}
		}
		return;
	}
	if (s->ncids == s->cids_cap) {
		size_t cap = s->cids_cap ? s->cids_cap * 2 : 4;
		uint8_t (*p)[HW_QUIC_CID_LEN] = realloc(s->cids, cap * sizeof(*p));
		if (!p) return; // not findable by this one: its datagrams get a stateless reset
		s->cids = p;
		s->cids_cap = cap;
	}
	// A CID is 7 random bytes behind the worker's index: one that is already taken is a coincidence
	// the connection survives without (it has others), never a reason to take it over.
	if (hw_smap_put(&ww->cids, key, s) != 0) return;
	memcpy(s->cids[s->ncids++], cid, HW_QUIC_CID_LEN);
}

static void q_closed(void *ud, uint64_t error, int app, const char *reason) {
	wt_session *s = ud;
	s->quic_closing = 1;
	HW_DEBUG("wt", "%s: QUIC closed (%s 0x%llx)", s->ip, app ? "application" : "transport", (unsigned long long)error);
	(void)reason;                      // the peer's words: not for the log
	if (s->wt) hw_wt_on_closed(s->wt); // which ends the session, and w_session_closed the connection
	if (s->c) {
		hw_conn *c = s->c;
		s->c = NULL;
		c->wt = NULL;
		conn_close(c);
	}
	session_touch(s);
}

// ---- hw_wt callbacks

static int wt_route_ok(const hw_server_config *cfg, const char *authority, const char *path) {
	if (cfg->webtransport_path_count == 0) return 1;
	for (int i = 0; i < cfg->webtransport_path_count; i++) {
		if (hw_wt_route_match(cfg->webtransport_paths[i].host, cfg->webtransport_paths[i].path, authority, path)) {
			return 1;
		}
	}
	return 0;
}

static int w_session_request(void *ud, const hw_wt_request *req, const char **protocol_out) {
	wt_session *s = ud;
	hw_server *srv = s->ww->w->server;
	if (s->c || s->refused) return 400; // one session per connection
	s->connect_id = s->in_stream;
	// The paths a WebSocket reaches the relay on behind the operator's proxy, and nothing else:
	// a session for any other is a 404, before anything is charged or counted for it. The path
	// is not logged (it may hold a gate key).
	if (!wt_route_ok(&srv->cfg, req->authority, req->path)) {
		HW_DEBUG("wt", "%s: session for a path no webtransport-path names", s->ip);
		s->refused = 1;
		s->refuse_at = hw_now_ms() + WT_REFUSE_MS;
		session_touch(s);
		return 404;
	}
	socklen_t pl = 0;
	const struct sockaddr *peer = hw_quic_peer(s->q, &pl);
	hw_conn *c = peer ? conn_wt_new(s->ww->w, s, peer) : NULL;
	if (!c) {
		s->refused = 1;
		s->refuse_at = hw_now_ms() + WT_REFUSE_MS;
		return 503;
	}
	s->c = c;
	int status = conn_wt_admit(c, req->origin, req->protocols);
	if (status != 200) {
		s->c = NULL;
		c->wt = NULL;
		conn_close(c);
		s->refused = 1;
		s->refuse_at = hw_now_ms() + WT_REFUSE_MS;
		session_touch(s);
		return status;
	}
	// The first protocol offered is echoed, as the WebSocket path echoes the subprotocol: a
	// browser fails the session when the one it asked for does not come back.
	if (c->is_v2 && req->protocols && hw_wt_protocol_first(req->protocols, s->protocol, sizeof(s->protocol)) == 0 &&
	    s->protocol[0]) {
		*protocol_out = s->protocol;
	}
	s->counted = 1;
	atomic_fetch_add(&srv->wt_sessions_total, 1);
	atomic_fetch_add(&srv->wt_sessions_active, 1);
	session_touch(s);
	return 200;
}

static void w_packet(void *ud, const uint8_t *data, size_t len, int datagram) {
	wt_session *s = ud;
	if (!s->c) return;
	if (!s->opened) {
		// The Wisp stream exists, or this would not be here: the opening goes first, as on a
		// WebSocket nothing precedes the server's first packet.
		if (datagram || !hw_wt_ready(s->wt)) {
			atomic_fetch_add(&s->ww->w->server->wt_dropped, 1);
			return;
		}
		s->opened = 1;
		conn_wt_open(s->c);
		if (!s->c) return;
	}
	if (!datagram) wisp_candidate(s, s->in_stream);
	conn_wt_packet(s->c, data, len, datagram);
	session_touch(s);
}

// Also the session's becoming ready: session_settle then sends the opening.
static void w_writable(void *ud) {
	wt_session *s = ud;
	session_touch(s);
}

static void w_session_closed(void *ud, uint32_t code, const char *reason) {
	wt_session *s = ud;
	(void)reason;
	HW_DEBUG("wt", "%s: session closed by the client (%u)", s->ip, code);
	if (s->c) {
		hw_conn *c = s->c;
		s->c = NULL;
		c->wt = NULL;
		conn_close(c);
	}
	// The session was all this connection was for.
	s->refused = 1;
	s->refuse_at = hw_now_ms();
	session_touch(s);
}

// ---------------------------------------------------------------------------------- conn.c's side

int wt_conn_send(wt_session *s, const uint8_t *pkt, size_t len, int unreliable) {
	// send_max is 0, so hw_wt_send never refuses for a full queue (1): the bound is conn.c's
	// backpressure on hw_wt_queued, as it is on a WebSocket's wbuf. Anything but 0 is a session
	// that cannot take packets any more.
	return hw_wt_send(s->wt, pkt, len, unreliable) == 0 ? 0 : -1;
}

size_t wt_conn_queued(const wt_session *s) {
	return hw_wt_queued(s->wt);
}

size_t wt_conn_datagram_max(const wt_session *s) {
	return hw_wt_datagram_max(s->wt);
}

uint8_t *wt_conn_scratch(wt_session *s) {
	return s->ww->pkt;
}

// Stopping is done at once (it only stops what is delivered next); starting again may hand over
// what hw_wt held, so it waits for session_settle, where no call into the stack is under way.
void wt_conn_pause(wt_session *s, int paused) {
	s->pause_want = paused;
	if (paused && !s->paused) {
		s->paused = 1;
		hw_wt_pause(s->wt, 1);
	} else if (!paused && s->paused) {
		session_defer(s);
	}
}

void wt_conn_flush(wt_session *s) {
	if (s->busy || s->ww->in_io) {
		session_touch(s); // the callback that is running settles it, output included
		return;
	}
	session_output(s);
	session_arm(s);
	tx_flush(s->ww);
}

void wt_conn_detach(wt_session *s, uint32_t code) {
	s->c = NULL;
	s->close_pending = 1;
	s->close_code = code;
	session_defer(s);
}

// ---------------------------------------------------------------------------------- receiving

static int ww_cert_for(void *ud, const char *sni, const hw_der **chain, size_t *chain_len, const uint8_t **key);

static void session_quic_config(const wt_worker *ww, hw_quic_config *qc) {
	static const char *const alpn[] = {HW_WT_ALPN};
	const hw_server *srv = ww->w->server;
	const hw_server_config *cfg = &srv->cfg;
	memset(qc, 0, sizeof(*qc));
	qc->is_server = 1;
	qc->tls.is_server = 1;
	qc->tls.chain = ww->cert->chain;
	qc->tls.chain_len = ww->cert->chain_len;
	qc->tls.key = ww->cert->key;
	if (ww->hosts) {
		qc->tls.cert_for = ww_cert_for;
		qc->tls.cert_ud = (void *)ww; // read on this worker, when the ClientHello is
	}
	qc->tls.alpn = alpn;
	qc->tls.alpn_count = 1;
	qc->max_idle_ms = (uint64_t)cfg->webtransport_idle_timeout_s * 1000;
	// The client's credit: what it may have in flight toward the server before the server reads
	// it. The Wisp stream carries every stream's uploads, so it gets the whole connection's.
	size_t window = cfg->ws_write_high_water;
	if (window < 1024 * 1024) window = 1024 * 1024;
	if (window > 16u * 1024 * 1024) window = 16u * 1024 * 1024;
	qc->initial_max_data = window;
	qc->initial_max_stream_data = window;
	qc->initial_max_streams_bidi = 16; // the CONNECT and the Wisp stream; the rest are refused
	qc->initial_max_streams_uni = 16;  // control, the QPACK pair, and whatever is refused
	qc->max_datagram_frame_size = 65535;
	qc->stream_send_max = cfg->ws_write_high_water;
	qc->conn_send_max = cfg->ws_write_high_water;
	qc->datagram_queue_max = 256;
	qc->keepalive_ms = WT_KEEPALIVE_MS;
	qc->cid_prefix = (uint8_t)ww->w->index;
	qc->reset_key = srv->wt_reset_key;
}

static void session_input(wt_session *s, hw_sys_dgram *d, uint64_t now) {
	s->busy++;
	hw_quic_input(s->q, d->buf, d->len, (struct sockaddr *)&d->addr, d->addr_len, now);
	s->busy--;
	session_touch(s);
}

static void new_cid(const wt_worker *ww, uint8_t cid[HW_QUIC_CID_LEN]) {
	if (hw_sys_random(cid, HW_QUIC_CID_LEN) != 0) memset(cid, 0x5a, HW_QUIC_CID_LEN);
	cid[0] = (uint8_t)ww->w->index;
}

// An Initial for no connection we have: a Retry, a new connection, or nothing.
static void initial_new(wt_worker *ww, hw_sys_dgram *d, const hw_quic_header *h, uint64_t now) {
	hw_server *srv = ww->w->server;
	const hw_server_config *cfg = &srv->cfg;
	const struct sockaddr *from = (const struct sockaddr *)&d->addr;
	if (!ww->cert || ww->cert->chain_len == 0) return;
	uint8_t odcid[20];
	uint8_t odcid_len = 0;
	int validated = h->token_len > 0 && hw_quic_token_valid(h->token, h->token_len, from, srv->wt_token_key, now,
	                                                        WT_TOKEN_AGE_MS, odcid, &odcid_len);
	if (ww->handshakes >= cfg->webtransport_max_handshakes) {
		atomic_fetch_add(&srv->wt_refused_handshakes, 1);
		return;
	}
	char ip[HW_IP_STR_LEN];
	hw_addr_ip_str(from, ip, sizeof(ip));
	uintptr_t counts = (uintptr_t)hw_smap_get(&ww->hs_addr, ip);
	uintptr_t mine = validated ? counts >> 16 : counts & 0xffff;
	// An address is a claim until it returns a token: a client past the worker's threshold or its
	// address's share proves it with a Retry first. One that has proven it is held to its share.
	if (!validated && (ww->handshakes >= cfg->webtransport_retry_threshold || mine >= WT_HS_PER_ADDR)) {
		hw_sys_dgram *t = tx_slot(ww);
		if (!t) return;
		uint8_t scid[HW_QUIC_CID_LEN];
		new_cid(ww, scid);
		size_t n = hw_quic_retry(h, from, srv->wt_token_key, now, scid, t->buf, HW_QUIC_MAX_DGRAM);
		if (n == 0) return;
		tx_commit(ww, n, from, d->addr_len);
		atomic_fetch_add(&srv->wt_retries, 1);
		return;
	}
	if (mine >= WT_HS_PER_ADDR) {
		atomic_fetch_add(&srv->wt_refused_handshakes, 1);
		return;
	}

	wt_session *s = calloc(1, sizeof(*s));
	if (!s) return;
	s->ww = ww;
	s->created_ms = now;
	s->wisp_id = -1;
	s->connect_id = -1;
	s->in_stream = -1;
	snprintf(s->ip, sizeof(s->ip), "%s", ip);
	hw_quic_config qc;
	session_quic_config(ww, &qc);
	hw_quic_callbacks cb = {
	    .ud = s,
	    .established = q_established,
	    .stream_data = q_stream_data,
	    .stream_reset = q_stream_reset,
	    .stream_stop = q_stream_stop,
	    .stream_writable = q_stream_writable,
	    .datagram = q_datagram,
	    .cid = q_cid,
	    .closed = q_closed,
	};
	// Linked first: the callbacks may run inside hw_quic_accept, and session_free undoes all of it.
	s->next = ww->sessions;
	if (ww->sessions) ww->sessions->prev = s;
	ww->sessions = s;
	s->hs_counted = 1;
	s->hs_validated = validated;
	ww->handshakes++;
	hs_addr_add(ww, ip, validated, 1);
	atomic_fetch_add(&srv->wt_handshakes, 1);
	s->busy++;
	s->q = hw_quic_accept(&qc, &cb, h, from, d->addr_len, validated, validated ? odcid : h->dcid,
	                      validated ? odcid_len : h->dcid_len, now);
	s->busy--;
	hw_wt_config wc = {.max_packet = cfg->max_message_size, .send_max = 0};
	hw_wt_callbacks wcb = {
	    .ud = s,
	    .session_request = w_session_request,
	    .packet = w_packet,
	    .writable = w_writable,
	    .session_closed = w_session_closed,
	};
	if (s->q) s->wt = hw_wt_new(s->q, &wc, &wcb);
	if (!s->q || !s->wt) {
		session_free(s);
		return;
	}
	// Retransmissions of this Initial still carry the client's own DCID.
	cid_key(h->dcid, h->dcid_len, s->odcid_key);
	if (hw_smap_put(&ww->cids, s->odcid_key, s) != 0) s->odcid_key[0] = '\0';
	session_input(s, d, now);
	// Nothing is kept for an Initial that does not decrypt: the bytes were anybody's.
	hw_quic_stats st;
	hw_quic_get_stats(s->q, &st);
	if (st.packets_received == 0) {
		atomic_fetch_add(&srv->wt_dropped, 1);
		session_free(s);
	}
}

static void datagram_in(wt_worker *ww, hw_sys_dgram *d, uint64_t now) {
	hw_server *srv = ww->w->server;
	hw_quic_header h;
	if (hw_quic_parse_header(d->buf, d->len, &h) != 0) {
		atomic_fetch_add(&srv->wt_dropped, 1);
		return;
	}
	char key[WT_KEY_HEX];
	cid_key(h.dcid, h.dcid_len, key);
	wt_session *s = hw_smap_get(&ww->cids, key);
	if (s) {
		session_input(s, d, now);
		return;
	}
	const struct sockaddr *from = (const struct sockaddr *)&d->addr;
	if (!h.long_header) {
		// A connection this worker does not have: gone, or another worker's after the group
		// changed. A stateless reset ends it at the client (only ever shorter than what came in).
		hw_sys_dgram *t = tx_slot(ww);
		size_t n = t && h.dcid_len == HW_QUIC_CID_LEN
		               ? hw_quic_stateless_reset(h.dcid, srv->wt_reset_key, d->len, t->buf, HW_QUIC_MAX_DGRAM)
		               : 0;
		if (n > 0) tx_commit(ww, n, from, d->addr_len);
		atomic_fetch_add(&srv->wt_dropped, 1);
		return;
	}
	if (h.version != HW_QUIC_VERSION_1) {
		hw_sys_dgram *t = tx_slot(ww);
		size_t n = t ? hw_quic_version_negotiation(&h, t->buf, HW_QUIC_MAX_DGRAM) : 0;
		if (n > 0) tx_commit(ww, n, from, d->addr_len);
		return;
	}
	// Only an Initial in a full-sized datagram may begin a connection (RFC 9000 14.1).
	if (h.type != 0 || d->len < HW_QUIC_MIN_DGRAM) {
		atomic_fetch_add(&srv->wt_dropped, 1);
		return;
	}
	initial_new(ww, d, &h, now);
}

// Every session whose output the socket could not take before: now it can.
static void wt_writable(wt_worker *ww) {
	ww->blocked = 0;
	tx_flush(ww);
	if (ww->blocked) return;
	hw_loop_mod_fd(ww->w->loop, ww->fd, HW_EV_READ);
	for (wt_session *s = ww->sessions; s && !ww->blocked; s = s->next) session_touch(s);
}

static void wt_io_cb(hw_loop *loop, int fd, unsigned events, void *ud) {
	wt_worker *ww = ud;
	ww->in_io = 1;
	if (events & HW_EV_WRITE) wt_writable(ww);
	if (events & (HW_EV_READ | HW_EV_ERROR | HW_EV_HUP)) {
		for (int round = 0; round < WT_RX_ROUNDS; round++) {
			for (size_t i = 0; i < ww->rx_slots; i++) {
				ww->rxd[i].buf = ww->rx + i * ww->rx_cap;
				ww->rxd[i].cap = ww->rx_cap;
			}
			int n = hw_sys_recv_batch(fd, ww->rxd, ww->rx_slots);
			if (n < 0) {
				if (errno == EAGAIN || errno == EWOULDBLOCK) break;
				// An ICMP error for an earlier send, taken off the socket by this receive.
				HW_DEBUG("wt", "worker %d: receive: %s", ww->w->index, strerror(errno));
				continue;
			}
			uint64_t now = hw_now_ms();
			for (int i = 0; i < n; i++) {
				// A coalesced read is datagrams of one sender back to back, each taken on its own.
				hw_sys_dgram *d = &ww->rxd[i];
				uint8_t *base = d->buf;
				size_t total = d->len, seg = d->segment ? d->segment : d->len;
				for (size_t off = 0; off < total; off += seg) {
					d->buf = base + off;
					d->len = HW_MIN(seg, total - off);
					datagram_in(ww, d, now);
				}
			}
			settle_dirty(ww);
			if ((size_t)n < ww->rx_slots) break;
		}
	}
	settle_dirty(ww);
	ww->in_io = 0;
	tx_flush(ww);
}

// ---------------------------------------------------------------------------------- certificates

static void wt_cert_clear(wt_cert *c) {
	for (size_t i = 0; i < c->chain_len; i++) hw_der_free(&c->chain[i]);
	c->chain_len = 0;
	memset(c->key, 0, sizeof(c->key));
}

void wt_cert_free(wt_cert *c) {
	if (!c) return;
	wt_cert_clear(c);
	free(c);
}

static wt_cert *wt_cert_copy(const wt_cert *src) {
	wt_cert *c = calloc(1, sizeof(*c));
	if (!c) return NULL;
	memcpy(c->key, src->key, sizeof(c->key));
	memcpy(c->hashes, src->hashes, sizeof(c->hashes));
	c->nhashes = src->nhashes;
	for (size_t i = 0; i < src->chain_len; i++) {
		c->chain[i].der = malloc(src->chain[i].len);
		if (!c->chain[i].der) {
			wt_cert_free(c);
			return NULL;
		}
		memcpy(c->chain[i].der, src->chain[i].der, src->chain[i].len);
		c->chain[i].len = src->chain[i].len;
		c->chain_len = i + 1;
	}
	return c;
}

typedef struct {
	wt_worker *ww;
	wt_cert *cert;
} cert_msg;

static void cert_swap_task(hw_loop *loop, void *ud) {
	(void)loop;
	cert_msg *m = ud;
	wt_cert_free(m->ww->cert);
	m->ww->cert = m->cert;
	free(m);
}

// Every worker its own copy: in place before the loops run, by a posted task after. New
// handshakes take the copy they find; one under way has its own (hw_tls copies the config), so the
// copy a swap frees is never in use. 0, or -1 when a worker kept the previous one (no memory).
static int wt_cert_publish(hw_server *s, int running) {
	int rc = 0;
	for (int i = 0; i < s->nworkers; i++) {
		wt_worker *ww = s->workers[i].wt;
		wt_cert *copy = wt_cert_copy(s->wt_cert_cur);
		if (!copy) {
			rc = -1; // this worker keeps the previous one until the next rotation or reload
			continue;
		}
		if (!running) {
			wt_cert_free(ww->cert);
			ww->cert = copy;
			continue;
		}
		cert_msg *m = malloc(sizeof(*m));
		if (m) {
			m->ww = ww;
			m->cert = copy;
		}
		if (!m || hw_loop_post(s->workers[i].loop, cert_swap_task, m) != 0) {
			free(m);
			wt_cert_free(copy);
			rc = -1;
		}
	}
	return rc;
}

// A new self-signed P-256 certificate, valid from an hour ago for 13 days, with the previous one's
// hash kept beside its own: a page that fetched /webtransport.json before the rotation still pins
// a hash the server lists.
static int wt_cert_make(hw_server *s) {
	wt_cert *c = calloc(1, sizeof(*c));
	uint8_t pub[HW_P256_PUB_LEN];
	if (!c || hw_p256_keygen(c->key, pub) != 0) goto fail;
	int64_t now = (int64_t)time(NULL);
	int64_t from = now - WT_CERT_EARLY_S;
	if (hw_cert_selfsigned(c->key, pub, WT_CERT_CN, from, from + WT_CERT_LIFE_S, &c->chain[0]) != 0) goto fail;
	c->chain_len = 1;
	hw_sha256(c->chain[0].der, c->chain[0].len, c->hashes[0]);
	c->nhashes = 1;
	if (s->wt_cert_cur && s->wt_cert_cur->nhashes > 0) {
		memcpy(c->hashes[1], s->wt_cert_cur->hashes[0], sizeof(c->hashes[1]));
		c->nhashes = 2;
	}
	wt_cert_free(s->wt_cert_cur);
	s->wt_cert_cur = c;
	s->wt_cert_made = (uint64_t)now;
	return 0;
fail:
	wt_cert_free(c);
	return -1;
}

static char *read_file(const char *path, size_t *len) {
	int fd = open(path, O_RDONLY);
	if (fd < 0) return NULL;
	char *buf = malloc(WT_PEM_MAX + 1);
	size_t n = 0;
	while (buf) {
		ssize_t r = read(fd, buf + n, WT_PEM_MAX + 1 - n);
		if (r < 0 && errno == EINTR) continue;
		if (r <= 0) break;
		n += (size_t)r;
		if (n > WT_PEM_MAX) {
			free(buf);
			buf = NULL;
			errno = EFBIG;
		}
	}
	int saved = errno;
	close(fd);
	errno = saved;
	if (buf) {
		buf[n] = '\0';
		*len = n;
	}
	return buf;
}

// A chain and its key from PEM texts (the same text for a file that holds both), into c. The key
// must be the leaf's and on P-256: that is the only signature the TLS layer makes. cname and kname
// say where they came from in a message. 0, or -1 and the reason in why (names and what is wrong,
// never the key's bytes).
static int wt_cert_parse(wt_cert *c, const char *cpem, size_t clen, const char *kpem, size_t klen, const char *cname,
                         const char *kname, char *why, size_t why_cap) {
	uint8_t pub[HW_P256_PUB_LEN], want[HW_P256_PUB_LEN];
	if (hw_cert_load_chain(cpem, clen, c->chain, HW_CERT_CHAIN_MAX, &c->chain_len) != 0) {
		snprintf(why, why_cap, "%s: no certificate chain of at most %d PEM blocks", cname, HW_CERT_CHAIN_MAX);
		return -1;
	}
	// Never the key's bytes in a message: only that it is not what is needed.
	if (hw_cert_load_p256_key(kpem, klen, c->key) != 0) {
		snprintf(why, why_cap, "%s: not an ECDSA P-256 private key", kname);
		wt_cert_clear(c);
		return -1;
	}
	if (hw_cert_p256_pubkey(c->chain[0].der, c->chain[0].len, want) != 0) {
		snprintf(why, why_cap, "%s: the first certificate has no ECDSA P-256 key", cname);
		wt_cert_clear(c);
		return -1;
	}
	if (hw_p256_public(c->key, pub) != 0 || memcmp(pub, want, sizeof(pub)) != 0) {
		snprintf(why, why_cap, "%s: the key is not the key of the first certificate in %s", kname, cname);
		wt_cert_clear(c);
		return -1;
	}
	c->nhashes = 0; // a certificate of the Web PKI is verified, not pinned
	return 0;
}

// webtransport-cert and webtransport-key, into *out. The same checks at start and on every reload.
static int wt_cert_load(const hw_server_config *cfg, wt_cert **out, char *why, size_t why_cap) {
	*out = NULL;
	size_t clen = 0, klen = 0;
	char *cpem = read_file(cfg->webtransport_cert, &clen);
	if (!cpem) {
		snprintf(why, why_cap, "webtransport-cert %s: %s", cfg->webtransport_cert, strerror(errno));
		return -1;
	}
	char *kpem = read_file(cfg->webtransport_key, &klen);
	if (!kpem) {
		snprintf(why, why_cap, "webtransport-key %s: %s", cfg->webtransport_key, strerror(errno));
		free(cpem);
		return -1;
	}
	wt_cert *c = calloc(1, sizeof(*c));
	int rc = -1;
	if (!c) {
		snprintf(why, why_cap, "webtransport-cert %s: %s", cfg->webtransport_cert, strerror(ENOMEM));
	} else {
		char cname[600], kname[600];
		snprintf(cname, sizeof(cname), "webtransport-cert %s", cfg->webtransport_cert);
		snprintf(kname, sizeof(kname), "webtransport-key %s", cfg->webtransport_key);
		if (wt_cert_parse(c, cpem, clen, kpem, klen, cname, kname, why, why_cap) == 0) {
			*out = c;
			c = NULL;
			rc = 0;
		}
	}
	free(c);
	memset(kpem, 0, klen);
	free(kpem);
	free(cpem);
	return rc;
}

// Whole seconds of mtime are enough: a renewal comes weeks after the last, and a file replaced by
// rename is another inode (except on Windows, which has none).
static wt_file_id file_id(const char *path) {
	wt_file_id id;
	memset(&id, 0, sizeof(id));
	struct stat sb;
	if (stat(path, &sb) != 0) return id;
	id.ok = 1;
	id.dev = (uint64_t)sb.st_dev;
	id.ino = (uint64_t)sb.st_ino;
	id.size = (uint64_t)sb.st_size;
	id.mtime = (int64_t)sb.st_mtime;
	return id;
}

static int file_id_same(const wt_file_id *a, const wt_file_id *b) {
	return a->ok == b->ok && a->dev == b->dev && a->ino == b->ino && a->size == b->size && a->mtime == b->mtime;
}

static int file_ids_same(const wt_file_id a[2], const wt_file_id b[2]) {
	return file_id_same(&a[0], &b[0]) && file_id_same(&a[1], &b[1]);
}

// The operator's pair as it is on disk now. Taken before the files are read, so a change after
// the stat is seen by the next look, never missed. stat follows a symlink: certbot's live/ names
// point at a new file on every renewal.
static void wt_files_stat(const hw_server *s, wt_file_id ids[2]) {
	ids[0] = file_id(s->cfg.webtransport_cert);
	ids[1] = file_id(s->cfg.webtransport_key);
}

// A renewer (certbot, lego) replaces the certificate and then the key, so a pair is read only
// once neither file has changed for one look: a new certificate is not tried with the old key
// while the new one is on its way. A pair that does not load is logged once and changes nothing:
// new sessions keep the certificate they had until the files change again. Sessions under way
// keep theirs in any case (hw_tls copied it at the first Initial).
static void wt_cert_watch(hw_server *s, int running) {
	wt_file_id now[2];
	wt_files_stat(s, now);
	if (!file_ids_same(now, s->wt_files_seen)) {
		memcpy(s->wt_files_seen, now, sizeof(now));
		return;
	}
	if (file_ids_same(now, s->wt_files_tried)) return;
	memcpy(s->wt_files_tried, now, sizeof(now));
	wt_cert *c = NULL;
	char why[WT_WHY_LEN];
	if (wt_cert_load(&s->cfg, &c, why, sizeof(why)) != 0) {
		HW_ERROR("wt", "%s; new sessions keep the certificate loaded before", why);
		return;
	}
	wt_cert_free(s->wt_cert_cur);
	s->wt_cert_cur = c;
	// A worker that missed its copy (no memory) gets the pair read again at the next look.
	if (wt_cert_publish(s, running) != 0) memset(s->wt_files_tried, 0, sizeof(s->wt_files_tried));
	uint8_t hash[HW_SHA256_LEN];
	hw_sha256(c->chain[0].der, c->chain[0].len, hash);
	char b64[HW_BASE64_LEN(HW_SHA256_LEN)];
	hw_base64_encode(hash, sizeof(hash), b64, sizeof(b64));
	char until[32] = "an unreadable date";
	int64_t not_after = 0;
	if (hw_cert_not_after(c->chain[0].der, c->chain[0].len, &not_after) == 0) {
		time_t t = (time_t)not_after;
		struct tm tm;
		if (gmtime_r(&t, &tm)) strftime(until, sizeof(until), "%Y-%m-%d %H:%M:%S UTC", &tm);
	}
	HW_INFO("wt", "webtransport-cert %s reloaded: new sessions get the certificate valid until %s, sha-256 %s",
	        s->cfg.webtransport_cert, until, b64);
}

// ---------------------------------------------------------------------------------- per-host certificates

// webtransport-cert-dir holds one <host>.pem per name, the chain and its key in the one file, so a
// renewal is one rename and never a new certificate beside the old key. The maintenance thread
// looks at the directory once a second and at every file once a minute; a file is read again only
// when it is another file (wt_file_id). The table is immutable: a change makes a new one, which
// every worker is posted a reference to.
#define WT_HOSTS_MAX     65536
#define WT_DIR_RESCAN_MS 60000

typedef struct {
	_Atomic int refs;
	int ok; // 0: the file did not load; kept so that it is not tried again until it changes
	wt_file_id id;
	char name[256]; // lower case, the file's name less ".pem"
	wt_cert cert;
} wt_hcert;

struct wt_hosts {
	_Atomic int refs;
	size_t n;
	wt_hcert **v; // sorted by name
};

static void hcert_unref(wt_hcert *h) {
	if (!h || atomic_fetch_sub(&h->refs, 1) != 1) return;
	wt_cert_clear(&h->cert);
	free(h);
}

void wt_hosts_unref(wt_hosts *t) {
	if (!t || atomic_fetch_sub(&t->refs, 1) != 1) return;
	for (size_t i = 0; i < t->n; i++) hcert_unref(t->v[i]);
	free(t->v);
	free(t);
}

static int hcert_cmp(const void *a, const void *b) {
	return strcmp((*(wt_hcert *const *)a)->name, (*(wt_hcert *const *)b)->name);
}

static const wt_hcert *hosts_find(const wt_hosts *t, const char *name) {
	size_t lo = 0, hi = t ? t->n : 0;
	while (lo < hi) {
		size_t mid = lo + (hi - lo) / 2;
		int c = strcmp(name, t->v[mid]->name);
		if (c == 0) return t->v[mid];
		if (c < 0) {
			hi = mid;
		} else {
			lo = mid + 1;
		}
	}
	return NULL;
}

// A file name the directory may hold: a host name in lower case, then ".pem". Anything else (a
// renewer's temporary file, a dotfile, a backup) is not looked at. The name goes to out.
static int host_file_name(const char *file, char out[256]) {
	size_t n = strlen(file);
	if (n < 5 || n - 4 > 253 || strcmp(file + n - 4, ".pem") != 0 || file[0] == '.' || file[0] == '-') return 0;
	for (size_t i = 0; i < n - 4; i++) {
		char c = file[i];
		if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_')) return 0;
	}
	memcpy(out, file, n - 4);
	out[n - 4] = '\0';
	return 1;
}

// The TLS layer asks once the ClientHello is read: the SNI as the client sent it, in any case and
// with or without the root's dot.
static int ww_cert_for(void *ud, const char *sni, const hw_der **chain, size_t *chain_len, const uint8_t **key) {
	const wt_worker *ww = ud;
	if (!sni || !ww->hosts) return 0;
	char name[256];
	size_t n = strlen(sni);
	if (n > 0 && sni[n - 1] == '.') n--;
	if (n == 0 || n >= sizeof(name)) return 0;
	for (size_t i = 0; i < n; i++) name[i] = (char)tolower((unsigned char)sni[i]);
	name[n] = '\0';
	const wt_hcert *h = hosts_find(ww->hosts, name);
	if (!h || !h->ok) return 0;
	*chain = h->cert.chain;
	*chain_len = h->cert.chain_len;
	*key = h->cert.key;
	return 1;
}

static wt_hcert *hcert_load(const char *dir, const char *file, const char *name, wt_file_id id) {
	wt_hcert *h = calloc(1, sizeof(*h));
	if (!h) return NULL;
	atomic_init(&h->refs, 1);
	h->id = id;
	snprintf(h->name, sizeof(h->name), "%s", name);
	char path[1024];
	snprintf(path, sizeof(path), "%s/%s", dir, file);
	size_t len = 0;
	char *pem = read_file(path, &len);
	char why[WT_WHY_LEN];
	if (!pem) {
		HW_WARN("wt", "webtransport-cert-dir: %s: %s; %s keeps no certificate of its own until it changes", file,
		        strerror(errno), name);
		return h;
	}
	if (wt_cert_parse(&h->cert, pem, len, pem, len, file, file, why, sizeof(why)) == 0) {
		h->ok = 1;
	} else {
		HW_WARN("wt", "webtransport-cert-dir: %s; %s keeps no certificate of its own until it changes", why, name);
	}
	memset(pem, 0, len);
	free(pem);
	return h;
}

typedef struct {
	wt_worker *ww;
	wt_hosts *hosts;
} hosts_msg;

static void hosts_swap_task(hw_loop *loop, void *ud) {
	(void)loop;
	hosts_msg *m = ud;
	wt_hosts_unref(m->ww->hosts);
	m->ww->hosts = m->hosts;
	free(m);
}

// s->wt_hosts_cur to every worker, a reference each: in place before the loops run, by a posted
// task after. A handshake under way copied its certificate when it asked (hw_tls), so the table a
// swap lets go of is never in use. 0, or -1 when a worker kept the previous one (no memory).
static int wt_hosts_publish(hw_server *s, int running) {
	int rc = 0;
	for (int i = 0; i < s->nworkers; i++) {
		wt_worker *ww = s->workers[i].wt;
		wt_hosts *t = s->wt_hosts_cur;
		atomic_fetch_add(&t->refs, 1);
		if (!running) {
			wt_hosts_unref(ww->hosts);
			ww->hosts = t;
			continue;
		}
		hosts_msg *m = malloc(sizeof(*m));
		if (m) {
			m->ww = ww;
			m->hosts = t;
		}
		if (!m || hw_loop_post(s->workers[i].loop, hosts_swap_task, m) != 0) {
			free(m);
			wt_hosts_unref(t);
			rc = -1;
		}
	}
	return rc;
}

// One look at every file. Returns 0, or -1 when the directory cannot be read (the table stays).
// *recent is set when a file was too new to read: one being written in place is read once it has
// sat for a second. recent NULL (at start, with nothing to keep meanwhile) reads every file.
static int wt_hosts_scan(hw_server *s, int running, int *recent) {
	const char *dir = s->cfg.webtransport_cert_dir;
	DIR *d = opendir(dir);
	if (!d) return -1;
	const wt_hosts *old = s->wt_hosts_cur;
	wt_hosts *t = calloc(1, sizeof(*t));
	size_t cap = 0, added = 0, replaced = 0, removed = 0;
	int full = 0;
	int64_t now = (int64_t)time(NULL);
	struct dirent *e;
	while (t && (e = readdir(d)) != NULL) {
		char name[256], path[1024];
		if (!host_file_name(e->d_name, name)) continue;
		if (snprintf(path, sizeof(path), "%s/%s", dir, e->d_name) >= (int)sizeof(path)) continue;
		wt_file_id id = file_id(path);
		struct stat sb;
		if (!id.ok || stat(path, &sb) != 0 || !S_ISREG(sb.st_mode)) continue;
		wt_hcert *prev = (wt_hcert *)hosts_find(old, name);
		wt_hcert *h = NULL;
		if (prev && file_id_same(&prev->id, &id)) {
			h = prev;
		} else if (recent && id.mtime >= now - 1) {
			*recent = 1;
			h = prev; // the old one until this one has settled, or nothing yet
		}
		if (h) {
			atomic_fetch_add(&h->refs, 1);
		} else {
			if (t->n >= WT_HOSTS_MAX) {
				full = 1;
				continue;
			}
			h = hcert_load(dir, e->d_name, name, id);
			if (!h) continue; // no memory: the next look tries again
			if (prev) {
				replaced++;
			} else {
				added++;
			}
		}
		if (t->n == cap) {
			size_t nc = cap ? cap * 2 : 64;
			wt_hcert **nv = realloc(t->v, nc * sizeof(*nv));
			if (!nv) {
				hcert_unref(h);
				break;
			}
			t->v = nv;
			cap = nc;
		}
		t->v[t->n++] = h;
	}
	closedir(d);
	if (!t) return 0;
	atomic_init(&t->refs, 1);
	if (full) {
		HW_ERROR("wt", "webtransport-cert-dir %s holds more than %d certificates: the rest are not read", dir,
		         WT_HOSTS_MAX);
	}
	if (t->n) qsort(t->v, t->n, sizeof(*t->v), hcert_cmp);
	for (size_t i = 0; old && i < old->n; i++) removed += hosts_find(t, old->v[i]->name) == NULL;
	if (added == 0 && replaced == 0 && removed == 0 && old && !s->wt_hosts_unpublished) {
		wt_hosts_unref(t);
		return 0;
	}
	size_t usable = 0;
	for (size_t i = 0; i < t->n; i++) usable += t->v[i]->ok;
	wt_hosts_unref(s->wt_hosts_cur);
	s->wt_hosts_cur = t;
	s->wt_hosts_unpublished = wt_hosts_publish(s, running) != 0;
	if (added || replaced || removed || !old) {
		HW_INFO("wt", "webtransport-cert-dir: %zu certificates (%zu new, %zu replaced, %zu gone, %zu unusable)", usable,
		        added, replaced, removed, t->n - usable);
	}
	return 0;
}

static void wt_hosts_watch(hw_server *s, int running) {
	const char *dir = s->cfg.webtransport_cert_dir;
	if (!dir[0]) return;
	wt_file_id d = file_id(dir);
	uint64_t now = hw_now_ms();
	if (file_id_same(&d, &s->wt_dir_seen) && now < s->wt_dir_rescan_ms && !s->wt_hosts_unpublished) return;
	int recent = 0;
	if (wt_hosts_scan(s, running, &recent) != 0) {
		if (!s->wt_dir_failed) {
			HW_ERROR("wt", "webtransport-cert-dir %s: %s; new sessions keep the certificates loaded before", dir,
			         strerror(errno));
		}
		s->wt_dir_failed = 1;
		memset(&s->wt_dir_seen, 0, sizeof(s->wt_dir_seen));
		s->wt_dir_rescan_ms = now + WT_DIR_RESCAN_MS;
		return;
	}
	s->wt_dir_failed = 0;
	// A directory changed within its mtime's second may change again in that second: look again.
	s->wt_dir_seen = d;
	if (recent || d.mtime >= (int64_t)time(NULL) - 1) memset(&s->wt_dir_seen, 0, sizeof(s->wt_dir_seen));
	s->wt_dir_rescan_ms = now + WT_DIR_RESCAN_MS;
}

void wt_cert_tick(hw_server *s, int running) {
	if (!s->cfg.webtransport) return;
	wt_hosts_watch(s, running);
	if (s->cfg.webtransport_cert[0]) {
		wt_cert_watch(s, running);
		return;
	}
	uint64_t now = (uint64_t)time(NULL);
	int asked = atomic_exchange(&s->wt_renew, 0);
	if (!asked && s->wt_cert_cur && now - s->wt_cert_made < WT_CERT_RENEW_S && now >= s->wt_cert_made) return;
	if (wt_cert_make(s) != 0) {
		HW_ERROR("wt", "cannot make a WebTransport certificate; new handshakes use the previous one");
		return;
	}
	char b64[HW_BASE64_LEN(32)];
	hw_base64_encode(s->wt_cert_cur->hashes[0], 32, b64, sizeof(b64));
	HW_INFO("wt", "new self-signed certificate, sha-256 %s, valid %d days", b64, WT_CERT_LIFE_S / 86400);
	wt_cert_publish(s, running);
}

size_t wt_json(const hw_worker *w, char *out, size_t cap) {
	const wt_cert *c = w->wt ? w->wt->cert : NULL;
	int n = snprintf(out, cap, "{\"url\":\"%s\",\"hashes\":[", w->server->cfg.webtransport_url);
	if (n < 0 || (size_t)n >= cap) return 0;
	size_t len = (size_t)n;
	for (int i = 0; c && i < c->nhashes; i++) {
		char b64[HW_BASE64_LEN(32)];
		hw_base64_encode(c->hashes[i], 32, b64, sizeof(b64));
		n = snprintf(out + len, cap - len, "%s{\"algorithm\":\"sha-256\",\"value\":\"%s\"}", i ? "," : "", b64);
		if (n < 0 || (size_t)n >= cap - len) return 0;
		len += (size_t)n;
	}
	n = snprintf(out + len, cap - len, "]}\n");
	if (n < 0 || (size_t)n >= cap - len) return 0;
	return len + (size_t)n;
}

// ---------------------------------------------------------------------------------- setup

// A UDP socket on host:port, non-blocking, in a reuseport group when asked. An empty host is
// every interface, IPv6 and IPv4 on one socket where the system allows it, as the TCP listener.
static int udp_bind(const char *host, uint16_t port, int reuseport, uint16_t *bound) {
	struct addrinfo hints;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_PASSIVE | AI_NUMERICSERV;
	if (!host || !*host) {
		hints.ai_flags |= AI_ADDRCONFIG;
		host = NULL;
	}
	char service[8];
	snprintf(service, sizeof(service), "%u", port);
	struct addrinfo *res = NULL;
	int gai = getaddrinfo(host, service, &hints, &res);
	if (gai != 0) {
		errno = gai == EAI_SYSTEM ? errno : EINVAL;
		return -1;
	}
	struct addrinfo *pick = res;
	if (!host) {
		for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
			if (ai->ai_family == AF_INET6) {
				pick = ai;
				break;
			}
		}
	}
	int fd = -1, saved = 0;
	for (struct addrinfo *ai = pick; ai; ai = ai->ai_next) {
		fd = hw_sys_socket(ai->ai_family, SOCK_DGRAM, 0, 1);
		if (fd < 0) {
			saved = errno;
			continue;
		}
		int one = 1, zero = 0;
		if (reuseport) setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one));
		if (ai->ai_family == AF_INET6) setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &zero, sizeof(zero));
		if (bind(fd, ai->ai_addr, ai->ai_addrlen) == 0) break;
		saved = errno;
		close(fd);
		fd = -1;
	}
	freeaddrinfo(res);
	if (fd < 0) {
		errno = saved ? saved : EADDRNOTAVAIL;
		return -1;
	}
	struct sockaddr_storage ss;
	socklen_t sl = sizeof(ss);
	if (bound && getsockname(fd, (struct sockaddr *)&ss, &sl) == 0) *bound = hw_addr_port((struct sockaddr *)&ss);
	return fd;
}

static wt_worker *wt_worker_new(hw_worker *w) {
	wt_worker *ww = calloc(1, sizeof(*ww));
	if (!ww) return NULL;
	ww->w = w;
	ww->fd = -1;
	hw_smap_init(&ww->cids);
	hw_smap_init(&ww->hs_addr);
	return ww;
}

static int wt_worker_open(wt_worker *ww, int fd) {
	// With GRO a read can be 64 KiB of one client's datagrams, which takes fewer but larger slots.
	int gro = hw_sys_udp_gro(fd);
	ww->rx_slots = gro ? WT_RX_GRO_SLOTS : HW_SYS_BATCH_MAX;
	ww->rx_cap = gro ? HW_SYS_GRO_SLOT : WT_RX_SLOT;
	ww->rx = malloc(ww->rx_slots * ww->rx_cap);
	ww->tx = malloc((size_t)HW_SYS_BATCH_MAX * HW_QUIC_MAX_DGRAM);
	ww->pkt = malloc(HW_WT_SCRATCH_LEN);
	if (!ww->rx || !ww->tx || !ww->pkt) return -1;
	for (size_t i = 0; i < HW_SYS_BATCH_MAX; i++) ww->txd[i].buf = ww->tx + i * HW_QUIC_MAX_DGRAM;
	if (hw_loop_add_fd(ww->w->loop, fd, HW_EV_READ, wt_io_cb, ww) != 0) return -1;
	ww->fd = fd;
	return 0;
}

int wt_listener_init(hw_server *s) {
	const hw_server_config *cfg = &s->cfg;
	if (!cfg->webtransport) return 0;
	if (hw_sys_random(s->wt_token_key, sizeof(s->wt_token_key)) != 0 ||
	    hw_sys_random(s->wt_reset_key, sizeof(s->wt_reset_key)) != 0) {
		HW_ERROR("wt", "no random bytes for the WebTransport keys");
		return -1;
	}
	for (int i = 0; i < s->nworkers; i++) {
		s->workers[i].wt = wt_worker_new(&s->workers[i]);
		if (!s->workers[i].wt) return -1;
	}
	if (cfg->webtransport_cert_dir[0]) {
		// What is in it is read at start like the rest of the configuration; a file that does not
		// load is only that host without a certificate of its own.
		s->wt_dir_seen = file_id(cfg->webtransport_cert_dir);
		s->wt_dir_rescan_ms = hw_now_ms() + WT_DIR_RESCAN_MS;
		if (wt_hosts_scan(s, 0, NULL) != 0) {
			HW_ERROR("wt", "webtransport-cert-dir %s: %s", cfg->webtransport_cert_dir, strerror(errno));
			return -1;
		}
	}
	if (cfg->webtransport_cert[0]) {
		char why[WT_WHY_LEN];
		wt_files_stat(s, s->wt_files_seen);
		memcpy(s->wt_files_tried, s->wt_files_seen, sizeof(s->wt_files_tried));
		if (wt_cert_load(cfg, &s->wt_cert_cur, why, sizeof(why)) != 0) {
			HW_ERROR("wt", "%s", why);
			return -1;
		}
		if (wt_cert_publish(s, 0) != 0) return -1;
	} else {
		wt_cert_tick(s, 0);
		if (!s->wt_cert_cur) return -1;
	}
	// Every worker its socket where the kernel can steer by connection ID; one socket otherwise,
	// whose worker then owns every WebTransport connection.
	const char *host = cfg->webtransport_host[0] ? cfg->webtransport_host : cfg->host;
	uint16_t port = cfg->webtransport_port ? cfg->webtransport_port : s->port;
	int steer = hw_sys_has_udp_steer() && s->nworkers > 1;
	int n = steer ? s->nworkers : 1;
	int fds[256];
	if (n > (int)HW_ARRAY_LEN(fds)) n = (int)HW_ARRAY_LEN(fds); // a CID's first byte names at most 256
	uint16_t bound = 0;
	for (int i = 0; i < n; i++) {
		fds[i] = udp_bind(host, i == 0 ? port : bound, steer, i == 0 ? &bound : NULL);
		// An ephemeral TCP port (port 0, as tests ask) promises nothing about the UDP port of the
		// same number, which another socket may hold: then any UDP port will do.
		if (fds[i] < 0 && i == 0 && errno == EADDRINUSE && !cfg->port && !cfg->webtransport_port) {
			fds[i] = udp_bind(host, 0, steer, &bound);
		}
		if (fds[i] < 0) {
			HW_ERROR("wt", "cannot bind UDP %s:%u for WebTransport: %s", host[0] ? host : "*", port, strerror(errno));
			for (int j = 0; j < i; j++) close(fds[j]);
			return -1;
		}
		// QUIC probes for its datagram size: a probe the path cannot carry must be lost, never
		// sent in fragments that every later packet would then be sent in too.
		if (hw_sys_udp_no_fragment(fds[i]) != 0 && i == 0) {
			HW_WARN("wt", "cannot set don't-fragment on the UDP socket: %s", strerror(errno));
		}
		int want = cfg->socket_buffer_size > 0 ? (int)cfg->socket_buffer_size : WT_SOCKET_BUFFER;
		size_t got = hw_sys_udp_buffers(fds[i], want);
		if (i == 0 && got > 0 && got < (size_t)want) {
			HW_WARN("wt",
			        "UDP receive buffer is %zu bytes, not the %d asked for (net.core.rmem_max): a full one drops "
			        "datagrams, and QUIC then slows the session down",
			        got, want);
		}
	}
	if (steer && hw_sys_udp_steer(fds, (size_t)n) != 0) {
		// Without steering the kernel's hash still keeps a client address on one socket, but a
		// client whose port changes would land elsewhere: one socket is the correct fallback.
		HW_WARN("wt", "cannot steer UDP by connection ID (%s); one worker takes every WebTransport connection",
		        strerror(errno));
		for (int j = 1; j < n; j++) close(fds[j]);
		n = 1;
	}
	for (int i = 0; i < n; i++) {
		if (wt_worker_open(s->workers[i].wt, fds[i]) != 0) {
			HW_ERROR("wt", "worker %d: cannot set up the WebTransport socket: %s", i, strerror(errno));
			for (int j = i; j < n; j++) close(fds[j]);
			return -1;
		}
	}
	s->wt_port = bound;
	HW_INFO("wt", "WebTransport on UDP %s:%u, %d socket%s", host[0] ? host : "*", bound, n, n == 1 ? "" : "s");
	return 0;
}

void wt_worker_free(hw_worker *w) {
	wt_worker *ww = w->wt;
	if (!ww) return;
	if (ww->settle_timer) hw_loop_cancel_timer(w->loop, ww->settle_timer);
	ww->settle_timer = NULL;
	// The connections are freed by the server after this: they only lose their session.
	wt_session *next = ww->sessions;
	ww->sessions = NULL;
	while (next) {
		wt_session *s = next;
		next = s->next;
		s->prev = s->next = NULL; // taken off the list whole; session_free unlinks nothing
		if (s->c) {
			s->c->wt = NULL;
			s->c = NULL;
		}
		session_free(s);
	}
	if (ww->fd >= 0) {
		hw_loop_del_fd(w->loop, ww->fd);
		close(ww->fd);
		ww->fd = -1;
	}
	hw_smap_free(&ww->cids);
	hw_smap_free(&ww->hs_addr);
	free(ww->rx);
	free(ww->tx);
	free(ww->pkt);
	wt_cert_free(ww->cert);
	wt_hosts_unref(ww->hosts);
	free(ww);
	w->wt = NULL;
}
