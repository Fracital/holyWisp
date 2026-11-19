/*
 * One client connection: HTTP upgrade, WebSocket framing, Wisp packet dispatch, the outbound queue
 * toward the client, connection-level backpressure, and the per-client half of the security policy
 * (connect-rate and concurrency limits, bandwidth throttling, flood-violation counting, password
 * auth, reputation). The per-destination half lives in stream.c.
 *
 * Re-entrancy rule: any call that queues bytes to the client may end up in conn_close(). After
 * such a call the caller checks c->closing and returns; the hw_conn itself stays valid until the
 * next loop iteration (conn_free_task), its streams do not.
 */
#include "holywisp/hw.h"
#include "holywisp/log.h"
#include "holywisp/sys.h"
#include "holywisp/webtransport.h"
#include "holywisp/wisp.h"
#include "holywisp/ws.h"

#include "holywisp_webclient.h" // generated: hw_webclient_html[], hw_webclient_html_len
#include "internal.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#ifndef CONN_MAX_READ_PER_EVENT
#define CONN_MAX_READ_PER_EVENT (1024 * 1024)
#endif
#define CONN_WINDOW_MIN 4 // packets granted per CONTINUE however many streams share a client
// What a connection offers each recv until its HTTP head is complete: a head is at most
// HW_HTTP_MAX_REQUEST, and a connection that has sent none of it should not hold 64 KiB.
#define CONN_HEAD_CHUNK 4096
// A busy client's recv room grows from HW_READ_CHUNK to about two of its frames, and at least to
// 256 KiB, more only for a client that sends very large ones. A big room on every connection
// costs throughput as soon as many connections are busy at once.
// Measured on the divide bench CT, 2026-11-17: 256 KiB instead of 128 KiB made one busy stream 5%
// cheaper per server CPU second and ten streams 3.5 to 4%, and lost no row. The gain is in TCP
// segments, not in the syscalls saved: a write to the remote carries about seven 64 KiB packets
// instead of three, each write ends in a short segment, and the server sent 5% fewer segments per
// MiB. 512 KiB and 1 MiB won the one-stream row the same and lost 5 to 6% with ten streams: their
// half-megabyte writes per stream went out in more and smaller segments, apparently because they
// outgrew the remotes' receive windows. A busy connection holds up to about 0.4 MiB more for it
// (peak RSS at 8 connections x 4 streams: 7 to 10 MiB); an idle one nothing.
#define CONN_READ_CHUNK_BASE (256 * 1024)
#define CONN_READ_CHUNK_MAX  (2 * 1024 * 1024)
// A DATA frame at least this large is forwarded piece by piece while it arrives instead of being
// reassembled first: the stream sees the same bytes sooner and they stay cache-warm.
#define CONN_PT_MIN    (128 * 1024)
#define CONN_WBUF_KEEP (4 * 1024 * 1024) // a drained write queue keeps at most this much allocated
// The most payload one DATA packet toward the client carries, whatever max-message-size allows.
// A WebSocket message is handed to the application whole, so the client has to hold all of it:
// megabyte packets (a relay pipe holds that much) made its buffer outgrow its cache and cost the
// client and the echo behind it 20 to 40% more per byte, while the server saved nothing by them.
// On the bench VM 128 KiB won the multi-connection rows by 8 to 9% and lost none.
#define CONN_FRAME_MAX HW_FRAME_MAX
// Frames are not written one by one while the queue is smaller than this: they wait for the end of
// the loop's batch and leave in one send (conn_kick). Anything larger is worth its own write.
#define CONN_DEFER_MAX (16 * 1024)

static void conn_io_cb(hw_loop *loop, int fd, unsigned events, void *ud);
static void marks_free(hw_conn *c);

// ---------------------------------------------------------------------------------- lifecycle

static int free_sigdet_visit(const char *key, void *value, void *ud) {
	free(value);
	return 0;
}

static void conn_unlink(hw_conn *c) {
	if (c->lprev) {
		c->lprev->lnext = c->lnext;
	} else if (c->w->conns == c) {
		c->w->conns = c->lnext;
	}
	if (c->lnext) c->lnext->lprev = c->lprev;
	c->lprev = c->lnext = NULL;
}

static void conn_release(hw_conn *c) {
	atomic_fetch_sub(&c->w->load, 1);
	hw_buf_free(&c->rbuf);
	hw_buf_free(&c->wbuf);
	free(c->marks);
	hw_buf_free(&c->frag);
	hw_buf_free(&c->pri);
	hw_map_free(&c->streams);
	hw_smap_each(&c->sigdets, free_sigdet_visit, NULL);
	hw_smap_free(&c->sigdets);
	free(c);
}

static void conn_free_task(hw_loop *loop, void *ud) {
	hw_conn *c = ud;
	conn_unlink(c);
	conn_release(c);
}

// Called by hw_server_free after the worker threads have joined: tear down whatever is still open
// and free it in place, since no loop will run the deferred free.
void conn_shutdown_free(hw_conn *c) {
	if (!c->closing) conn_close(c); // posts a free task that will never run; we free below instead
	conn_unlink(c);
	conn_release(c);
}

static void handshake_timeout_cb(hw_loop *loop, void *ud) {
	hw_conn *c = ud;
	c->handshake_timer = NULL;
	HW_DEBUG("conn", "%s: handshake timeout", c->peer);
	conn_close(c);
}

// Connections that have not sent their whole HTTP head are counted by nothing at upgrade time, and
// a client that opens them and sends nothing holds a descriptor each until the handshake timeout:
// enough of them push accept into EMFILE for everyone. max-handshakes-per-ip bounds how many one
// address holds at once. It is counted by the socket's peer, from accept, before a byte is read,
// so a trusted proxy (every client behind it has its address) is not counted at all. 0: refused.
static int conn_head_admit(hw_conn *c) {
	hw_server *srv = c->w->server;
	const hw_server_config *cfg = &srv->cfg;
	if (!srv->heads_per_ip) return 1;
	if (hw_cidr_any_contains(cfg->trusted_proxies, cfg->trusted_proxy_count, (const struct sockaddr *)&c->peer_addr)) {
		return 1;
	}
	int r = hw_gauge_acquire(srv->heads_per_ip, c->ip);
	if (r == 0) return 0;
	c->head_slot = r == 1;
	return 1;
}

// The head is in (or the connection is going): its slot goes back, under the key it was taken by,
// before the trusted headers can change c->ip.
static void conn_head_done(hw_conn *c) {
	if (!c->head_slot) return;
	hw_gauge_release(c->w->server->heads_per_ip, c->ip);
	c->head_slot = 0;
}

void conn_accept(hw_worker *w, int fd, const struct sockaddr *peer) {
	hw_conn *c = calloc(1, sizeof(*c));
	if (!c) {
		atomic_fetch_sub(&w->load, 1);
		close(fd);
		return;
	}
	c->w = w;
	c->fd = fd;
	c->state = CONN_HTTP;
	c->stream_cap = w->server->cfg.max_streams_per_conn;
	c->read_chunk = HW_READ_CHUNK;
	hw_buf_init(&c->rbuf);
	hw_buf_init(&c->wbuf);
	hw_buf_init(&c->frag);
	hw_buf_init(&c->pri);
	hw_map_init(&c->streams);
	hw_smap_init(&c->sigdets);
	memcpy(&c->peer_addr, peer, peer->sa_family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6));
	hw_addr_str(peer, c->peer, sizeof(c->peer));
	// Policy IP defaults to the socket peer; the upgrade may replace it from a trusted header.
	hw_addr_ip_str(peer, c->ip, sizeof(c->ip));
	if (!conn_head_admit(c)) {
		static const char busy[] = "HTTP/1.1 429 Too Many Requests\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
		ssize_t r = send(fd, busy, sizeof(busy) - 1, HW_MSG_NOSIGNAL | MSG_DONTWAIT); // best effort
		(void)r;
		HW_DEBUG("conn", "%s: refused, too many connections still in their HTTP head", c->peer);
		HW_STAT_INC(w->server, refused_connection_limit);
		atomic_fetch_sub(&w->load, 1);
		close(fd);
		free(c);
		return;
	}
	server_tune_socket(w->server, fd, 1);
	if (w->server->client_rcvbuf > 0) {
		setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &w->server->client_rcvbuf, sizeof(w->server->client_rcvbuf));
	}
	if (hw_loop_add_fd(w->loop, fd, HW_EV_READ, conn_io_cb, c) != 0) {
		HW_WARN("conn", "%s: cannot watch fd: %s", c->peer, strerror(errno));
		conn_head_done(c);
		atomic_fetch_sub(&w->load, 1);
		close(fd);
		free(c);
		return;
	}
	c->handshake_timer = hw_loop_add_timer(w->loop, (uint64_t)w->server->cfg.handshake_timeout_ms, 0,
	                                       handshake_timeout_cb, c);
	c->lnext = w->conns;
	if (w->conns) w->conns->lprev = c;
	w->conns = c;
	atomic_fetch_add(&w->server->connections_total, 1);
	atomic_fetch_add(&w->server->connections_active, 1);
	HW_DEBUG("conn", "%s: accepted on worker %d", c->peer, w->index);
}

static int close_stream_visit(uint32_t key, void *value, void *ud) {
	stream_close(value, HW_CLOSE_UNKNOWN, 0);
	return 0;
}

void conn_close(hw_conn *c) {
	if (c->closing) return;
	c->closing = 1;
	c->state = CONN_CLOSED;
	if (c->handshake_timer) {
		hw_loop_cancel_timer(c->w->loop, c->handshake_timer);
		c->handshake_timer = NULL;
	}
	if (c->throttle_timer) {
		hw_loop_cancel_timer(c->w->loop, c->throttle_timer);
		c->throttle_timer = NULL;
	}
	if (c->auth_req) {
		auth_cancel(c->auth_req);
		c->auth_req = NULL;
	}
	if (c->fd >= 0) {
		hw_loop_del_fd(c->w->loop, c->fd);
		close(c->fd);
		c->fd = -1;
	}
	hw_map_each(&c->streams, close_stream_visit, NULL);
	marks_free(c); // after the streams: every pipe still queued is an orphan now
	if (c->wt) {
		// What the streams' closing queued is on its way first: the session closes behind it.
		wt_session *s = c->wt;
		c->wt = NULL;
		wt_conn_detach(s, c->wt_code);
	}
	if (c->conn_slot) {
		hw_semaphore_release(&c->w->server->connections);
		c->conn_slot = 0;
	}
	if (c->ip_slot) {
		hw_gauge_release(c->w->server->conns_per_ip, c->ip);
		c->ip_slot = 0;
	}
	conn_head_done(c);
	if (c->budget_held) { // taken under this c->ip: it does not change after the upgrade
		hw_budget_give(c->w->server->queue_budget, c->ip, c->budget_held);
		c->budget_held = 0;
	}
	atomic_fetch_sub(&c->w->server->connections_active, 1);
	if (c->ws_counted) atomic_fetch_sub(&c->w->server->ws_connections_active, 1);
	HW_DEBUG("conn", "%s: closed", c->peer);
	hw_loop_post(c->w->loop, conn_free_task, c);
}

// ---------------------------------------------------------------------------------- policy helpers

void conn_rep_source(hw_conn *c, enum hw_rep_event e) {
	if (c->w->server->reputation) hw_reputation_add_source(c->w->server->reputation, c->ip, e);
}

void conn_rep_dest(hw_conn *c, const char *dest, enum hw_rep_event e) {
	if (c->w->server->reputation) hw_reputation_add_dest(c->w->server->reputation, dest, e, c->ip);
}

int conn_violation(hw_conn *c, const char *reason) {
	int limit = c->w->server->cfg.flood.ws_close_after_violations;
	conn_rep_source(c, HW_REP_PROTOCOL_VIOLATION);
	if (limit <= 0) return 0;
	if (++c->violations >= limit) {
		HW_WARN("flood", "%s: closing after %d violations (last: %s)", c->peer, c->violations, reason);
		HW_STAT_INC(c->w->server, ws_closed_violations);
		conn_close(c);
		return 1;
	}
	return 0;
}

// Reads from the client stop for five reasons: the bandwidth throttle, too much queued toward slow
// remotes (conn-queue-max), too much queued toward the client itself, which is a client that sends
// but does not read (conn_backpressure), the server-wide queue budget or its per-IP share spent
// (conn_budget_sync), and a plain HTTP reply on its way out, after which nothing the client sends
// is wanted (reading it would only grow rbuf).
static int conn_reads_stopped(const hw_conn *c) {
	return c->throttled || c->read_paused || c->wr_stalled || c->budget_paused || c->state == CONN_HTTP_REPLY;
}

// The client socket's event mask follows that and one more bit: writes are wanted while wbuf (or
// a pipe) has bytes.
static void conn_apply_events(hw_conn *c) {
	if (c->closing) return;
	if (c->wt) {
		// A session's reads are QUIC credit: withholding it is what not reading a socket is.
		wt_conn_pause(c->wt, conn_reads_stopped(c));
		return;
	}
	if (c->fd < 0) return;
	unsigned ev = 0;
	if (!conn_reads_stopped(c)) ev |= HW_EV_READ;
	if (c->write_armed) ev |= HW_EV_WRITE;
	hw_loop_mod_fd(c->w->loop, c->fd, ev);
}

static int pause_visit(uint32_t key, void *value, void *ud) {
	stream_pause(value);
	return 0;
}

static int resume_visit(uint32_t key, void *value, void *ud) {
	hw_stream *s = value;
	if (!(s->conn->lane_paused >> s->lane & 1u)) stream_resume(s); // its lane's queue holds it still
	return 0;
}

// The streams read from their remotes unless the client's send queue is over its mark, the
// connection is over its bandwidth or it may not queue more (the queue budget). `paused` is what
// stream.c looks at; this keeps it and every stream's read interest equal to the three reasons.
static void conn_sync_streams(hw_conn *c) {
	int want = c->bp_paused || c->throttled || c->budget_paused;
	if (want == c->paused) return;
	c->paused = want;
	hw_map_each(&c->streams, want ? pause_visit : resume_visit, NULL);
}

static void throttle_wake_cb(hw_loop *loop, void *ud) {
	hw_conn *c = ud;
	c->throttle_timer = NULL;
	c->throttled = 0;
	conn_apply_events(c);
	conn_sync_streams(c);
}

void conn_charge_bandwidth(hw_conn *c, size_t bytes) {
	if (!c->w->server->bandwidth || c->closing) return;
	// Charged even while paused: the bytes of a pass that was under way when the pause began still
	// moved, and skipping them made every pause too short (and a download free, since its bytes
	// arrive while the client's reads are the only thing stopped).
	uint64_t wait = hw_bandwidth_charge(c->w->server->bandwidth, c->ip, bytes);
	if (wait == 0) return;
	// Both directions stop until the virtual clock catches up: reads from the client, and reads
	// from every remote. Nothing is dropped; what is queued still drains.
	if (c->throttle_timer) hw_loop_cancel_timer(c->w->loop, c->throttle_timer);
	c->throttle_timer = hw_loop_add_timer(c->w->loop, wait, 0, throttle_wake_cb, c);
	if (c->throttled) return;
	c->throttled = 1;
	conn_apply_events(c);
	conn_sync_streams(c);
}

// One stream on a connection may have the whole advertised window in flight; ten streams with
// the whole window each would make the server buffer tens of megabytes toward slow remotes and
// pay for it in copies. The budget (upload-window, by default the client's own send-queue mark)
// keeps the sum near one pipeline, which is plenty for one stream and keeps many streams on the
// fast path. It is its own key because the mark is also how long a small reply waits behind a
// download, and a short queue there is not a reason for a slow upload.
//
// The budget is shared by the streams that upload, not by every stream open: a browser keeps
// dozens of idle keep-alive sockets and UDP streams on one connection, and dividing by them gave
// an upload beside 30 idle streams 4 packets per refill where it should have had 128. A stream
// counts from the window it spends for UPLOAD_ACTIVE_MS to twice that (two periods, so that no
// stream drops out at a period's edge), and for as long as its refill is held behind a slow
// remote, which is when it holds the server's memory. Each share is in packets of the size that
// stream sends, not the connection's average, which a stream of small packets would drag down.
// O(1): a stream is in one of three counts, and a new period moves the current one to the last.
#define UPLOAD_ACTIVE_MS 2000

static void conn_upload_unlink(hw_conn *c, hw_stream *s) {
	if (s->up_held) {
		c->up_held--;
		s->up_held = 0;
	} else if (s->up_epoch != 0 && s->up_epoch == c->up_epoch) {
		c->up_cur--;
	} else if (s->up_epoch != 0 && s->up_epoch + 1 == c->up_epoch) {
		c->up_prev--;
	}
	s->up_epoch = 0;
}

static void conn_upload_mark(hw_conn *c, hw_stream *s) {
	uint64_t epoch = hw_now_ms() / UPLOAD_ACTIVE_MS + 2; // never 0 or 1: 0 is "never"
	conn_upload_unlink(c, s);
	if (epoch != c->up_epoch) {
		c->up_prev = epoch == c->up_epoch + 1 ? c->up_cur : 0;
		c->up_cur = 0;
		c->up_epoch = epoch;
	}
	s->up_epoch = epoch;
	c->up_cur++;
}

void conn_upload_hold(hw_conn *c, hw_stream *s, int held) {
	if (!held) {
		conn_upload_mark(c, s);
		return;
	}
	conn_upload_unlink(c, s);
	s->up_held = 1;
	c->up_held++;
}

void conn_upload_forget(hw_conn *c, hw_stream *s) {
	conn_upload_unlink(c, s);
}

uint32_t conn_window(hw_conn *c, hw_stream *s) {
	const hw_server *srv = c->w->server;
	conn_upload_mark(c, s);
	size_t streams = (size_t)c->up_cur + c->up_prev + c->up_held; // s is one of them
	size_t pkt = s->pkt_avg ? s->pkt_avg : c->pkt_avg ? c->pkt_avg : 64 * 1024;
	size_t w = cfg_upload_window(&srv->cfg) / streams / pkt;
	if (w < CONN_WINDOW_MIN) w = CONN_WINDOW_MIN;
	if (w > srv->window) w = srv->window;
	return (uint32_t)w;
}

// ---- the queue budget
//
// Every queue is bounded per stream or per connection, and the connections of one address only
// by max-concurrent-connections-per-ip, which is thousands: on their own, one address could make
// the server hold that many times conn-queue-max. server-queue-max bounds what every connection
// together queues toward its client and its remotes, and server-queue-max-per-ip what those of
// one client address do, so that no address can take the whole of it.
//
// The budget is shared by all workers and locked, so a connection takes and gives back whole
// chunks of it, never bytes: it holds what it queues rounded down to a chunk, takes a chunk when
// its queues pass the next one and gives back only once they are a chunk below what it holds,
// or all of it once they are under one chunk.
// Below one chunk it never touches the lock, and a queue swinging between the backpressure marks
// costs a few locked operations per megabyte that moves. What a connection queues uncounted is
// under one chunk.
//
// A refused take is a pause, never a drop: the connection stops reading its client and its
// remotes (conn_reads_stopped, conn_sync_streams), and everything it has queued still drains.
// It goes on as soon as it can take again or its own queues have drained to what it holds, so
// it needs no timer: draining is what calls this. A connection whose peers never read is held
// for as long as they do not, and closed by client-write-timeout-s for its client.
#define BUDGET_CHUNK (1024 * 1024)

static void conn_budget_sync(hw_conn *c) {
	hw_budget *b = c->w->server->queue_budget;
	// Only an upgraded connection: c->ip may still change before that, and an HTTP reply is small.
	if (!b || c->closing || c->state != CONN_WS) return;
	uint64_t queued = (uint64_t)c->queued_out + c->q_client;
	uint64_t want = queued / BUDGET_CHUNK * BUDGET_CHUNK;
	int pause = 0;
	if (want > c->budget_held) {
		int r = hw_budget_take(b, c->ip, want - c->budget_held);
		if (r == 1) {
			c->budget_held = want;
		} else if (r == 0) {
			pause = 1;
		} // -1: no memory for the count, let through uncounted (fail open)
	} else if (c->budget_held > want + BUDGET_CHUNK || (want == 0 && c->budget_held > 0)) {
		// One chunk is kept against a queue that swings, but not by a queue that has drained:
		// idle connections would hold a chunk each of their address's share.
		uint64_t keep = want ? want + BUDGET_CHUNK : 0;
		hw_budget_give(b, c->ip, c->budget_held - keep);
		c->budget_held = keep;
	}
	if (pause == c->budget_paused) return;
	c->budget_paused = pause;
	if (pause) {
		HW_DEBUG("conn", "%s (%s): %llu bytes queued, over the queue budget: pausing", c->peer, c->ip,
		         (unsigned long long)queued);
		HW_STAT_INC(c->w->server, queue_budget_pauses);
	}
	conn_apply_events(c);
	conn_sync_streams(c);
}

void conn_queue_add(hw_conn *c, size_t n) {
	c->queued_out += n;
	if (!c->read_paused && c->queued_out > c->w->server->cfg.conn_queue_max) {
		HW_DEBUG("conn", "%s: %zu bytes queued toward remotes, pausing reads", c->peer, c->queued_out);
		c->read_paused = 1;
		conn_apply_events(c);
	}
	conn_budget_sync(c);
}

void conn_queue_sub(hw_conn *c, size_t n) {
	c->queued_out -= n < c->queued_out ? n : c->queued_out;
	if (c->read_paused && c->queued_out < c->w->server->cfg.conn_queue_max / 2) {
		c->read_paused = 0;
		conn_apply_events(c);
	}
	conn_budget_sync(c);
}

// ---------------------------------------------------------------------------------- writing

static int arm_write(hw_conn *c, int on) {
	if (c->write_armed == on) return 0;
	c->write_armed = on;
	conn_apply_events(c);
	return 0;
}

// ---- relay pipes
//
// The kernel charges pipe memory to the user and, past fs.pipe-user-pages-soft, hands out pipes of
// two pages that cannot be enlarged. A pipe that small turns every splice into an 8 KiB relay, far
// slower than copying, so anything under PIPE_MIN is refused and the stream copies instead (and
// the worker waits a while before asking again: the pressure may come from other processes of
// the same user, or from this server's own bulk streams). A pipe costs two descriptors and is
// opened only when a stream first goes bulk.
#define PIPE_WANT     (1024 * 1024)
#define PIPE_MIN      (256 * 1024)
#define PIPE_RETRY_MS 2000
#define PIPE_FILLS    4 // splices per frame: a socket hands a large backlog over in pieces

static hw_spipe *spipe_open(hw_worker *w, hw_stream *s) {
	uint64_t now = hw_now_ms();
	if (now < w->pipe_retry_ms) return NULL;
	hw_spipe *p = calloc(1, sizeof(*p));
	if (!p) return NULL;
	if (hw_sys_relay_pipe(p->fd, PIPE_WANT, PIPE_MIN, &p->size) != 0) {
		// ENOBUFS is the pipe memory limit; ENOTSUP a kernel that does not splice.
		HW_DEBUG("server", "worker %d: no relay pipe of %d bytes (%s); copying", w->index, PIPE_MIN, strerror(errno));
		free(p);
		w->pipe_retry_ms = now + PIPE_RETRY_MS;
		return NULL;
	}
	p->stream = s;
	return p;
}

static void spipe_free(hw_spipe *p) {
	close(p->fd[0]);
	close(p->fd[1]);
	free(p);
}

void conn_pipe_drop(hw_stream *s) {
	hw_spipe *p = s->pipe;
	if (!p) return;
	s->pipe = NULL;
	if (p->pending > 0) {
		p->stream = NULL; // its payload is already framed on the wire: the queue finishes and frees it
	} else {
		spipe_free(p);
	}
}

static int mark_push(hw_conn *c, hw_spipe *p, size_t n) {
	if (c->mark_count == c->mark_cap) {
		size_t cap = c->mark_cap ? c->mark_cap * 2 : 8;
		hw_pipe_mark *m = malloc(cap * sizeof(*m));
		if (!m) return -1;
		for (size_t i = 0; i < c->mark_count; i++) m[i] = c->marks[(c->mark_head + i) % c->mark_cap];
		free(c->marks);
		c->marks = m;
		c->mark_head = 0;
		c->mark_cap = cap;
	}
	hw_pipe_mark *m = &c->marks[(c->mark_head + c->mark_count) % c->mark_cap];
	m->at = c->wsent + hw_buf_avail(&c->wbuf);
	m->n = n;
	m->p = p;
	c->mark_count++;
	c->pipe_bytes += n;
	p->pending = n;
	return 0;
}

// The head mark's payload is on the wire (or the connection is going away).
static void mark_pop(hw_conn *c) {
	hw_pipe_mark *m = &c->marks[c->mark_head];
	hw_spipe *p = m->p;
	c->pipe_bytes -= m->n;
	c->mark_head = (c->mark_head + 1) % c->mark_cap;
	c->mark_count--;
	p->pending = 0;
	if (!p->stream) {
		spipe_free(p);
	} else if (!c->closing) {
		stream_unpark(p->stream);
	}
}

static void marks_free(hw_conn *c) {
	while (c->mark_count > 0) mark_pop(c);
}

// Everything queued toward the client: the write buffer plus the payloads still in pipes.
static size_t conn_queued(const hw_conn *c) {
	if (c->wt) return wt_conn_queued(c->wt); // the session's queue stands in for wbuf
	return hw_buf_avail(&c->wbuf) + c->pipe_bytes + hw_buf_avail(&c->pri);
}

typedef struct {
	uint32_t lanes;
	int pause;
} lane_visit_arg;

static int lane_visit(uint32_t key, void *value, void *ud) {
	hw_stream *s = value;
	const lane_visit_arg *a = ud;
	if (!(a->lanes >> s->lane & 1u)) return 0;
	if (a->pause) {
		stream_pause(s);
	} else if (!s->conn->paused) {
		stream_resume(s);
	}
	return 0;
}

// WebTransport with lanes: each lane's own queue pauses the remotes of the streams on it past the
// high-water mark and resumes them under a quarter of it, so a lane that waits for the client's
// credit (or a lost packet) holds up only its own streams. The session's mark, past which every
// stream pauses as on a WebSocket, is the open lanes' marks together. Lane 0 alone is the
// WebSocket rule, and nothing pauses per lane. Returns the session's mark.
static size_t conn_wt_lane_marks(hw_conn *c, size_t high) {
	uint32_t open = wt_conn_lanes(c->wt);
	uint32_t want = 0;
	size_t n = 0;
	if (open & ~1u) {
		for (int i = 0; i < HW_WT_LANES_MAX; i++) {
			uint32_t bit = 1u << i;
			if (!(open & bit)) continue;
			n++;
			size_t q = wt_conn_lane_queued(c->wt, i);
			if (q > high || ((c->lane_paused & bit) && q >= high / 4)) want |= bit;
		}
	}
	if (want != c->lane_paused) {
		lane_visit_arg on = {want & ~c->lane_paused, 1};
		lane_visit_arg off = {c->lane_paused & ~want, 0};
		c->lane_paused = want;
		if (on.lanes) hw_map_each(&c->streams, lane_visit, &on);
		if (off.lanes) hw_map_each(&c->streams, lane_visit, &off);
	}
	return n ? n * high : high;
}

static void conn_backpressure(hw_conn *c) {
	size_t queued = conn_queued(c);
	size_t high = c->w->server->cfg.ws_write_high_water;
	c->q_client = queued;
	conn_budget_sync(c);
	if (c->closing) return;
	if (c->wt) high = conn_wt_lane_marks(c, high);
	if (!c->bp_paused && queued > high) {
		c->bp_paused = 1;
		conn_sync_streams(c);
	} else if (c->bp_paused && queued < high / 4) {
		c->bp_paused = 0;
		conn_sync_streams(c);
	}
	// Pausing the remotes bounds what they add, not what the client makes the server say: every
	// ping is answered and every refused CONNECT gets a CLOSE, so a client that sends those and
	// never reads would grow this queue without limit. At twice the mark the server stops
	// listening to it until it has read down to the mark. No reply is larger than what caused it,
	// so the overshoot is one read. A client that never reads again is closed by the sweep.
	if (!c->wr_stalled && queued > 2 * high) {
		HW_DEBUG("conn", "%s: %zu bytes queued for a client that is not reading, pausing its reads", c->peer, queued);
		c->wr_stalled = 1;
		conn_apply_events(c);
	} else if (c->wr_stalled && queued <= high) {
		c->wr_stalled = 0;
		conn_apply_events(c);
	}
}

static void ws_fail(hw_conn *c, uint16_t code);

void conn_sweep(hw_worker *w) {
	const hw_server_config *cfg = &w->server->cfg;
	uint64_t now = hw_now_ms();
	uint64_t write_ms = (uint64_t)cfg->client_write_timeout_s * 1000;
	uint64_t idle_ms = (uint64_t)cfg->idle_timeout_s * 1000;
	hw_conn *next;
	for (hw_conn *c = w->conns; c; c = next) {
		next = c->lnext; // conn_close leaves the list alone: the connection is unlinked when it is freed
		if (c->closing) continue;
		if (c->heard || c->active_ms == 0) c->active_ms = now;
		c->heard = 0;
		if (c->wrote || conn_queued(c) == 0) {
			c->stall_ms = 0;
		} else if (c->stall_ms == 0) {
			c->stall_ms = now;
		} else if (write_ms > 0 && now - c->stall_ms >= write_ms) {
			HW_INFO("conn", "%s: closing, %zu bytes queued and the client has read nothing for %d s", c->peer,
			        conn_queued(c), cfg->client_write_timeout_s);
			conn_close(c);
			continue;
		}
		c->wrote = 0;
		if (idle_ms > 0 && c->state == CONN_WS && hw_map_count(&c->streams) == 0 && now - c->active_ms >= idle_ms) {
			HW_DEBUG("conn", "%s: idle for %d s with no streams, closing", c->peer, cfg->idle_timeout_s);
			ws_fail(c, 1001);
		}
	}
}

// The wire length of a frame the server wrote (hw_ws_write_header: unmasked, the shortest length
// form), from its header, which wbuf always holds whole.
static uint64_t frame_wire_len(const uint8_t *p) {
	uint8_t code = p[1] & 0x7f;
	if (code < 126) return 2 + (uint64_t)code;
	if (code == 126) return 4 + ((uint64_t)p[2] << 8 | p[3]);
	uint64_t n = 0;
	for (int i = 0; i < 8; i++) n = n << 8 | p[2 + i];
	return 10 + n;
}

// n bytes from the head of wbuf have just been sent (they are still in it): move fr_end over the
// frames they began. Only the head mark can lie inside one of them, since a send stops at it, and
// a frame with a mark inside ends its part in wbuf there: its payload follows from the pipe. One
// header read per frame, and none for the bytes of a frame already begun.
static void conn_frames_walk(hw_conn *c, size_t n) {
	if (c->state != CONN_WS) return; // the HTTP head is not frames; http_process sets fr_end past it
	uint64_t to = c->wsent + n;
	const hw_pipe_mark *m = c->mark_count ? &c->marks[c->mark_head] : NULL;
	while (c->fr_end < to) {
		uint64_t end = c->fr_end + frame_wire_len(hw_buf_head(&c->wbuf) + (c->fr_end - c->wsent));
		if (m && m->at > c->fr_end && m->at < end) end = m->at;
		c->fr_end = end;
	}
}

// The queue is wbuf with pipe payloads spliced in at the marks: bytes are sent from wbuf until
// the head mark's position, then that pipe is emptied into the socket, and so on. A frame header
// is always the last thing in wbuf before its mark, so frames never interleave.
//
// pri goes ahead of all that at the next frame boundary: where the frame under way has ended in
// wbuf and no pipe payload is owed at that point (a mark at wsent is the middle of a frame). Once a
// frame of pri has begun, pri is sent to its end before anything else.
//
// After a short write or a large splice the loops here and in conn_splice_data ask the kernel
// again, and about one call in eight comes back EAGAIN. That looks like waste and is not: taking
// the retries out (stop at the first short result, let epoll report the rest) removed 11% of the
// syscalls and made one busy connection 3 to 4% slower, because the retry that does find bytes
// saves a whole trip through epoll_wait.
void conn_flush(hw_conn *c) {
	if (c->closing) return;
	if (c->wt) {
		wt_conn_flush(c->wt);
		conn_backpressure(c);
		return;
	}
	for (;;) {
		size_t avail = hw_buf_avail(&c->wbuf);
		hw_pipe_mark *m = c->mark_count ? &c->marks[c->mark_head] : NULL;
		size_t ahead = hw_buf_avail(&c->pri);
		ssize_t n;
		if (ahead > 0 && (c->pri_mid || (!(m && m->at == c->wsent) && (c->fr_end <= c->wsent || avail == 0)))) {
			// pri, and behind it in the same call what wbuf holds up to its head mark: what goes
			// ahead costs no syscall of its own. (The casts: iovec is not const, sendmsg only reads.)
			struct iovec iov[2] = {{.iov_base = (void *)(uintptr_t)hw_buf_head(&c->pri), .iov_len = ahead}};
			size_t more = avail;
			if (m && m->at - c->wsent < more) more = (size_t)(m->at - c->wsent);
			iov[1].iov_base = (void *)(uintptr_t)hw_buf_head(&c->wbuf);
			iov[1].iov_len = more;
			struct msghdr mh = {.msg_iov = iov, .msg_iovlen = more > 0 ? 2 : 1};
			n = sendmsg(c->fd, &mh, HW_MSG_NOSIGNAL | MSG_DONTWAIT);
			if (n > 0) {
				size_t took = (size_t)n < ahead ? (size_t)n : ahead;
				hw_buf_consume(&c->pri, took);
				c->pri_mid = took < ahead;
				size_t rest = (size_t)n - took;
				if (rest > 0) {
					conn_frames_walk(c, rest);
					hw_buf_consume(&c->wbuf, rest);
					c->wsent += (uint64_t)rest;
				}
				c->wrote = 1;
				continue;
			}
		} else if (m && m->at == c->wsent) {
			n = hw_sys_splice(m->p->fd[0], c->fd, m->n);
			if (n > 0) {
				m->n -= (size_t)n;
				m->p->pending -= (size_t)n;
				c->pipe_bytes -= (size_t)n;
				c->wrote = 1;
				if (m->n == 0) mark_pop(c);
				continue;
			}
			if (n == 0) {
				// The pipe holds less than was promised in the frame header. That cannot be
				// repaired on the wire.
				HW_WARN("conn", "%s: relay pipe ran dry with %zu bytes owed", c->peer, m->n);
				conn_close(c);
				return;
			}
		} else if (avail > 0) {
			size_t want = avail;
			int flags = HW_MSG_NOSIGNAL | MSG_DONTWAIT;
			if (m && m->at - c->wsent <= want) {
				want = (size_t)(m->at - c->wsent);
				flags |= HW_MSG_MORE; // a payload follows from its pipe
			}
			if (ahead > 0 && c->fr_end - c->wsent < want) {
				want = (size_t)(c->fr_end - c->wsent); // to the end of this frame: pri goes next
				flags &= ~HW_MSG_MORE;
			}
			n = send(c->fd, hw_buf_head(&c->wbuf), want, flags);
			if (n > 0) {
				conn_frames_walk(c, (size_t)n);
				hw_buf_consume(&c->wbuf, (size_t)n);
				c->wsent += (uint64_t)n;
				c->wrote = 1;
				continue;
			}
		} else {
			break;
		}
		if (n < 0 && errno == EINTR) continue;
		if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			arm_write(c, 1);
			conn_backpressure(c);
			return;
		}
		HW_DEBUG("conn", "%s: send: %s", c->peer, strerror(errno));
		conn_close(c);
		return;
	}
	arm_write(c, 0);
	hw_buf_shrink(&c->wbuf, CONN_WBUF_KEEP);
	hw_buf_shrink(&c->pri, CONN_DEFER_MAX);
	conn_backpressure(c);
	if (c->state == CONN_HTTP_REPLY) conn_close(c);
}

// Frames were just queued. A large queue, or one with a pipe payload in it, is written now. A
// small one waits on the worker's flush list for conn_batch_end, so the CONTINUE, CLOSE and small
// DATA frames that several streams produce in one pass over the loop's events cost one send and
// one segment instead of one each. With the socket already full (write_armed) the write is still
// attempted, as it always was: it often finds room before epoll gets round to saying so.
static void conn_kick(hw_conn *c) {
	if (c->closing) return;
	if (c->mark_count > 0 || hw_buf_avail(&c->wbuf) >= CONN_DEFER_MAX || c->write_armed) {
		conn_flush(c);
		return;
	}
	if (!c->flush_queued) {
		c->flush_queued = 1;
		c->flush_next = c->w->flush_head;
		c->w->flush_head = c;
	}
}

// Every connection on the list is still allocated: one that closed during this batch is freed by a
// task posted to the next iteration, and the list is emptied here before that task can run.
void conn_batch_end(hw_loop *loop, void *ud) {
	hw_worker *w = ud;
	hw_conn *c = w->flush_head;
	w->flush_head = NULL;
	while (c) {
		hw_conn *next = c->flush_next;
		c->flush_queued = 0;
		c->flush_next = NULL;
		conn_flush(c); // returns at once when the connection is closing
		c = next;
	}
}

// The payload of one DATA packet toward this client: within max-message-size and CONN_FRAME_MAX.
static size_t frame_payload_max(const hw_conn *c) {
	size_t max = c->w->server->cfg.max_message_size - HW_WISP_HEADER_LEN;
	if (max > CONN_FRAME_MAX) max = CONN_FRAME_MAX;
	return max < 1 ? 1 : max;
}

ssize_t conn_splice_data(hw_conn *c, hw_stream *s, size_t max) {
	if (c->throttled || c->wt) return -2; // a session's bytes are copied into QUIC packets, never spliced
	hw_spipe *p = s->pipe;
	if (!p) {
		p = s->pipe = spipe_open(c->w, s);
		if (!p) return -2;
	}
	if (p->pending > 0) return -3;
	size_t cap = frame_payload_max(c);
	if (cap > p->size) cap = p->size;
	if (cap > max) cap = max; // the stream's credit: never a byte more is taken from the remote
	size_t got = 0;
	for (int i = 0; i < PIPE_FILLS && got < cap; i++) {
		ssize_t n = hw_sys_splice(s->fd, p->fd[1], cap - got);
		if (n > 0) {
			got += (size_t)n;
			if ((size_t)n < HW_READ_CHUNK) break; // a small piece: the socket is drained
			continue;
		}
		if (got > 0) break; // EOF or an error after some bytes: the next call reports it
		if (n < 0 && (errno == EINVAL || errno == ENOSYS)) return -2; // not spliceable: copy instead
		return n;
	}

	uint8_t hdr[HW_WS_MAX_HEADER + HW_WISP_HEADER_LEN];
	size_t hlen = hw_ws_write_header(hdr, 1, HW_WS_BINARY, HW_WISP_HEADER_LEN + (uint64_t)got, NULL);
	hw_wisp_write_header(hdr + hlen, HW_WISP_DATA, s->id);
	hlen += HW_WISP_HEADER_LEN;
	if (hw_buf_append(&c->wbuf, hdr, hlen) != 0 || mark_push(c, p, got) != 0) {
		// The payload is in the pipe but cannot be framed: nothing sane can follow on this stream.
		conn_close(c);
		return (ssize_t)got;
	}
	atomic_fetch_add(&c->w->bytes_out, (uint64_t)got);
	conn_charge_bandwidth(c, got);
	conn_kick(c);
	return (ssize_t)got;
}

// Reserve room for a frame header + payload of `len` and write the header. Returns the payload
// pointer or NULL (ENOMEM; the connection is closed).
static uint8_t *frame_begin(hw_conn *c, size_t len) {
	size_t hlen = hw_ws_header_len(len, 0);
	if (hw_buf_reserve(&c->wbuf, hlen + len) != 0) {
		conn_close(c);
		return NULL;
	}
	uint8_t *p = hw_buf_tail(&c->wbuf);
	hw_ws_write_header(p, 1, HW_WS_BINARY, len, NULL);
	hw_buf_commit(&c->wbuf, hlen + len);
	return p + hlen;
}

// The lane a packet for stream id goes on over WebTransport: stream 0's is lane 0, an open
// stream's is its own, and one for a stream that is not open (the CLOSE that refuses a CONNECT)
// goes where the packet that caused it came from.
static int conn_wt_lane(const hw_conn *c, uint32_t id) {
	if (id == 0) return 0;
	const hw_stream *s = hw_map_get(&c->streams, id);
	return s ? s->lane : c->rx_lane;
}

static int conn_wt_send_packet(hw_conn *c, const uint8_t *packet, size_t len, int lane) {
	if (wt_conn_send(c->wt, lane, packet, len, 0) != 0) {
		conn_close(c);
		return -1;
	}
	conn_kick(c);
	return 0;
}

int conn_send_packet(hw_conn *c, const uint8_t *packet, size_t len) {
	if (c->closing) return -1;
	if (c->wt) {
		// A CLOSE on stream 0 ends the connection: the session's close carries its reason as the code,
		// as it carries ws_fail's, so a page that missed the packet still learns why.
		if (!c->wt_code && len > HW_WISP_HEADER_LEN && packet[0] == HW_WISP_CLOSE && hw_le32(packet + 1) == 0) {
			c->wt_code = packet[HW_WISP_HEADER_LEN];
		}
		return conn_wt_send_packet(c, packet, len, conn_wt_lane(c, hw_le32(packet + 1)));
	}
	uint8_t *p = frame_begin(c, len);
	if (!p) return -1;
	memcpy(p, packet, len);
	conn_kick(c);
	return c->closing ? -1 : 0;
}

// The same over a WebTransport session: each packet laid out whole for hw_wt, and a UDP stream's
// sent as a datagram where it fits one, so that a lost one is lost and holds nothing up.
static int conn_wt_send_data(hw_conn *c, uint32_t stream_id, const uint8_t *data, size_t len) {
	hw_stream *s = hw_map_get(&c->streams, stream_id);
	int unreliable = s && s->type == HW_STREAM_UDP;
	int lane = s ? s->lane : c->rx_lane;
	size_t max = frame_payload_max(c);
	if (max > HW_WT_SCRATCH_LEN - HW_WISP_HEADER_LEN) max = HW_WT_SCRATCH_LEN - HW_WISP_HEADER_LEN;
	size_t total = len;
	do {
		size_t n = len < max ? len : max;
		uint8_t *p = wt_conn_scratch(c->wt);
		hw_wisp_write_header(p, HW_WISP_DATA, stream_id);
		memcpy(p + HW_WISP_HEADER_LEN, data, n);
		if (wt_conn_send(c->wt, lane, p, HW_WISP_HEADER_LEN + n, unreliable) != 0) {
			conn_close(c);
			return -1;
		}
		data += n;
		len -= n;
	} while (len > 0);
	atomic_fetch_add(&c->w->bytes_out, total);
	conn_charge_bandwidth(c, total);
	conn_kick(c);
	return c->closing ? -1 : 0;
}

int conn_send_data(hw_conn *c, uint32_t stream_id, const uint8_t *data, size_t len) {
	if (c->closing) return -1;
	if (c->wt) return conn_wt_send_data(c, stream_id, data, len);
	// One remote read may be larger than a packet may carry: it goes out as several DATA packets,
	// each within max-message-size, so a strict peer never sees an oversize frame.
	size_t max = frame_payload_max(c);
	size_t total = len;
	do {
		size_t n = len < max ? len : max;
		uint8_t *p = frame_begin(c, HW_WISP_HEADER_LEN + n);
		if (!p) return -1;
		hw_wisp_write_header(p, HW_WISP_DATA, stream_id);
		memcpy(p + HW_WISP_HEADER_LEN, data, n);
		data += n;
		len -= n;
	} while (len > 0);
	atomic_fetch_add(&c->w->bytes_out, total);
	conn_charge_bandwidth(c, total);
	conn_kick(c);
	return c->closing ? -1 : 0;
}

// Whether a frame the client is waiting on goes ahead of what is queued for it (pri): on a
// WebSocket, once the opening is over. Every such frame goes there, an empty queue or not, so they
// keep their order among themselves: two CONTINUEs of one stream never swap, nor two pongs.
static int conn_ahead(const hw_conn *c) {
	return !c->wt && c->state == CONN_WS && c->handshake_done;
}

// Queue a frame on pri. It never waits behind the download that fills wbuf, only for the end of
// the frame being sent (at most CONN_FRAME_MAX of payload): a refill CONTINUE behind 2 MiB of
// queue cost that upload 2 MiB of the client's downlink per round trip.
static int conn_send_ahead(hw_conn *c, uint8_t opcode, const uint8_t *payload, size_t len) {
	uint8_t hdr[HW_WS_MAX_HEADER];
	size_t hlen = hw_ws_write_header(hdr, 1, opcode, len, NULL);
	if (hw_buf_append(&c->pri, hdr, hlen) != 0 || hw_buf_append(&c->pri, payload, len) != 0) {
		conn_close(c);
		return -1;
	}
	conn_kick(c);
	return c->closing ? -1 : 0;
}

// A CONTINUE is the one small frame that does not wait for the end of the batch: the client has
// stopped sending on that stream until it arrives, so every microsecond it sits in the queue is a
// microsecond of idle pipeline (deferring it measurably slowed a connection with ten busy streams).
// For the same reason it goes ahead of a queued download (conn_ahead); the stream-0 CONTINUE of
// the opening never does.
int conn_send_continue(hw_conn *c, uint32_t stream_id, uint32_t remaining) {
	uint8_t pkt[HW_WISP_HEADER_LEN + 4];
	size_t n = hw_wisp_build_continue(pkt, stream_id, remaining);
	if (stream_id != 0 && conn_ahead(c)) {
		if (conn_send_ahead(c, HW_WS_BINARY, pkt, n) != 0) return -1;
	} else if (conn_send_packet(c, pkt, n) != 0) {
		return -1;
	}
	if (!c->write_armed) conn_flush(c);
	return c->closing ? -1 : 0;
}

int conn_send_close(hw_conn *c, uint32_t stream_id, uint8_t reason) {
	// For a stream other than 0, this is a CONNECT refused before it was a stream: a stream's own
	// CLOSE goes through conn_send_close_lane, and is counted by stream_close.
	if (stream_id != 0) HW_WSTAT_ADD(c->w->st.stream_refused[stats_reason(reason)], 1);
	uint8_t pkt[HW_WISP_HEADER_LEN + 1];
	return conn_send_packet(c, pkt, hw_wisp_build_close(pkt, stream_id, reason));
}

int conn_send_close_lane(hw_conn *c, uint32_t stream_id, uint8_t reason, int lane) {
	uint8_t pkt[HW_WISP_HEADER_LEN + 1];
	size_t n = hw_wisp_build_close(pkt, stream_id, reason);
	if (c->wt && !c->closing) return conn_wt_send_packet(c, pkt, n, lane);
	return conn_send_packet(c, pkt, n);
}

// A control frame (a pong) goes ahead of a queued download, as a refill CONTINUE does: a client
// that pings to measure the path, or to keep it, would otherwise measure the queue.
static void send_control(hw_conn *c, uint8_t opcode, const uint8_t *payload, size_t len) {
	if (conn_ahead(c)) {
		conn_send_ahead(c, opcode, payload, len);
		return;
	}
	uint8_t hdr[HW_WS_MAX_HEADER];
	size_t hlen = hw_ws_write_header(hdr, 1, opcode, len, NULL);
	if (hw_buf_append(&c->wbuf, hdr, hlen) != 0 || hw_buf_append(&c->wbuf, payload, len) != 0) {
		conn_close(c);
		return;
	}
	conn_kick(c);
}

static void ws_fail(hw_conn *c, uint16_t code) {
	if (c->wt) {
		c->wt_code = code; // the session's close carries the code the WebSocket's would
		conn_close(c);
		return;
	}
	uint8_t payload[2] = {(uint8_t)(code >> 8), (uint8_t)code};
	HW_DEBUG("conn", "%s: websocket close %u", c->peer, code);
	uint8_t frame[HW_WS_MAX_HEADER + 2];
	size_t hlen = hw_ws_write_header(frame, 1, HW_WS_CLOSE, 2, NULL);
	memcpy(frame + hlen, payload, 2);
	ssize_t r = send(c->fd, frame, hlen + 2, HW_MSG_NOSIGNAL | MSG_DONTWAIT);
	(void)r;
	conn_close(c);
}

// ---------------------------------------------------------------------------------- HTTP

// `extra` is zero or more complete header lines, each ending in CRLF.
static void http_reply_x(hw_conn *c, int status, const char *reason, const char *ctype, const char *extra,
                         const void *body, size_t blen) {
	char head[512];
	int n = snprintf(head, sizeof(head),
	                 "HTTP/1.1 %d %s\r\n"
	                 "Content-Type: %s\r\n"
	                 "Content-Length: %zu\r\n"
	                 "Cache-Control: no-store\r\n"
	                 "%s"
	                 "Connection: close\r\n"
	                 "\r\n",
	                 status, reason, ctype, blen, extra);
	if (n < 0 || (size_t)n >= sizeof(head) || hw_buf_append(&c->wbuf, head, (size_t)n) != 0 ||
	    hw_buf_append(&c->wbuf, body, blen) != 0) {
		conn_close(c);
		return;
	}
	c->state = CONN_HTTP_REPLY;
	atomic_fetch_add(&c->w->server->http_replies, 1);
	conn_apply_events(c); // nothing more is read from this client (conn_reads_stopped)
	conn_flush(c);
}

static void http_reply_n(hw_conn *c, int status, const char *reason, const char *ctype, const void *body, size_t blen) {
	http_reply_x(c, status, reason, ctype, "", body, blen);
}

static void http_reply(hw_conn *c, int status, const char *reason, const char *ctype, const char *body) {
	http_reply_n(c, status, reason, ctype, body, strlen(body));
}

static void stats_reply(hw_conn *c) {
	hw_buf body;
	hw_buf_init(&body);
	if (stats_json(c->w, &body) != 0) {
		http_reply(c, 503, "Service Unavailable", "text/plain; charset=utf-8", "no memory for the stats\n");
	} else {
		http_reply_n(c, 200, "OK", "application/json", hw_buf_head(&body), hw_buf_avail(&body));
	}
	hw_buf_free(&body);
}

static int ct_equal(const char *a, const char *b, size_t n);

// Fill c->ip from the trusted-proxy headers when the peer is a trusted proxy.
// Who the client is, from the trusted headers when a trusted proxy sent the request. 0, or -1 when
// the request cannot be believed either way and is to be refused.
static int resolve_real_ip(hw_conn *c, const hw_http_request *req) {
	const hw_server_config *cfg = &c->w->server->cfg;
	if (!cfg->parse_real_ip || cfg->trusted_proxy_count == 0) return 0;
	if (cfg->trusted_proxy_secret[0]) {
		// The proxy's address alone is not proof (see trusted_proxy_secret): without the secret the
		// request is treated as coming from the peer itself.
		const char *got = hw_http_header_get(req, "X-HolyWisp-Proxy-Secret");
		size_t want = strlen(cfg->trusted_proxy_secret);
		if (!got || strlen(got) != want || !ct_equal(got, cfg->trusted_proxy_secret, want)) return 0;
	}
	int from_proxy = hw_cidr_any_contains(cfg->trusted_proxies, cfg->trusted_proxy_count,
	                                      (const struct sockaddr *)&c->peer_addr);
	// Every instance of each trusted header, in the order of the request: a proxy that appends
	// its own line after the client's must be read last, not dropped for the client's first one.
	const char *values[HW_MAX_TRUSTED_HEADERS][HW_HTTP_MAX_HEADERS];
	hw_real_ip_header headers[HW_MAX_TRUSTED_HEADERS];
	for (int i = 0; i < cfg->trusted_header_count; i++) {
		int cut = 0;
		headers[i].values = values[i];
		headers[i].count = hw_http_header_all(req, cfg->trusted_headers[i], values[i], HW_HTTP_MAX_HEADERS, &cut);
		// A trusted header with a cut value has lost its end, and the end is where the proxy wrote
		// the real address: what is left is the client's own text. From a trusted proxy that is a
		// request whose client cannot be known, and counting it as the proxy itself would give it
		// the proxy's allowance and its clean record: it is refused. From anyone else the header
		// means nothing anyway.
		if (cut && from_proxy) return -1;
		if (cut) return 0;
	}
	hw_real_ip((const struct sockaddr *)&c->peer_addr, cfg->trusted_proxies, cfg->trusted_proxy_count, headers,
	           cfg->trusted_header_count, c->ip);
	return 0;
}

// Apply reputation tier to the connection: STRICT refuses, THROTTLE tightens the stream cap.
// Returns 0 to continue, -1 when the connection was refused.
static int apply_reputation(hw_conn *c) {
	hw_reputation *rep = c->w->server->reputation;
	if (!rep) return 0;
	int score = hw_reputation_source_score(rep, c->ip);
	c->tier = hw_reputation_tier(rep, score);
	if (c->tier == HW_TIER_STRICT) {
		HW_WARN("reputation", "%s: refused, score %d (strict)", c->ip, score);
		HW_STAT_INC(c->w->server, refused_reputation);
		return -1;
	}
	if (c->tier >= HW_TIER_THROTTLE) {
		int capped = c->w->server->cfg.max_streams_per_conn;
		c->stream_cap = capped > 0 ? (capped < 16 ? capped : 16) : 16;
		HW_INFO("reputation", "%s: throttled, score %d, stream cap %d", c->ip, score, c->stream_cap);
	}
	return 0;
}

static void send_server_info(hw_conn *c) {
	const hw_server_config *cfg = &c->w->server->cfg;
	uint8_t pkt[HW_WISP_HEADER_LEN + 2 + 5 + 6 + 5 + sizeof(cfg->motd) + 6 + 5];
	size_t n = hw_wisp_build_info(pkt, HW_WISP_MAJOR, HW_WISP_MINOR);
	if (cfg->allow_udp) n += hw_wisp_build_extension(pkt + n, sizeof(pkt) - n, HW_EXT_UDP, NULL, 0);
	if (cfg->password_user_count > 0) {
		uint8_t required = cfg->password_required ? 1 : 0;
		n += hw_wisp_build_extension(pkt + n, sizeof(pkt) - n, HW_EXT_PASSWORD, &required, 1);
	}
	if (cfg->motd[0]) {
		n += hw_wisp_build_extension(pkt + n, sizeof(pkt) - n, HW_EXT_MOTD, cfg->motd, (uint32_t)strlen(cfg->motd));
	}
	if (c->wt && wt_conn_lanes_offered(c->wt) >= 2) {
		uint8_t lanes = (uint8_t)wt_conn_lanes_offered(c->wt);
		n += hw_wisp_build_extension(pkt + n, sizeof(pkt) - n, HW_EXT_LANES, &lanes, 1);
	}
	if (cfg->stream_credit) {
		n += hw_wisp_build_extension(pkt + n, sizeof(pkt) - n, HW_EXT_CREDIT, NULL, 0);
		c->credit_offered = 1;
	}
	conn_send_packet(c, pkt, n);
}

static void handshake_done(hw_conn *c) {
	c->handshake_done = 1;
	if (c->handshake_timer) {
		hw_loop_cancel_timer(c->w->loop, c->handshake_timer);
		c->handshake_timer = NULL;
	}
	if (!c->continue_sent) conn_send_continue(c, 0, c->w->server->window);
	if (c->wt && !c->closing) wt_conn_release(c->wt); // the lanes held until now
}

// Returns 1 to keep parsing rbuf, 0 to wait for more bytes (or because the conn is closing).
// The page reads window.HOLYWISP_CONFIG.wisp for its default server; inject it before </head> so
// it is defined by the time the page's own script runs. The URL was validated to be safe inside a
// script string literal (hw_server_config_validate).
int webclient_page_build(hw_server *s) {
	const char *url = s->cfg.webclient_wisp_url;
	if (!url[0]) return 0;
	static const char marker[] = "</head>";
	const char *html = (const char *)hw_webclient_html;
	const char *at = memmem(html, hw_webclient_html_len, marker, sizeof(marker) - 1);
	if (!at) {
		errno = EINVAL;
		return -1;
	}
	char script[512];
	int n = snprintf(script, sizeof(script),
	                 "\t\t<script>\n\t\t\twindow.HOLYWISP_CONFIG = { wisp: \"%s\" };\n\t\t</script>\n\t", url);
	if (n < 0 || (size_t)n >= sizeof(script)) {
		errno = EINVAL;
		return -1;
	}
	size_t head = (size_t)(at - html);
	size_t total = hw_webclient_html_len + (size_t)n;
	uint8_t *page = malloc(total);
	if (!page) return -1;
	memcpy(page, html, head);
	memcpy(page + head, script, (size_t)n);
	memcpy(page + head + (size_t)n, html + head, hw_webclient_html_len - head);
	s->webclient_page = page;
	s->webclient_page_len = total;
	return 0;
}

// A browser names the page that opened the connection, and cannot be made to lie about it. With
// allow-origin set, a page that is not on the list may not use this relay from its visitors'
// addresses (and so cannot spend their rate limits or their reputation). A client that sends
// no Origin is not a browser, and is not stopped by this: it speaks for itself.
static int origin_allowed(const hw_server_config *cfg, const char *origin) {
	if (cfg->allow_origin_count == 0 || origin == NULL) return 1;
	for (int i = 0; i < cfg->allow_origin_count; i++) {
		if (strcasecmp(origin, cfg->allow_origins[i]) == 0) return 1;
	}
	return 0;
}

enum admit {
	ADMIT_OK = 0,
	ADMIT_RATE,       // connections-limit-per-ip in connection-window-s
	ADMIT_REPUTATION, // a STRICT source
	ADMIT_PER_IP,     // max-concurrent-connections-per-ip
	ADMIT_CAPACITY    // max-concurrent-connections
};

// The connection-level checks after the origin and the client's address, in this order, for the
// WebSocket upgrade and the WebTransport CONNECT alike. On ADMIT_OK the connection holds its slots.
static enum admit conn_admit(hw_conn *c) {
	hw_server *srv = c->w->server;
	if (srv->conn_rate && !hw_window_allow(srv->conn_rate, c->ip)) {
		HW_STAT_INC(srv, refused_connection_rate);
		return ADMIT_RATE;
	}
	if (apply_reputation(c) != 0) return ADMIT_REPUTATION;
	// Concurrent connections from one address, so that no single client can hold every slot of the
	// server-wide cap below. Refused like the rate limit is.
	int ip_slot = hw_gauge_acquire(srv->conns_per_ip, c->ip);
	if (ip_slot == 0) {
		HW_STAT_INC(srv, refused_connection_limit);
		return ADMIT_PER_IP;
	}
	c->ip_slot = ip_slot == 1;
	if (!hw_semaphore_try(&srv->connections)) {
		HW_STAT_INC(srv, refused_connection_limit);
		return ADMIT_CAPACITY;
	}
	c->conn_slot = 1;
	return ADMIT_OK;
}

static void wt_json_reply(hw_conn *c) {
	char body[512];
	size_t n = wt_json(c->w, body, sizeof(body));
	// Any page may read it: the hashes are what the server shows every client anyway.
	http_reply_x(c, 200, "OK", "application/json", "Access-Control-Allow-Origin: *\r\n", body, n);
}

static int http_process(hw_conn *c) {
	const hw_server_config *cfg = &c->w->server->cfg;
	hw_server *srv = c->w->server;
	hw_http_request req;
	// Each read looks only at what is new: a head that arrives a byte at a time is scanned once.
	size_t avail = hw_buf_avail(&c->rbuf);
	size_t end = hw_http_head_end(hw_buf_head(&c->rbuf), avail, c->head_scanned);
	if (end == 0 && avail < HW_HTTP_MAX_REQUEST) {
		c->head_scanned = avail;
		return 0;
	}
	conn_head_done(c); // a whole head, or more than one may be: either way it is not pending now
	int r = hw_http_parse_request(hw_buf_head(&c->rbuf), end ? end : avail, &req);
	if (r < 0) { // HW_ERR_AGAIN cannot be: the head is whole, or too long to ever be
		http_reply(c, 400, "Bad Request", "text/plain; charset=utf-8", "bad request\n");
		return 0;
	}
	hw_buf_consume(&c->rbuf, (size_t)r);

	if (!req.is_websocket) {
		if (strcmp(req.path, "/health") == 0) {
			http_reply(c, 200, "OK", "application/json", "{\"status\":\"ok\"}\n");
		} else if (strcmp(req.path, "/stats") == 0) {
			stats_reply(c);
		} else if (c->w->wt && strcmp(req.path, "/webtransport.json") == 0) {
			wt_json_reply(c);
		} else if (cfg->serve_webclient && strcmp(req.path, "/") == 0) {
			// Visiting the server in a browser shows the built-in web client (serve-webclient).
			if (srv->webclient_page) {
				http_reply_n(c, 200, "OK", "text/html; charset=utf-8", srv->webclient_page, srv->webclient_page_len);
			} else {
				http_reply_n(c, 200, "OK", "text/html; charset=utf-8", hw_webclient_html, hw_webclient_html_len);
			}
		} else if (cfg->non_ws_response[0]) {
			http_reply(c, 200, "OK", "text/plain; charset=utf-8", cfg->non_ws_response);
		} else {
			http_reply(c, 426, "Upgrade Required", "text/plain; charset=utf-8", "websocket upgrade required\n");
		}
		return 0;
	}

	if (!origin_allowed(cfg, hw_http_header_get(&req, "Origin"))) {
		http_reply(c, 403, "Forbidden", "text/plain; charset=utf-8", "origin not allowed\n");
		return 0;
	}

	if (resolve_real_ip(c, &req) != 0) {
		http_reply(c, 400, "Bad Request", "text/plain; charset=utf-8", "forwarding header too long\n");
		return 0;
	}

	char retry[64];
	switch (conn_admit(c)) {
	case ADMIT_OK:
		break;
	case ADMIT_RATE:
		snprintf(retry, sizeof(retry), "Retry-After: %d\r\n", cfg->connection_window_s);
		http_reply_x(c, 429, "Too Many Requests", "text/plain; charset=utf-8", retry, "rate limit\n", 11);
		return 0;
	case ADMIT_REPUTATION:
		http_reply(c, 403, "Forbidden", "text/plain; charset=utf-8", "blocked\n");
		return 0;
	case ADMIT_PER_IP:
		snprintf(retry, sizeof(retry), "Retry-After: %d\r\n",
		         cfg->connection_window_s > 0 ? cfg->connection_window_s : 10);
		http_reply_x(c, 429, "Too Many Requests", "text/plain; charset=utf-8", retry, "too many connections\n", 21);
		return 0;
	case ADMIT_CAPACITY:
		http_reply(c, 503, "Service Unavailable", "text/plain; charset=utf-8", "at capacity\n");
		return 0;
	}

	// Wisp v2 is opted into by offering any Sec-WebSocket-Protocol at all, not a fixed name: the
	// spec does not name one, wispurr treats a non-empty header as v2, and epoxy sends a random
	// UUID as the subprotocol. Whatever was offered is echoed verbatim; a browser fails the
	// handshake if the token it asked for does not come back.
	int v2 = cfg->enable_v2 && req.ws_protocol[0] != '\0';
	if (cfg->password_required && !v2) {
		http_reply(c, 426, "Upgrade Required", "text/plain; charset=utf-8", "wisp-v2 with authentication required\n");
		return 0;
	}
	char accept[HW_WS_ACCEPT_LEN + 1];
	hw_ws_accept_key(req.ws_key, accept);
	char head[512];
	int n = snprintf(head, sizeof(head),
	                 "HTTP/1.1 101 Switching Protocols\r\n"
	                 "Upgrade: websocket\r\n"
	                 "Connection: Upgrade\r\n"
	                 "Sec-WebSocket-Accept: %s\r\n"
	                 "%s%s%s"
	                 "\r\n",
	                 accept, v2 ? "Sec-WebSocket-Protocol: " : "", v2 ? req.ws_protocol : "", v2 ? "\r\n" : "");
	if (n < 0 || hw_buf_append(&c->wbuf, head, (size_t)n) != 0) {
		conn_close(c);
		return 0;
	}
	c->state = CONN_WS;
	c->fr_end = c->wsent + hw_buf_avail(&c->wbuf); // the head is no frame: the first one starts here
	c->is_v2 = v2;
	// A WebSocket, as /stats counts them apart from the HTTP polls on the same port.
	c->ws_counted = 1;
	atomic_fetch_add(&srv->ws_connections_total, 1);
	atomic_fetch_add(&srv->ws_connections_active, 1);
	// c->ip is no address only for a peer that is none (a Unix socket): it then has no key.
	if (cfg->proxy_client_key) {
		hw_warp_client_key(srv->client_key_secret, srv->client_key_secret_len, c->ip, c->client_key);
	}
	HW_DEBUG("conn", "%s (%s): websocket %s", c->peer, c->ip, v2 ? "wisp-v2" : "wisp-v1");
	if (v2) {
		send_server_info(c);
		// The stream-0 CONTINUE goes with the INFO, a round trip before the client's, so v2 costs
		// no more to open than v1 (stream credit needs v2). The client's INFO is still handled
		// before anything else it sends (handle_message), and with no password users that is
		// done at once, in order, behind it. With one, the INFO may wait for an auth thread, and
		// what follows it would be dropped meanwhile: the CONTINUE then waits for it as before.
		if (!c->closing && cfg->password_user_count == 0) {
			c->continue_sent = 1;
			conn_send_continue(c, 0, srv->window);
		}
	} else {
		handshake_done(c);
	}
	return !c->closing;
}

// ---------------------------------------------------------------------------------- Wisp

// Constant-time byte compare.
static int ct_equal(const char *a, const char *b, size_t n) {
	unsigned diff = 0;
	for (size_t i = 0; i < n; i++) diff |= (unsigned)((unsigned char)a[i] ^ (unsigned char)b[i]);
	return diff == 0;
}

// How a password offered in INFO stands against the configured users. A plain stored password is
// compared here and now. A hashed one is not: crypt(3) is slow by design, so it goes to the auth
// threads and the answer comes back to info_finish through auth_done.
enum {
	PASS_BAD = 0,
	PASS_OK,
	PASS_PENDING, // c->auth_req is set
	PASS_BUSY     // too many checks waiting: turned away, and not held against the client
};

static void info_finish(hw_conn *c, int tried, int ok);

static void auth_done(hw_loop *loop, int ok, void *ud) {
	hw_conn *c = ud;
	c->auth_req = NULL;
	info_finish(c, 1, ok);
}

static int password_check(hw_conn *c, const char *user, size_t ulen, const char *pass, size_t plen) {
	const hw_server_config *cfg = &c->w->server->cfg;
	hw_auth *auth = c->w->server->auth;
	char userz[64], passz[256];
	if (ulen >= sizeof(userz) || plen >= sizeof(passz)) return PASS_BAD;
	memcpy(userz, user, ulen);
	userz[ulen] = '\0';
	memcpy(passz, pass, plen);
	passz[plen] = '\0';
	const hw_password_user *found = NULL;
	const hw_password_user *hashed = NULL; // any user with a hash, for the cost of a name that is not there
	for (int i = 0; i < cfg->password_user_count; i++) {
		const hw_password_user *u = &cfg->password_users[i];
		if (!hashed && u->pass[0] == '$') hashed = u;
		if (!found && strcmp(u->user, userz) == 0) found = u;
	}
	if (found && found->pass[0] != '$') {
		size_t sl = strlen(found->pass);
		return sl == plen && ct_equal(found->pass, passz, sl) ? PASS_OK : PASS_BAD;
	}
	// A hashed user, or nobody. Nobody is hashed too when hashes are in use at all, against some
	// user's salt, so that the time the answer takes does not say which names exist.
	const hw_password_user *with = found ? found : hashed;
	if (!with || !auth) return PASS_BAD;
	c->auth_req = auth_check(auth, c->w->loop, passz, with->pass, found != NULL, auth_done, c);
	return c->auth_req ? PASS_PENDING : PASS_BUSY;
}

// The rest of the INFO exchange, once the password (if one was offered: `tried`) has its answer.
static void info_finish(hw_conn *c, int tried, int ok) {
	const hw_server_config *cfg = &c->w->server->cfg;
	if (tried && !ok) {
		// The name is not logged: it is whatever the client typed, and a failed login is where a
		// password typed into the wrong field ends up.
		HW_INFO("auth", "%s: bad password", c->peer);
		HW_STAT_INC(c->w->server, auth_failures);
		conn_rep_source(c, HW_REP_AUTH_FAILURE);
		conn_send_close(c, 0, HW_CLOSE_AUTH_BAD_PASSWORD);
		conn_flush(c); // the CLOSE is deferred like any small frame: write it before the socket goes
		conn_close(c);
		return;
	}
	if (tried) c->authenticated = 1;
	if (cfg->password_required && !c->authenticated) {
		HW_STAT_INC(c->w->server, auth_failures);
		conn_rep_source(c, HW_REP_AUTH_FAILURE);
		conn_send_close(c, 0, HW_CLOSE_AUTH_REQUIRED);
		conn_flush(c);
		conn_close(c);
		return;
	}
	handshake_done(c);
}

static void handle_info(hw_conn *c, const hw_wisp_packet *p) {
	const hw_server_config *cfg = &c->w->server->cfg;
	hw_wisp_info info;
	if (c->auth_req) return; // a second INFO while the first one's password is being checked
	if (hw_wisp_parse_info(p, &info) != 0 || info.major != HW_WISP_MAJOR) {
		HW_DEBUG("conn", "%s: incompatible client INFO", c->peer);
		conn_send_close(c, 0, HW_CLOSE_INCOMPATIBLE);
		conn_flush(c); // the CLOSE is deferred like any small frame: write it before the socket goes
		conn_close(c);
		return;
	}
	c->stream_confirm = info.has_stream_confirm;
	// Stream credit is on when both INFOs name it; a client's 0xE2 without a window is no 0xE2.
	if (c->credit_offered && info.has_credit_window) {
		c->credit_window = info.credit_window > HW_WISP_CREDIT_MIN ? info.credit_window : HW_WISP_CREDIT_MIN;
	}
	if (cfg->password_user_count > 0 && info.has_password && info.user) {
		int r = password_check(c, info.user, info.user_len, info.pass, info.pass_len);
		if (r == PASS_PENDING) return; // auth_done carries on
		if (r == PASS_BUSY) {
			conn_send_close(c, 0, HW_CLOSE_THROTTLED);
			conn_flush(c);
			conn_close(c);
			return;
		}
		info_finish(c, 1, r == PASS_OK);
		return;
	}
	info_finish(c, 0, 0);
}

// A destination is a hostname or an address literal, and both are made of these bytes. Anything
// else is refused before it can reach a resolver, a log line or an upstream proxy's request line
// (a space or a line break in the host of an HTTP CONNECT is a second request).
static int host_chars_ok(const char *host, size_t len) {
	for (size_t i = 0; i < len; i++) {
		unsigned char ch = (unsigned char)host[i];
		int ok = (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '.' ||
		         ch == '-' || ch == '_' || ch == ':' || ch == '[' || ch == ']';
		if (!ok) return 0;
	}
	return 1;
}

static void handle_connect(hw_conn *c, const hw_wisp_packet *p) {
	const hw_server_config *cfg = &c->w->server->cfg;
	hw_server *srv = c->w->server;
	hw_wisp_connect req;
	// A CLOSE for stream 0 would end the whole connection, so a CONNECT on it gets no reply at all.
	if (p->stream_id == 0) return;
	if (hw_wisp_parse_connect(p, &req) != 0 || req.host_len == 0 || req.host_len > 255 ||
	    memchr(req.host, '\0', req.host_len)) {
		conn_send_close(c, p->stream_id, HW_CLOSE_INVALID_INFO);
		return;
	}
	hw_stream *dup = hw_map_get(&c->streams, p->stream_id);
	if (dup) {
		// The CLOSE this earns names the id, so the client now believes that stream is gone. It
		// is closed here too: left open, it would relay for an id the client no longer knows.
		HW_DEBUG("conn", "%s: duplicate stream %u", c->peer, p->stream_id);
		stream_close(dup, HW_CLOSE_INVALID_INFO, 1);
		return;
	}
	if (c->stream_cap > 0 && hw_map_count(&c->streams) >= (size_t)c->stream_cap) {
		// A browser opens many concurrent streams over one multiplexor as a matter of course (one
		// page's subresources, a challenge that fans out dozens of XHRs); refusing the ones past the
		// cap is back-pressure on that client, not a protocol violation. Counting it as one closed
		// the whole connection once the burst passed ws-close-after-violations and drove the source's
		// reputation to STRICT, so a client throttled to a low cap lost every in-flight stream the
		// moment a page burst (its epoxy reported Wisp(MuxTaskEnded)) and then had its reconnect
		// refused. Refuse the one stream and leave the connection and the client's standing alone.
		HW_STAT_INC(c->w->server, throttled_source);
		conn_send_close(c, p->stream_id, HW_CLOSE_THROTTLED);
		return;
	}

	// Twisp terminal stream: off unless explicitly enabled, v2, and authenticated. Each gate also
	// feeds reputation, since probing it is a strong abuse signal.
	if (req.stream_type == HW_STREAM_TERM) {
		if (!cfg->enable_twisp) {
			// Nothing to probe: the feature does not exist on this server. Asking is not abuse, and
			// scoring it let any page spend its visitors' reputation here with one packet.
			conn_send_close(c, p->stream_id, HW_CLOSE_BLOCKED);
			return;
		}
		if (!c->is_v2 || !c->authenticated) {
			HW_WARN("twisp", "%s: terminal stream refused (v2=%d auth=%d)", c->peer, c->is_v2, c->authenticated);
			conn_rep_source(c, HW_REP_TWISP_NO_AUTH);
			conn_send_close(c, p->stream_id, HW_CLOSE_BLOCKED);
			return;
		}
		twisp_open(c, p->stream_id, req.host, req.host_len);
		return;
	}

	if ((req.stream_type == HW_STREAM_TCP && !cfg->allow_tcp) ||
	    (req.stream_type == HW_STREAM_UDP && !cfg->allow_udp)) {
		conn_send_close(c, p->stream_id, HW_CLOSE_BLOCKED);
		return;
	}
	if (req.stream_type != HW_STREAM_TCP && req.stream_type != HW_STREAM_UDP) {
		conn_send_close(c, p->stream_id, HW_CLOSE_INVALID_INFO);
		return;
	}
	if (!host_chars_ok(req.host, req.host_len)) {
		conn_send_close(c, p->stream_id, HW_CLOSE_INVALID_INFO);
		return;
	}
	// Per-source connect rate (flood protection): count every CONNECT from this client IP.
	if (srv->per_source && !hw_window_allow(srv->per_source, c->ip)) {
		HW_STAT_INC(srv, throttled_source);
		conn_rep_source(c, HW_REP_BURST_RATE);
		HW_DEBUG("flood", "%s: per-source connect rate", c->ip);
		conn_violation(c, "per_source_rate");
		if (c->closing) return;
		conn_send_close(c, p->stream_id, HW_CLOSE_THROTTLED);
		return;
	}
	stream_open(c, p->stream_id, req.stream_type, req.host, req.host_len, req.port);
}

static void handle_resize(hw_conn *c, const hw_wisp_packet *p) {
	if (p->payload_len < 4) return;
	hw_stream *s = hw_map_get(&c->streams, p->stream_id);
	if (s && s->type == HW_STREAM_TERM) twisp_resize(s, hw_le16(p->payload), hw_le16(p->payload + 2));
}

// CREDIT: the client lets a stream send it more. It is ignored where it cannot apply (a session
// without stream credit, stream 0, a stream that is not open or is UDP, a short payload, a limit
// that is not higher), so a duplicate or one overtaken by a later one changes nothing. A stream
// held by nothing else reads again.
static void handle_credit(hw_conn *c, const hw_wisp_packet *p) {
	uint64_t limit;
	if (!c->credit_window || p->stream_id == 0 || hw_wisp_parse_credit(p, &limit) != 0) return;
	hw_stream *s = hw_map_get(&c->streams, p->stream_id);
	if (!s || s->type == HW_STREAM_UDP || limit <= s->credit_limit) return;
	s->credit_limit = limit;
	if (!conn_stream_paused(c, s)) stream_resume(s); // a parked one goes on when its pipe drains
}

static void handle_message(hw_conn *c, const uint8_t *data, size_t len) {
	hw_wisp_packet p;
	if (hw_wisp_parse(data, len, &p) != 0) return; // runt packet: ignored, like other servers do

	if (c->is_v2 && !c->handshake_done) {
		if (p.type == HW_WISP_INFO && p.stream_id == 0) {
			handle_info(c, &p);
		} else if (p.type == HW_WISP_CLOSE && p.stream_id == 0) {
			conn_close(c);
		}
		return;
	}

	if (p.type == HW_WISP_CREDIT) {
		// Not behind the batch flush below: a CREDIT opens and closes nothing, writes nothing and
		// only arms a stream's read interest, while the batch is bytes toward a remote. Flushing for
		// it would cut an upload's batch at every grant for a download on the same connection.
		handle_credit(c, &p);
		return;
	}
	if (p.type != HW_WISP_DATA) {
		// Anything else may open, close or resize a stream: batched DATA goes out first, in order.
		stream_batch_flush(c->w);
		if (c->closing) return;
	}
	switch (p.type) {
	case HW_WISP_DATA: {
		hw_stream *s = hw_map_get(&c->streams, p.stream_id);
		if (!s) return; // raced with our CLOSE
		atomic_fetch_add(&c->w->bytes_in, p.payload_len);
		conn_charge_bandwidth(c, p.payload_len);
		c->pkt_avg = c->pkt_avg ? (c->pkt_avg * 7 + p.payload_len) / 8 : p.payload_len;
		s->pkt_avg = s->pkt_avg ? (s->pkt_avg * 7 + p.payload_len) / 8 : p.payload_len;
		stream_on_data(s, p.payload, p.payload_len);
		break;
	}
	case HW_WISP_CONNECT:
		handle_connect(c, &p);
		break;
	case HW_WISP_CLOSE: {
		if (p.stream_id == 0) {
			conn_close(c);
			return;
		}
		hw_stream *s = hw_map_get(&c->streams, p.stream_id);
		if (s) stream_close(s, HW_CLOSE_VOLUNTARY, 0);
		break;
	}
	case HW_WISP_TWISP_RESIZE:
		handle_resize(c, &p);
		break;
	case HW_WISP_CONTINUE:
	case HW_WISP_INFO:
	default:
		break;
	}
}

// ---------------------------------------------------------------------------------- WebSocket

static int ws_frames(hw_conn *c) {
	const hw_server_config *cfg = &c->w->server->cfg;
	while (!c->closing) {
		size_t avail = hw_buf_avail(&c->rbuf);
		if (c->pt_left > 0) {
			// The rest of a large DATA frame: unmask what is here and hand it on.
			if (avail == 0) return 0;
			size_t n = avail < c->pt_left ? avail : c->pt_left;
			uint8_t *p = c->rbuf.data + c->rbuf.off;
			hw_ws_mask(p, n, c->pt_mask, c->pt_off);
			c->pt_off = (c->pt_off + n) & 3;
			c->pt_left -= n;
			hw_stream *s = hw_map_get(&c->streams, c->pt_stream);
			if (s) { // otherwise it closed mid-frame and the rest is dropped, like a late packet
				atomic_fetch_add(&c->w->bytes_in, n);
				conn_charge_bandwidth(c, n);
				stream_on_data_part(s, p, n, c->pt_left == 0);
				if (c->closing) return 0;
			}
			hw_buf_consume(&c->rbuf, n);
			continue;
		}
		hw_ws_frame f;
		int r = hw_ws_parse_header(hw_buf_head(&c->rbuf), avail, &f);
		if (r == HW_ERR_AGAIN) return 0;
		if (r < 0 || !f.masked) {
			ws_fail(c, 1002);
			return 0;
		}
		if (f.payload_len > cfg->max_message_size) {
			ws_fail(c, 1009);
			return 0;
		}
		size_t total = f.header_len + (size_t)f.payload_len;
		if (avail < total && f.opcode == HW_WS_BINARY && f.fin && !c->frag_active && f.payload_len >= CONN_PT_MIN &&
		    avail >= f.header_len + HW_WISP_HEADER_LEN && (!c->is_v2 || c->handshake_done)) {
			uint8_t wh[HW_WISP_HEADER_LEN];
			memcpy(wh, c->rbuf.data + c->rbuf.off + f.header_len, sizeof(wh));
			hw_ws_mask(wh, sizeof(wh), f.mask, 0);
			if (wh[0] == HW_WISP_DATA) {
				c->pt_stream = hw_le32(wh + 1);
				c->pt_left = (size_t)f.payload_len - HW_WISP_HEADER_LEN;
				memcpy(c->pt_mask, f.mask, sizeof(c->pt_mask));
				c->pt_off = HW_WISP_HEADER_LEN & 3;
				c->pkt_avg = c->pkt_avg ? (c->pkt_avg * 7 + c->pt_left) / 8 : c->pt_left;
				hw_stream *ps = hw_map_get(&c->streams, c->pt_stream);
				if (ps) ps->pkt_avg = ps->pkt_avg ? (ps->pkt_avg * 7 + c->pt_left) / 8 : c->pt_left;
				hw_buf_consume(&c->rbuf, f.header_len + HW_WISP_HEADER_LEN);
				continue;
			}
		}
		if (avail < total) {
			stream_batch_flush(c->w);
			if (c->closing) return 0;
			if (hw_buf_reserve(&c->rbuf, total - avail) != 0) conn_close(c);
			return 0;
		}
		uint8_t *payload = c->rbuf.data + c->rbuf.off + f.header_len;
		size_t len = (size_t)f.payload_len;
		hw_ws_mask(payload, len, f.mask, 0);

		switch (f.opcode) {
		case HW_WS_BINARY:
			if (c->frag_active) {
				ws_fail(c, 1002);
				return 0;
			}
			if (f.fin) {
				handle_message(c, payload, len);
			} else {
				c->frag_active = 1;
				if (hw_buf_append(&c->frag, payload, len) != 0) conn_close(c);
			}
			break;
		case HW_WS_CONTINUATION:
			if (!c->frag_active) {
				ws_fail(c, 1002);
				return 0;
			}
			if (hw_buf_avail(&c->frag) + len > cfg->max_message_size) {
				ws_fail(c, 1009);
				return 0;
			}
			if (hw_buf_append(&c->frag, payload, len) != 0) {
				conn_close(c);
				return 0;
			}
			if (f.fin) {
				c->frag_active = 0;
				handle_message(c, hw_buf_head(&c->frag), hw_buf_avail(&c->frag));
				stream_batch_flush(c->w); // the payload lives in frag, which is about to be reused
				hw_buf_clear(&c->frag);
			}
			break;
		case HW_WS_PING:
			send_control(c, HW_WS_PONG, payload, len);
			break;
		case HW_WS_PONG:
			break;
		case HW_WS_CLOSE: {
			uint16_t code = 1000;
			if (len == 1) {
				ws_fail(c, 1002);
				return 0;
			}
			if (len >= 2) code = (uint16_t)(payload[0] << 8 | payload[1]);
			ws_fail(c, code);
			return 0;
		}
		case HW_WS_TEXT:
			ws_fail(c, 1003);
			return 0;
		default:
			ws_fail(c, 1002);
			return 0;
		}
		if (c->closing) return 0;
		hw_buf_consume(&c->rbuf, total);
	}
	return 0;
}

// DATA payloads are handed to their streams as pointers into rbuf (stream_on_data batches them),
// so the batch is flushed before rbuf can be compacted or grown, and before returning.
static int ws_process(hw_conn *c) {
	int r = ws_frames(c);
	stream_batch_flush(c->w);
	return r;
}

static void conn_process(hw_conn *c) {
	for (;;) {
		if (c->closing) return;
		if (c->state == CONN_HTTP) {
			if (!http_process(c)) return;
		} else if (c->state == CONN_WS) {
			if (!ws_process(c)) return;
		} else {
			return; // CONN_HTTP_REPLY: whatever else the client sends is ignored
		}
	}
}

static void conn_read(hw_conn *c) {
	size_t total = 0;
	while (!c->closing && !conn_reads_stopped(c) && total < CONN_MAX_READ_PER_EVENT) {
		int head = c->state == CONN_HTTP; // a head is small: no room for frames until it is in
		if (hw_buf_reserve(&c->rbuf, head ? CONN_HEAD_CHUNK : c->read_chunk) != 0) {
			conn_close(c);
			return;
		}
		size_t room = hw_buf_room(&c->rbuf);
		ssize_t n = recv(c->fd, hw_buf_tail(&c->rbuf), room, MSG_DONTWAIT);
		if (n == 0) {
			conn_close(c);
			return;
		}
		if (n < 0) {
			if (errno == EINTR) continue;
			if (errno != EAGAIN && errno != EWOULDBLOCK) {
				HW_DEBUG("conn", "%s: recv: %s", c->peer, strerror(errno));
				conn_close(c);
			}
			return;
		}
		hw_buf_commit(&c->rbuf, (size_t)n);
		total += (size_t)n;
		c->heard = 1;
		conn_process(c);
		if (c->closing) return;
		if (head && (size_t)n == room) continue; // more of the head, or frames behind it
		if ((size_t)n == room) {
			// The client is sending faster than one read takes: offer more room next time, so a
			// burst of frames arrives in one recv and leaves in one write per stream.
			size_t limit = 2 * c->pkt_avg;
			if (limit < CONN_READ_CHUNK_BASE) limit = CONN_READ_CHUNK_BASE;
			if (limit > CONN_READ_CHUNK_MAX) limit = CONN_READ_CHUNK_MAX;
			if (c->read_chunk < limit) c->read_chunk *= 2;
			continue;
		}
		if (!head && (size_t)n < c->read_chunk / 4 && c->read_chunk > HW_READ_CHUNK) {
			c->read_chunk /= 2;
			hw_buf_shrink(&c->rbuf, c->read_chunk); // no-op unless the buffer is empty
		}
		return; // drained
	}
}

static void conn_io_cb(hw_loop *loop, int fd, unsigned events, void *ud) {
	hw_conn *c = ud;
	if (c->closing) return;
	if (events & HW_EV_WRITE) conn_flush(c);
	if (c->closing) return;
	if (!(events & (HW_EV_READ | HW_EV_HUP | HW_EV_ERROR))) return;
	if (!conn_reads_stopped(c)) {
		conn_read(c);
	} else if (events & (HW_EV_HUP | HW_EV_ERROR)) {
		// The client's socket is dead while its reads are paused. Nothing can clear that
		// level-triggered condition but closing, and there is no one left to relay for.
		HW_DEBUG("conn", "%s: hung up while paused", c->peer);
		conn_close(c);
	}
}

// ---------------------------------------------------------------------------------- WebTransport
//
// A session is a connection without a socket: wt_listener.c hands over each Wisp packet whole
// (conn_wt_packet, the WebTransport ws_process), and what the connection sends goes to the
// session (the c->wt branches of conn_send_packet, conn_send_data and conn_flush). Everything
// between, from handle_message on, is the WebSocket path's.

hw_conn *conn_wt_new(hw_worker *w, wt_session *s, const struct sockaddr *peer) {
	hw_conn *c = calloc(1, sizeof(*c));
	if (!c) return NULL;
	c->w = w;
	c->wt = s;
	c->fd = -1;
	c->state = CONN_HTTP;
	c->stream_cap = w->server->cfg.max_streams_per_conn;
	c->read_chunk = HW_READ_CHUNK;
	hw_buf_init(&c->rbuf);
	hw_buf_init(&c->wbuf);
	hw_buf_init(&c->frag);
	hw_buf_init(&c->pri);
	hw_map_init(&c->streams);
	hw_smap_init(&c->sigdets);
	memcpy(&c->peer_addr, peer, peer->sa_family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6));
	hw_addr_str(peer, c->peer, sizeof(c->peer));
	// The UDP peer is the client: there is no proxy in front of this listener, and no header of
	// the CONNECT is ever taken for an address.
	hw_addr_ip_str(peer, c->ip, sizeof(c->ip));
	// Until the opening is over, as on a WebSocket: a v2 client that never sends its INFO goes.
	c->handshake_timer = hw_loop_add_timer(w->loop, (uint64_t)w->server->cfg.handshake_timeout_ms, 0,
	                                       handshake_timeout_cb, c);
	c->lnext = w->conns;
	if (w->conns) w->conns->lprev = c;
	w->conns = c;
	atomic_fetch_add(&w->load, 1);
	atomic_fetch_add(&w->server->connections_total, 1);
	atomic_fetch_add(&w->server->connections_active, 1);
	return c;
}

int conn_wt_admit(hw_conn *c, const char *origin, const char *protocols) {
	const hw_server_config *cfg = &c->w->server->cfg;
	hw_server *srv = c->w->server;
	if (!origin_allowed(cfg, origin)) return 403;
	switch (conn_admit(c)) {
	case ADMIT_OK:
		break;
	case ADMIT_RATE:
	case ADMIT_PER_IP:
		return 429;
	case ADMIT_REPUTATION:
		return 403;
	case ADMIT_CAPACITY:
		return 503;
	}
	// The WebSocket rule: offering any protocol at all is the v2 opt-in.
	int v2 = cfg->enable_v2 && protocols != NULL;
	if (cfg->password_required && !v2) return 426;
	c->state = CONN_WS;
	c->is_v2 = v2;
	if (cfg->proxy_client_key) {
		hw_warp_client_key(srv->client_key_secret, srv->client_key_secret_len, c->ip, c->client_key);
	}
	HW_DEBUG("conn", "%s: webtransport %s", c->peer, v2 ? "wisp-v2" : "wisp-v1");
	return 200;
}

void conn_wt_open(hw_conn *c) {
	if (c->closing) return;
	if (!c->is_v2) {
		handshake_done(c);
		return;
	}
	send_server_info(c);
	if (c->closing || !wt_conn_server_stream(c->wt)) return;
	// The server opened lane 0, so nothing of the client's can have come first: its first packet
	// must be its INFO (conn_wt_packet), and hw_wt delivers nothing else until the handshake is
	// done. So the stream-0 CONTINUE can go now, with the INFO, a round trip before the client's,
	// unless a password has to be checked before the client may go on.
	c->wt_info_first = 1;
	if (!c->w->server->cfg.password_required) {
		c->continue_sent = 1;
		conn_send_continue(c, 0, c->w->server->window);
	}
}

void conn_wt_packet(hw_conn *c, const uint8_t *data, size_t len, int lane) {
	if (c->closing) return;
	c->heard = 1;
	if (lane >= 0) {
		c->rx_lane = lane;
		if (c->wt_info_first) {
			c->wt_info_first = 0;
			hw_wisp_packet p;
			if (hw_wisp_parse(data, len, &p) != 0 || p.type != HW_WISP_INFO || p.stream_id != 0) {
				HW_DEBUG("conn", "%s: the client's first packet is not its INFO", c->peer);
				conn_send_close(c, 0, HW_CLOSE_INCOMPATIBLE);
				conn_flush(c);
				conn_close(c);
				return;
			}
		}
	} else {
		// A datagram may be lost or overtake the stream, so only what tolerates that is taken
		// from one: DATA for a UDP stream. A CLOSE or a CONNECT there would be a race.
		hw_wisp_packet p;
		hw_stream *s = NULL;
		if (c->handshake_done && hw_wisp_parse(data, len, &p) == 0 && p.type == HW_WISP_DATA) {
			s = hw_map_get(&c->streams, p.stream_id);
		}
		if (!s || s->type != HW_STREAM_UDP) {
			atomic_fetch_add(&c->w->server->wt_dropped, 1);
			return;
		}
	}
	handle_message(c, data, len);
	// The packet's bytes are the session's and only valid now: what was batched goes out first.
	stream_batch_flush(c->w);
}

void conn_wt_progress(hw_conn *c) {
	if (!c->closing) conn_backpressure(c);
}
