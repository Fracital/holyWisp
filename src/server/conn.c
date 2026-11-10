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
#include "holywisp/wisp.h"
#include "holywisp/ws.h"

#include "holywisp_webclient.h" // generated: hw_webclient_html[], hw_webclient_html_len
#include "internal.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef CONN_MAX_READ_PER_EVENT
#define CONN_MAX_READ_PER_EVENT (1024 * 1024)
#endif
#define CONN_WINDOW_MIN 4 // packets granted per CONTINUE however many streams share a client
// A busy client's recv room grows from HW_READ_CHUNK to about two of its frames: 128 KiB for
// ordinary packets, more only for a client that sends very large ones. A big room on every
// connection costs throughput as soon as many connections are busy at once.
#define CONN_READ_CHUNK_BASE (128 * 1024)
#define CONN_READ_CHUNK_MAX  (2 * 1024 * 1024)
// A DATA frame at least this large is forwarded piece by piece while it arrives instead of being
// reassembled first: the stream sees the same bytes sooner and they stay cache-warm.
#define CONN_PT_MIN    (128 * 1024)
#define CONN_WBUF_KEEP (4 * 1024 * 1024) // a drained write queue keeps at most this much allocated
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
	hw_buf_free(&c->rbuf);
	hw_buf_free(&c->wbuf);
	free(c->marks);
	hw_buf_free(&c->frag);
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

void conn_accept(hw_worker *w, int fd, const struct sockaddr *peer) {
	hw_conn *c = calloc(1, sizeof(*c));
	if (!c) {
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
	hw_map_init(&c->streams);
	hw_smap_init(&c->sigdets);
	memcpy(&c->peer_addr, peer, peer->sa_family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6));
	hw_addr_str(peer, c->peer, sizeof(c->peer));
	// Policy IP defaults to the socket peer; the upgrade may replace it from a trusted header.
	hw_addr_ip_str(peer, c->ip, sizeof(c->ip));
	server_tune_socket(w->server, fd, 1);
	if (w->server->client_rcvbuf > 0) {
		setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &w->server->client_rcvbuf, sizeof(w->server->client_rcvbuf));
	}
	if (hw_loop_add_fd(w->loop, fd, HW_EV_READ, conn_io_cb, c) != 0) {
		HW_WARN("conn", "%s: cannot watch fd: %s", c->peer, strerror(errno));
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
	hw_loop_del_fd(c->w->loop, c->fd);
	close(c->fd);
	c->fd = -1;
	hw_map_each(&c->streams, close_stream_visit, NULL);
	marks_free(c); // after the streams: every pipe still queued is an orphan now
	if (c->conn_slot) {
		hw_semaphore_release(&c->w->server->connections);
		c->conn_slot = 0;
	}
	atomic_fetch_sub(&c->w->server->connections_active, 1);
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

// The client socket's event mask follows three bits of state: reads stop while the bandwidth
// throttle or the queue budget says so, writes are wanted while wbuf (or the pipe) has bytes.
static void conn_apply_events(hw_conn *c) {
	if (c->closing || c->fd < 0) return;
	unsigned ev = 0;
	if (!c->throttled && !c->read_paused) ev |= HW_EV_READ;
	if (c->write_armed) ev |= HW_EV_WRITE;
	hw_loop_mod_fd(c->w->loop, c->fd, ev);
}

static void throttle_wake_cb(hw_loop *loop, void *ud) {
	hw_conn *c = ud;
	c->throttle_timer = NULL;
	c->throttled = 0;
	conn_apply_events(c);
}

void conn_charge_bandwidth(hw_conn *c, size_t bytes) {
	if (!c->w->server->bandwidth || c->throttled) return;
	uint64_t wait = hw_bandwidth_charge(c->w->server->bandwidth, c->ip, bytes);
	if (wait == 0) return;
	// Stop reading from the client until the virtual clock catches up; remote-side reads are
	// paused with it through the loop's event mask.
	c->throttled = 1;
	conn_apply_events(c);
	if (c->throttle_timer) hw_loop_cancel_timer(c->w->loop, c->throttle_timer);
	c->throttle_timer = hw_loop_add_timer(c->w->loop, wait, 0, throttle_wake_cb, c);
}

// One stream on a connection may have the whole advertised window in flight; ten streams with
// the whole window each would make the server buffer tens of megabytes toward slow remotes and
// pay for it in copies. The budget keeps the sum near the client's own send-queue mark, which is
// plenty of pipeline for one stream and keeps many streams on the fast path.
uint32_t conn_window(const hw_conn *c) {
	const hw_server *srv = c->w->server;
	size_t streams = hw_map_count(&c->streams);
	size_t pkt = c->pkt_avg ? c->pkt_avg : 64 * 1024;
	size_t w = srv->cfg.ws_write_high_water / (streams ? streams : 1) / pkt;
	if (w < CONN_WINDOW_MIN) w = CONN_WINDOW_MIN;
	if (w > srv->window) w = srv->window;
	return (uint32_t)w;
}

void conn_queue_add(hw_conn *c, size_t n) {
	c->queued_out += n;
	if (!c->read_paused && c->queued_out > c->w->server->cfg.conn_queue_max) {
		HW_DEBUG("conn", "%s: %zu bytes queued toward remotes, pausing reads", c->peer, c->queued_out);
		c->read_paused = 1;
		conn_apply_events(c);
	}
}

void conn_queue_sub(hw_conn *c, size_t n) {
	c->queued_out -= n < c->queued_out ? n : c->queued_out;
	if (c->read_paused && c->queued_out < c->w->server->cfg.conn_queue_max / 2) {
		c->read_paused = 0;
		conn_apply_events(c);
	}
}

// ---------------------------------------------------------------------------------- writing

static int arm_write(hw_conn *c, int on) {
	if (c->write_armed == on) return 0;
	c->write_armed = on;
	conn_apply_events(c);
	return 0;
}

static int pause_visit(uint32_t key, void *value, void *ud) {
	stream_pause(value);
	return 0;
}

static int resume_visit(uint32_t key, void *value, void *ud) {
	stream_resume(value);
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
	return hw_buf_avail(&c->wbuf) + c->pipe_bytes;
}

static void conn_backpressure(hw_conn *c) {
	size_t queued = conn_queued(c);
	size_t high = c->w->server->cfg.ws_write_high_water;
	if (!c->paused && queued > high) {
		c->paused = 1;
		hw_map_each(&c->streams, pause_visit, NULL);
	} else if (c->paused && queued < high / 4) {
		c->paused = 0;
		hw_map_each(&c->streams, resume_visit, NULL);
	}
}

// The queue is wbuf with pipe payloads spliced in at the marks: bytes are sent from wbuf until
// the head mark's position, then that pipe is emptied into the socket, and so on. A frame header
// is always the last thing in wbuf before its mark, so frames never interleave.
//
// After a short write or a large splice the loops here and in conn_splice_data ask the kernel
// again, and about one call in eight comes back EAGAIN. That looks like waste and is not: taking
// the retries out (stop at the first short result, let epoll report the rest) removed 11% of the
// syscalls and made one busy connection 3 to 4% slower, because the retry that does find bytes
// saves a whole trip through epoll_wait.
void conn_flush(hw_conn *c) {
	if (c->closing) return;
	for (;;) {
		size_t avail = hw_buf_avail(&c->wbuf);
		hw_pipe_mark *m = c->mark_count ? &c->marks[c->mark_head] : NULL;
		ssize_t n;
		if (m && m->at == c->wsent) {
			n = hw_sys_splice(m->p->fd[0], c->fd, m->n);
			if (n > 0) {
				m->n -= (size_t)n;
				m->p->pending -= (size_t)n;
				c->pipe_bytes -= (size_t)n;
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
			n = send(c->fd, hw_buf_head(&c->wbuf), want, flags);
			if (n > 0) {
				hw_buf_consume(&c->wbuf, (size_t)n);
				c->wsent += (uint64_t)n;
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

ssize_t conn_splice_data(hw_conn *c, hw_stream *s) {
	if (c->throttled) return -2;
	hw_spipe *p = s->pipe;
	if (!p) {
		p = s->pipe = spipe_open(c->w, s);
		if (!p) return -2;
	}
	if (p->pending > 0) return -3;
	size_t max = c->w->server->cfg.max_message_size - HW_WISP_HEADER_LEN;
	size_t cap = p->size < max ? p->size : max;
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

int conn_send_packet(hw_conn *c, const uint8_t *packet, size_t len) {
	if (c->closing) return -1;
	uint8_t *p = frame_begin(c, len);
	if (!p) return -1;
	memcpy(p, packet, len);
	conn_kick(c);
	return c->closing ? -1 : 0;
}

int conn_send_data(hw_conn *c, uint32_t stream_id, const uint8_t *data, size_t len) {
	if (c->closing) return -1;
	// One remote read may be larger than the negotiated message size: it goes out as several DATA
	// packets, each within max-message-size, so a strict peer never sees an oversize frame.
	size_t max = c->w->server->cfg.max_message_size - HW_WISP_HEADER_LEN;
	if (max < 1) max = 1;
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

// A CONTINUE is the one small frame that does not wait for the end of the batch: the client has
// stopped sending on that stream until it arrives, so every microsecond it sits in the queue is a
// microsecond of idle pipeline (deferring it measurably slowed a connection with ten busy streams).
int conn_send_continue(hw_conn *c, uint32_t stream_id, uint32_t remaining) {
	uint8_t pkt[HW_WISP_HEADER_LEN + 4];
	if (conn_send_packet(c, pkt, hw_wisp_build_continue(pkt, stream_id, remaining)) != 0) return -1;
	if (!c->write_armed) conn_flush(c);
	return c->closing ? -1 : 0;
}

int conn_send_close(hw_conn *c, uint32_t stream_id, uint8_t reason) {
	uint8_t pkt[HW_WISP_HEADER_LEN + 1];
	return conn_send_packet(c, pkt, hw_wisp_build_close(pkt, stream_id, reason));
}

// A control frame (a pong) joins the queue behind whatever is already waiting.
static void send_control(hw_conn *c, uint8_t opcode, const uint8_t *payload, size_t len) {
	uint8_t hdr[HW_WS_MAX_HEADER];
	size_t hlen = hw_ws_write_header(hdr, 1, opcode, len, NULL);
	if (hw_buf_append(&c->wbuf, hdr, hlen) != 0 || hw_buf_append(&c->wbuf, payload, len) != 0) {
		conn_close(c);
		return;
	}
	conn_kick(c);
}

static void ws_fail(hw_conn *c, uint16_t code) {
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
	conn_flush(c);
}

static void http_reply_n(hw_conn *c, int status, const char *reason, const char *ctype, const void *body, size_t blen) {
	http_reply_x(c, status, reason, ctype, "", body, blen);
}

static void http_reply(hw_conn *c, int status, const char *reason, const char *ctype, const char *body) {
	http_reply_n(c, status, reason, ctype, body, strlen(body));
}

static void stats_json(hw_conn *c) {
	hw_server_stats st;
	hw_server_stats_get(c->w->server, &st);
	char body[1024];
	snprintf(body, sizeof(body),
	         "{\"uptimeSeconds\":%llu,"
	         "\"connections\":{\"total\":%llu,\"active\":%llu},"
	         "\"streams\":{\"total\":%llu,\"active\":%llu},"
	         "\"bytes\":{\"in\":%llu,\"out\":%llu},"
	         "\"refused\":{\"connectionRate\":%llu,\"connectionLimit\":%llu,\"reputation\":%llu},"
	         "\"blocked\":{\"filter\":%llu,\"egress\":%llu},"
	         "\"throttled\":{\"source\":%llu,\"dest\":%llu,\"syns\":%llu},"
	         "\"synSignatures\":%llu,\"wsClosedViolations\":%llu,\"authFailures\":%llu,"
	         "\"dnsCacheEntries\":%llu,\"reputation\":{\"sources\":%llu,\"destinations\":%llu}}\n",
	         (unsigned long long)st.uptime_s, (unsigned long long)st.connections_total,
	         (unsigned long long)st.connections_active, (unsigned long long)st.streams_total,
	         (unsigned long long)st.streams_active, (unsigned long long)st.bytes_in, (unsigned long long)st.bytes_out,
	         (unsigned long long)st.refused_connection_rate, (unsigned long long)st.refused_connection_limit,
	         (unsigned long long)st.refused_reputation, (unsigned long long)st.blocked_filter,
	         (unsigned long long)st.blocked_egress, (unsigned long long)st.throttled_source,
	         (unsigned long long)st.throttled_dest, (unsigned long long)st.throttled_syns,
	         (unsigned long long)st.syn_signatures, (unsigned long long)st.ws_closed_violations,
	         (unsigned long long)st.auth_failures, (unsigned long long)st.dns_cache_entries,
	         (unsigned long long)st.reputation_sources, (unsigned long long)st.reputation_dests);
	http_reply(c, 200, "OK", "application/json", body);
}

// Fill c->ip from the trusted-proxy headers when the peer is a trusted proxy.
static void resolve_real_ip(hw_conn *c, const hw_http_request *req) {
	const hw_server_config *cfg = &c->w->server->cfg;
	if (!cfg->parse_real_ip || cfg->trusted_proxy_count == 0) return;
	const char *values[HW_MAX_TRUSTED_HEADERS];
	int nvalues = 0;
	for (int i = 0; i < cfg->trusted_header_count; i++) {
		const char *v = hw_http_header_get(req, cfg->trusted_headers[i]);
		if (v) values[nvalues++] = v;
	}
	hw_real_ip((const struct sockaddr *)&c->peer_addr, cfg->trusted_proxies, cfg->trusted_proxy_count, values, nvalues,
	           c->ip);
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
	uint8_t pkt[HW_WISP_HEADER_LEN + 2 + 5 + 6 + 5 + sizeof(cfg->motd)];
	size_t n = hw_wisp_build_info(pkt, HW_WISP_MAJOR, HW_WISP_MINOR);
	if (cfg->allow_udp) n += hw_wisp_build_extension(pkt + n, sizeof(pkt) - n, HW_EXT_UDP, NULL, 0);
	if (cfg->password_user_count > 0) {
		uint8_t required = cfg->password_required ? 1 : 0;
		n += hw_wisp_build_extension(pkt + n, sizeof(pkt) - n, HW_EXT_PASSWORD, &required, 1);
	}
	if (cfg->motd[0]) {
		n += hw_wisp_build_extension(pkt + n, sizeof(pkt) - n, HW_EXT_MOTD, cfg->motd, (uint32_t)strlen(cfg->motd));
	}
	conn_send_packet(c, pkt, n);
}

static void handshake_done(hw_conn *c) {
	c->handshake_done = 1;
	if (c->handshake_timer) {
		hw_loop_cancel_timer(c->w->loop, c->handshake_timer);
		c->handshake_timer = NULL;
	}
	conn_send_continue(c, 0, c->w->server->window);
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

static int http_process(hw_conn *c) {
	const hw_server_config *cfg = &c->w->server->cfg;
	hw_server *srv = c->w->server;
	hw_http_request req;
	int r = hw_http_parse_request(hw_buf_head(&c->rbuf), hw_buf_avail(&c->rbuf), &req);
	if (r == HW_ERR_AGAIN) return 0;
	if (r < 0) {
		http_reply(c, 400, "Bad Request", "text/plain; charset=utf-8", "bad request\n");
		return 0;
	}
	hw_buf_consume(&c->rbuf, (size_t)r);

	if (!req.is_websocket) {
		if (strcmp(req.path, "/health") == 0) {
			http_reply(c, 200, "OK", "application/json", "{\"status\":\"ok\"}\n");
		} else if (strcmp(req.path, "/stats") == 0) {
			stats_json(c);
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

	resolve_real_ip(c, &req);

	// Per-IP connection rate.
	if (srv->conn_rate && !hw_window_allow(srv->conn_rate, c->ip)) {
		HW_STAT_INC(srv, refused_connection_rate);
		char retry[64];
		snprintf(retry, sizeof(retry), "Retry-After: %d\r\n", cfg->connection_window_s);
		http_reply_x(c, 429, "Too Many Requests", "text/plain; charset=utf-8", retry, "rate limit\n", 11);
		return 0;
	}
	// Reputation gate.
	if (apply_reputation(c) != 0) {
		http_reply(c, 403, "Forbidden", "text/plain; charset=utf-8", "blocked\n");
		return 0;
	}
	// Server-wide concurrent connection cap.
	if (!hw_semaphore_try(&srv->connections)) {
		HW_STAT_INC(srv, refused_connection_limit);
		http_reply(c, 503, "Service Unavailable", "text/plain; charset=utf-8", "at capacity\n");
		return 0;
	}
	c->conn_slot = 1;

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
	c->is_v2 = v2;
	HW_DEBUG("conn", "%s (%s): websocket %s", c->peer, c->ip, v2 ? "wisp-v2" : "wisp-v1");
	if (v2) {
		send_server_info(c);
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

static int password_ok(const hw_server_config *cfg, const char *user, size_t ulen, const char *pass, size_t plen) {
	char userz[64], passz[256];
	if (ulen >= sizeof(userz) || plen >= sizeof(passz)) return 0;
	memcpy(userz, user, ulen);
	userz[ulen] = '\0';
	memcpy(passz, pass, plen);
	passz[plen] = '\0';
	for (int i = 0; i < cfg->password_user_count; i++) {
		const hw_password_user *u = &cfg->password_users[i];
		if (strcmp(u->user, userz) != 0) continue;
		if (u->pass[0] == '$') {
			// crypt(3) hash: hash the candidate with the stored value as its salt and compare.
			char got[256];
			if (hw_sys_crypt(passz, u->pass, got, sizeof(got)) != 0) return 0;
			size_t gl = strlen(got), sl = strlen(u->pass);
			return gl == sl && ct_equal(got, u->pass, gl);
		}
		size_t sl = strlen(u->pass);
		return sl == plen && ct_equal(u->pass, passz, sl);
	}
	return 0;
}

static void handle_info(hw_conn *c, const hw_wisp_packet *p) {
	const hw_server_config *cfg = &c->w->server->cfg;
	hw_wisp_info info;
	if (hw_wisp_parse_info(p, &info) != 0 || info.major != HW_WISP_MAJOR) {
		HW_DEBUG("conn", "%s: incompatible client INFO", c->peer);
		conn_send_close(c, 0, HW_CLOSE_INCOMPATIBLE);
		conn_flush(c); // the CLOSE is deferred like any small frame: write it before the socket goes
		conn_close(c);
		return;
	}
	if (cfg->password_user_count > 0 && info.has_password && info.user) {
		if (!password_ok(cfg, info.user, info.user_len, info.pass, info.pass_len)) {
			HW_INFO("auth", "%s: bad password for '%.*s'", c->peer, (int)HW_MIN(info.user_len, 64), info.user);
			HW_STAT_INC(c->w->server, auth_failures);
			conn_rep_source(c, HW_REP_AUTH_FAILURE);
			conn_send_close(c, 0, HW_CLOSE_AUTH_BAD_PASSWORD);
			conn_flush(c);
			conn_close(c);
			return;
		}
		c->authenticated = 1;
	}
	if (cfg->password_required && !c->authenticated) {
		HW_STAT_INC(c->w->server, auth_failures);
		conn_rep_source(c, HW_REP_AUTH_FAILURE);
		conn_send_close(c, 0, HW_CLOSE_AUTH_REQUIRED);
		conn_flush(c);
		conn_close(c);
		return;
	}
	c->stream_confirm = info.has_stream_confirm;
	handshake_done(c);
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
	if (hw_map_get(&c->streams, p->stream_id)) {
		HW_DEBUG("conn", "%s: duplicate stream %u", c->peer, p->stream_id);
		conn_send_close(c, p->stream_id, HW_CLOSE_INVALID_INFO);
		return;
	}
	if (c->stream_cap > 0 && hw_map_count(&c->streams) >= (size_t)c->stream_cap) {
		conn_violation(c, "per_ws_streams");
		conn_send_close(c, p->stream_id, HW_CLOSE_THROTTLED);
		return;
	}

	// Twisp terminal stream: off unless explicitly enabled, v2, and authenticated. Each gate also
	// feeds reputation, since probing it is a strong abuse signal.
	if (req.stream_type == HW_STREAM_TERM) {
		if (!cfg->enable_twisp || !c->is_v2 || !c->authenticated) {
			HW_WARN("twisp", "%s: terminal stream refused (enabled=%d v2=%d auth=%d)", c->peer, cfg->enable_twisp,
			        c->is_v2, c->authenticated);
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
	while (!c->closing && !c->throttled && !c->read_paused && total < CONN_MAX_READ_PER_EVENT) {
		if (hw_buf_reserve(&c->rbuf, c->read_chunk) != 0) {
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
		conn_process(c);
		if (c->closing) return;
		if ((size_t)n == room) {
			// The client is sending faster than one read takes: offer more room next time, so a
			// burst of frames arrives in one recv and leaves in one write per stream.
			size_t limit = 2 * c->pkt_avg;
			if (limit < CONN_READ_CHUNK_BASE) limit = CONN_READ_CHUNK_BASE;
			if (limit > CONN_READ_CHUNK_MAX) limit = CONN_READ_CHUNK_MAX;
			if (c->read_chunk < limit) c->read_chunk *= 2;
			continue;
		}
		if ((size_t)n < c->read_chunk / 4 && c->read_chunk > HW_READ_CHUNK) {
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
	if ((events & (HW_EV_READ | HW_EV_HUP | HW_EV_ERROR)) && !c->throttled && !c->read_paused) conn_read(c);
}
