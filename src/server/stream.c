/*
 * One relayed stream: resolve, apply the per-destination policy, connect (directly or through the
 * upstream proxy, trying each resolved address in turn), then shovel bytes both ways. Toward the
 * remote, bytes queue in s->out until the socket takes them; toward the client, they go straight
 * into the connection's write queue. Terminal (Twisp) streams arrive here already "connected" with
 * a PTY master as the fd and are relayed the same way.
 *
 * Re-entrancy rule: stream_close() frees the stream, and anything that writes to the client may
 * close the connection, which frees every stream. Callers read `hw_conn *c = s->conn` first and
 * test c->closing afterwards instead of touching s again. c->closing says nothing about a stream
 * that was closed alone: a function that can do that (stream_flush, stream_connected,
 * signature_record) reports it in its result, and its caller tests the result, never s->state.
 */
#include "holywisp/hw.h"
#include "holywisp/log.h"
#include "holywisp/sys.h"
#include "holywisp/wisp.h"

#include "internal.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef STREAM_MAX_READS_PER_EVENT
#define STREAM_MAX_READS_PER_EVENT 4
#define STREAM_OUT_KEEP            (256 * 1024)
#endif

static void stream_io_cb(hw_loop *loop, int fd, unsigned events, void *ud);
static void stream_connect_next(hw_stream *s, int last_errno);
static int stream_flush(hw_stream *s);
static void begin_dial(hw_stream *s);

static uint8_t map_errno(int err) {
	switch (err) {
	case ECONNREFUSED:
		return HW_CLOSE_REFUSED;
	case ETIMEDOUT:
		return HW_CLOSE_NO_RESPONSE;
	case ENETUNREACH:
	case EHOSTUNREACH:
	case EADDRNOTAVAIL:
	case EAFNOSUPPORT:
		return HW_CLOSE_UNREACHABLE;
	default:
		return HW_CLOSE_NETWORK_ERROR;
	}
}

static int stream_uses_proxy(const hw_stream *s) {
	return s->conn->w->server->proxy.kind != PROXY_NONE && s->type == HW_STREAM_TCP;
}

// A terminal stream's fd is a PTY master, not a socket, so it takes read()/write(), not
// recv()/send(). Both ends are non-blocking, so the EAGAIN handling is identical.
static ssize_t stream_send(hw_stream *s, const void *buf, size_t len) {
	if (s->type == HW_STREAM_TERM) return write(s->fd, buf, len);
	return send(s->fd, buf, len, HW_MSG_NOSIGNAL | MSG_DONTWAIT);
}

static ssize_t stream_recv(hw_stream *s, void *buf, size_t len) {
	if (s->type == HW_STREAM_TERM) return read(s->fd, buf, len);
	return recv(s->fd, buf, len, MSG_DONTWAIT);
}

static int stream_update_events(hw_stream *s) {
	unsigned ev = 0;
	if (s->read_armed) ev |= HW_EV_READ;
	if (hw_buf_avail(&s->out) > 0) ev |= HW_EV_WRITE;
	if (s->detached) {
		// The socket hung up while its reads were paused and was taken off the loop
		// (stream_io_cb). It goes back when the stream may read again: that read finds what the
		// remote left, then the end or the error, and closes the stream.
		if (!s->read_armed) return 0;
		s->detached = 0;
		return hw_loop_add_fd(s->conn->w->loop, s->fd, ev, stream_io_cb, s);
	}
	return hw_loop_mod_fd(s->conn->w->loop, s->fd, ev);
}

// ---------------------------------------------------------------------------------- lifecycle

// A TCP connect in progress holds one of the server's in-flight slots and one of its client
// address's. Both are held from the dial until the connect resolves (success, failure, timeout).
// Returns 0 with both held, or the reason there is none: 1 the server-wide cap, 2 this client's.
static int syn_acquire(hw_stream *s) {
	hw_conn *c = s->conn;
	hw_server *srv = c->w->server;
	if (s->syn_held) return 0;
	int mine = hw_gauge_acquire(srv->syns_per_ip, c->ip);
	if (mine == 0) return 2;
	if (!hw_semaphore_try(&srv->in_flight_syns)) {
		if (mine == 1) hw_gauge_release(srv->syns_per_ip, c->ip);
		return 1;
	}
	s->syn_held = 1;
	s->syn_ip_held = mine == 1;
	return 0;
}

static void syn_release(hw_stream *s) {
	hw_server *srv = s->conn->w->server;
	if (!s->syn_held) return;
	hw_semaphore_release(&srv->in_flight_syns);
	if (s->syn_ip_held) hw_gauge_release(srv->syns_per_ip, s->conn->ip);
	s->syn_held = 0;
	s->syn_ip_held = 0;
}

hw_stream *stream_new(hw_conn *c, uint32_t id, uint8_t type, const char *host, size_t host_len, uint16_t port) {
	hw_stream *s = calloc(1, sizeof(*s));
	if (!s) {
		conn_send_close(c, id, HW_CLOSE_UNKNOWN);
		return NULL;
	}
	s->conn = c;
	s->id = id;
	s->type = type;
	s->fd = -1;
	s->pid = -1;
	s->port = port;
	s->remaining = c->w->server->window;
	hw_buf_init(&s->out);
	hw_buf_init(&s->pin);
	if (host_len >= sizeof(s->host)) host_len = sizeof(s->host) - 1;
	memcpy(s->host, host, host_len);
	s->host[host_len] = '\0';
	if (hw_map_put(&c->streams, id, s) != 0) {
		hw_buf_free(&s->out);
		hw_buf_free(&s->pin);
		free(s);
		conn_send_close(c, id, HW_CLOSE_UNKNOWN);
		return NULL;
	}
	atomic_fetch_add(&c->w->server->streams_total, 1);
	atomic_fetch_add(&c->w->server->streams_active, 1);
	return s;
}

// Whether the socket toward the remote may be reset when it is closed, which spares this host a
// connection in TIME_WAIT and a local port for every stream that ends (hw_sys_close_reset). Only
// where a reset cannot cost the remote anything the client sent: the client itself ended the
// stream (its CLOSE, or its connection), the remote has spoken since the client last did, so it
// has read what it was answering, and nothing is waiting here to be written. The kernel adds its
// own condition: every byte written has been acknowledged. Never toward an upstream proxy, which
// may still be holding bytes for the destination. A stream the remote ended, or one the server
// closes for a reason of its own, is closed in the ordinary way.
static int stream_may_reset(const hw_stream *s, int send_close) {
	return !send_close && s->type == HW_STREAM_TCP && s->heard && hw_buf_avail(&s->out) == 0 && !stream_uses_proxy(s);
}

void stream_close(hw_stream *s, uint8_t reason, int send_close) {
	hw_conn *c = s->conn;
	if (s->state == STREAM_CLOSED) return;
	s->state = STREAM_CLOSED;
	if (s->connect_timer) {
		hw_loop_cancel_timer(c->w->loop, s->connect_timer);
		s->connect_timer = NULL;
	}
	if (s->resolve) {
		hw_resolve_cancel(s->resolve);
		s->resolve = NULL;
	}
	syn_release(s);
	if (s->type == HW_STREAM_TERM) twisp_kill(s);
	if (s->fd >= 0) {
		hw_loop_del_fd(c->w->loop, s->fd);
		if (stream_may_reset(s, send_close)) {
			hw_sys_close_reset(s->fd);
		} else {
			close(s->fd);
		}
		s->fd = -1;
	}
	hw_map_remove(&c->streams, s->id);
	atomic_fetch_sub(&c->w->server->streams_active, 1);
	HW_DEBUG("stream", "%s: stream %u closed: %s", c->peer, s->id, hw_close_reason_str(reason));
	conn_queue_sub(c, hw_buf_avail(&s->out));
	conn_pipe_drop(s);
	if (c->w->batch_stream == s) { // bytes batched for a stream that is going away are dropped
		c->w->batch_stream = NULL;
		c->w->batch_n = 0;
		c->w->batch_pkts = 0;
	}
	hw_buf_free(&s->out);
	hw_buf_free(&s->pin);
	uint32_t id = s->id;
	free(s);
	if (send_close) conn_send_close(c, id, reason);
}

void stream_pause(hw_stream *s) {
	if (s->state != STREAM_OPEN || !s->read_armed) return;
	s->read_armed = 0;
	stream_update_events(s);
}

void stream_resume(hw_stream *s) {
	if (s->parked) return; // its pipe is still busy: stream_unpark resumes it
	if (s->state != STREAM_OPEN || s->read_armed) return;
	s->read_armed = 1;
	stream_update_events(s);
}

void stream_park(hw_stream *s) {
	s->parked = 1;
	if (s->state != STREAM_OPEN || !s->read_armed) return;
	s->read_armed = 0;
	stream_update_events(s);
}

void stream_unpark(hw_stream *s) {
	if (!s->parked) return;
	s->parked = 0;
	if (!s->conn->paused) stream_resume(s);
}

// ---------------------------------------------------------------------------------- SYN signature

// A connection keeps a record for the destinations it dialled most recently, and no more than
// this many: the records are 2 KiB each and a client can name a new destination with every
// CONNECT. A flood has to keep returning to its target, so its record is never the oldest.
#define SIGDET_MAX_PER_CONN 32

typedef struct sigdet_oldest {
	const char *key;
	hw_sigdet *d;
} sigdet_oldest;

static int sigdet_oldest_visit(const char *key, void *value, void *ud) {
	sigdet_oldest *o = ud;
	hw_sigdet *d = value;
	if (!o->d || hw_sigdet_last(d) < hw_sigdet_last(o->d)) {
		o->key = key;
		o->d = d;
	}
	return 0;
}

static hw_sigdet *sigdet_for(hw_conn *c, const char *dest) {
	hw_sigdet *d = hw_smap_get(&c->sigdets, dest);
	if (d) return d;
	if (hw_smap_count(&c->sigdets) >= SIGDET_MAX_PER_CONN) {
		// Reuse the record that has gone longest without a sample for the new destination.
		sigdet_oldest o = {0};
		hw_smap_each(&c->sigdets, sigdet_oldest_visit, &o);
		if (!o.d) return NULL;
		hw_smap_remove(&c->sigdets, o.key);
		memset(o.d, 0, sizeof(*o.d));
		if (hw_smap_put(&c->sigdets, dest, o.d) != 0) {
			free(o.d);
			return NULL;
		}
		return o.d;
	}
	d = calloc(1, sizeof(*d));
	if (!d || hw_smap_put(&c->sigdets, dest, d) != 0) {
		free(d);
		return NULL;
	}
	return d;
}

// Record a connect outcome against the SYN-flood signature and act on a match. Returns 1 when the
// match closed the whole connection: `s` is freed then, and the caller returns without reading it.
// The result may not be dropped (the connect timeout did, and read the stream it had lost).
HW_MUST_USE static int signature_record(hw_stream *s, int ok) {
	hw_conn *c = s->conn;
	const hw_flood_config *f = &c->w->server->cfg.flood;
	if (!f->enabled || !f->syn_signature_enabled || s->type != HW_STREAM_TCP) return 0;
	hw_sigdet *d = sigdet_for(c, s->dest);
	if (!d) return 0;
	hw_sigdet_record(d, ok, hw_now_ms(), (uint64_t)f->syn_signature_window_ms);
	if (!hw_sigdet_match(d, f->syn_signature_min_samples, f->syn_signature_failed_ratio)) return 0;
	HW_WARN("flood", "%s: SYN-flood signature matched for %s; closing", c->ip, s->dest);
	HW_STAT_INC(c->w->server, syn_signatures);
	conn_rep_source(c, HW_REP_SYN_SIGNATURE);
	conn_rep_dest(c, s->dest, HW_REP_SYN_SIGNATURE);
	conn_close(c);
	return 1;
}

// ---------------------------------------------------------------------------------- connecting

void stream_adopt(hw_stream *s, int fd) {
	hw_conn *c = s->conn;
	s->fd = fd;
	if (hw_loop_add_fd(c->w->loop, fd, 0, stream_io_cb, s) != 0) {
		stream_close(s, HW_CLOSE_NETWORK_ERROR, 1);
		return;
	}
	(void)stream_connected(s);
}

int stream_connected(hw_stream *s) {
	hw_conn *c = s->conn;
	syn_release(s);
	if (s->connect_timer) {
		hw_loop_cancel_timer(c->w->loop, s->connect_timer);
		s->connect_timer = NULL;
	}
	s->state = STREAM_OPEN;
	if (s->type == HW_STREAM_TCP) server_tune_socket(c->w->server, s->fd, 1);
	s->read_armed = !c->paused;
	// With client data already queued, stream_flush below sets the event mask once it knows what
	// is left; setting it here as well would be a second epoll_ctl for every such stream.
	if (hw_buf_avail(&s->out) == 0 && stream_update_events(s) != 0) {
		stream_close(s, HW_CLOSE_NETWORK_ERROR, 1);
		return -1;
	}
	conn_rep_source(c, HW_REP_SUCCESSFUL_STREAM);
	HW_DEBUG("stream", "%s: stream %u open to %s:%u", c->peer, s->id, s->host, s->port);
	if (c->stream_confirm) {
		conn_send_continue(c, s->id, s->remaining);
		if (c->closing) return -1;
	}
	return stream_flush(s); // what the client sent while the dial was in progress
}

// The stream is still waiting for something other than a connect when its time is up: a name
// that has not resolved, or a proxy that has not answered.
static void open_timeout_cb(hw_loop *loop, void *ud) {
	hw_stream *s = ud;
	s->connect_timer = NULL;
	HW_DEBUG("stream", "%s: stream %u to %s:%u: no answer while %s", s->conn->peer, s->id, s->host, s->port,
	         s->state == STREAM_RESOLVING ? "resolving" : "asking the proxy");
	stream_close(s, s->state == STREAM_RESOLVING ? HW_CLOSE_UNREACHABLE : HW_CLOSE_NO_RESPONSE, 1);
}

// A TCP connect (direct or to the proxy) completed. Start the proxy handshake or open directly.
static void connect_succeeded(hw_stream *s) {
	hw_conn *c = s->conn;
	if (stream_uses_proxy(s)) {
		s->state = STREAM_PROXY;
		s->read_armed = 1;
		// Only READ during the handshake: any client data already in s->out must wait until the
		// tunnel is up, and arming WRITE here would busy-loop the worker on the writable socket.
		if (hw_loop_mod_fd(c->w->loop, s->fd, HW_EV_READ) != 0) {
			stream_close(s, HW_CLOSE_NETWORK_ERROR, 1);
			return;
		}
		// The proxy gets as long to answer as a remote gets to accept: a proxy that takes the
		// connection and then says nothing would otherwise hold the stream for good.
		s->connect_timer = hw_loop_add_timer(c->w->loop, (uint64_t)c->w->server->cfg.connect_timeout_ms, 0,
		                                     open_timeout_cb, s);
		proxy_start(s); // closes the stream itself on a write error
		return;
	}
	(void)stream_connected(s);
}

static void connect_timeout_cb(hw_loop *loop, void *ud) {
	hw_stream *s = ud;
	s->connect_timer = NULL;
	syn_release(s);
	hw_loop_del_fd(loop, s->fd);
	close(s->fd);
	s->fd = -1;
	if (signature_record(s, 0)) return; // the match closed the connection, and s went with it
	stream_connect_next(s, ETIMEDOUT);
}

// Per-destination policy for the address about to be dialled (s->dest): rate caps and destination
// reputation. Returns 0 to dial it, or the close reason that address is refused with.
//
// A hit here is not held against the client that ran into it. The caps are per destination and
// shared by every client, so the one that finds a window full is as likely to be a bystander as
// the cause, and a client cannot know what the server has learned about a destination. Counting
// these let one client get others closed and banned, and (by scoring the destination for its own
// popularity) get any destination refused for everyone, for hours. The client that floods is
// counted where it can be told apart: by its own connect rate, in handle_connect.
static uint8_t dest_policy(hw_stream *s) {
	hw_conn *c = s->conn;
	hw_server *srv = c->w->server;
	if (srv->per_dest_sec && !hw_window_allow(srv->per_dest_sec, s->dest)) {
		HW_STAT_INC(srv, throttled_dest);
		return HW_CLOSE_THROTTLED;
	}
	if (srv->per_dest_min && !hw_window_allow(srv->per_dest_min, s->dest)) {
		HW_STAT_INC(srv, throttled_dest);
		return HW_CLOSE_THROTTLED;
	}
	if (srv->reputation) {
		int score = hw_reputation_dest_score(srv->reputation, s->dest);
		if (hw_reputation_tier(srv->reputation, score) == HW_TIER_STRICT) {
			HW_WARN("reputation", "%s: destination %s refused (score %d)", c->ip, s->dest, score);
			return HW_CLOSE_BLOCKED;
		}
	}
	return 0;
}

static void stream_dest_set(hw_stream *s, const struct sockaddr *sa) {
	char ipbuf[HW_IP_STR_LEN];
	hw_addr_ip_str(sa, ipbuf, sizeof(ipbuf));
	snprintf(s->dest, sizeof(s->dest), "%s:%u", ipbuf, s->port);
}

// Try the next resolved address. With the proxy on, "the address" is the proxy and we try it once.
// Each address is put to the destination policy before it is dialled, not only the first: the
// limits are per address, and a name that resolves to several would otherwise be counted against
// one and connected to another.
static void stream_connect_next(hw_stream *s, int last_errno) {
	hw_conn *c = s->conn;
	hw_server *srv = c->w->server;
	int proxying = stream_uses_proxy(s);
	for (;;) {
		const struct sockaddr *sa;
		socklen_t sl;
		if (proxying) {
			if (s->addr_idx >= 1) break; // one shot at the proxy
			s->addr_idx = 1;             // target for proxy_start is addrs[0]
			stream_dest_set(s, (const struct sockaddr *)&s->addrs[0]);
			sa = (const struct sockaddr *)&srv->proxy.addr;
			sl = srv->proxy.addr_len;
		} else {
			if (s->addr_idx >= s->naddrs) break;
			sa = (const struct sockaddr *)&s->addrs[s->addr_idx];
			sl = s->addr_lens[s->addr_idx];
			s->addr_idx++;
			stream_dest_set(s, sa);
		}
		uint8_t denied = dest_policy(s);
		if (denied) {
			s->denied = denied;
			continue;
		}
		int socktype = s->type == HW_STREAM_UDP ? SOCK_DGRAM : SOCK_STREAM;
		s->fd = hw_socket_nb(sa->sa_family, socktype, 0);
		if (s->fd < 0) {
			last_errno = errno;
			continue;
		}
		if (s->type == HW_STREAM_TCP) {
			int full = syn_acquire(s);
			if (full) {
				HW_STAT_INC(srv, throttled_syns);
				close(s->fd);
				s->fd = -1;
				// Only the client's own cap is the client's doing. The server-wide one is full
				// because of everyone, and whoever arrives last is not to blame for it.
				if (full == 2) {
					conn_violation(c, "in_flight_syns_per_ip");
					if (c->closing) return;
				}
				stream_close(s, HW_CLOSE_THROTTLED, 1);
				return;
			}
		}
		s->denied = 0; // an address is being dialled: the stream ends with what the dial finds
		int r = connect(s->fd, sa, sl);
		last_errno = r == 0 ? 0 : errno;
		if (r == 0 || last_errno == EINPROGRESS) {
			// The socket joins the loop only now, with the interest it needs: one epoll_ctl where
			// adding it first and arming it after the connect() would be two for every stream.
			if (hw_loop_add_fd(c->w->loop, s->fd, r == 0 ? 0 : HW_EV_WRITE, stream_io_cb, s) == 0) {
				if (r == 0) {
					if (signature_record(s, 1)) return;
					connect_succeeded(s);
					return;
				}
				s->state = STREAM_CONNECTING;
				s->connect_timer = hw_loop_add_timer(c->w->loop, (uint64_t)srv->cfg.connect_timeout_ms, 0,
				                                     connect_timeout_cb, s);
				return;
			}
			last_errno = errno;
		}
		syn_release(s);
		close(s->fd);
		s->fd = -1;
	}
	if (s->denied) {
		// Nothing was dialled after the policy refused an address: that refusal is the answer.
		stream_close(s, s->denied, 1);
		return;
	}
	if (signature_record(s, 0)) return;
	HW_DEBUG("stream", "%s: stream %u to %s:%u failed: %s", c->peer, s->id, s->host, s->port, strerror(last_errno));
	if (srv->cfg.flood.log_blocked_dials) {
		HW_INFO("flood", "%s: dial to %s:%u failed: %s", c->ip, s->host, s->port, strerror(last_errno));
	}
	stream_close(s, map_errno(last_errno), 1);
}

static void begin_dial(hw_stream *s) {
	stream_connect_next(s, EHOSTUNREACH);
}

static void resolve_cb(hw_loop *loop, int gai_err, const hw_dns_result *res, void *ud) {
	hw_stream *s = ud;
	hw_conn *c = s->conn;
	s->resolve = NULL;
	if (s->connect_timer) {
		hw_loop_cancel_timer(loop, s->connect_timer);
		s->connect_timer = NULL;
	}
	if (gai_err != 0) {
		HW_DEBUG("stream", "%s: stream %u: resolve %s: %s", c->peer, s->id, s->host, gai_strerror(gai_err));
		stream_close(s, HW_CLOSE_UNREACHABLE, 1);
		return;
	}
	enum hw_addr_class blocked = HW_ADDR_PUBLIC;
	int any_blocked = 0;
	for (int i = 0; i < res->count && s->naddrs < HW_STREAM_MAX_ADDRS; i++) {
		if (egress_allowed(&c->w->server->cfg, (const struct sockaddr *)&res->addrs[i], &blocked) != 0) {
			any_blocked = 1;
			continue;
		}
		memcpy(&s->addrs[s->naddrs], &res->addrs[i], res->lens[i]);
		s->addr_lens[s->naddrs] = res->lens[i];
		s->naddrs++;
	}
	if (s->naddrs == 0) {
		if (any_blocked) {
			HW_INFO("egress", "%s: blocked %s:%u (%s)", c->ip, s->host, s->port, hw_addr_class_str(blocked));
			HW_STAT_INC(c->w->server, blocked_egress);
			conn_rep_source(c, HW_REP_PRIVATE_EGRESS);
		}
		stream_close(s, any_blocked ? HW_CLOSE_BLOCKED : HW_CLOSE_UNREACHABLE, 1);
		return;
	}
	begin_dial(s);
}

// Host/port allow and block lists. Returns 0 when the target is permitted.
static int filter_ok(const hw_server_config *cfg, const char *host, size_t host_len, uint16_t port) {
	if (cfg->allow_hosts.count > 0) {
		if (!hw_hostlist_allows(&cfg->allow_hosts, host, host_len)) return -1;
	} else if (hw_hostlist_blocks(&cfg->block_hosts, host, host_len)) {
		return -1;
	}
	if (cfg->allow_ports.count > 0) {
		if (!hw_portset_has(&cfg->allow_ports, port)) return -1;
	} else if (cfg->block_ports.count > 0 && hw_portset_has(&cfg->block_ports, port)) {
		return -1;
	}
	return 0;
}

void stream_open(hw_conn *c, uint32_t id, uint8_t type, const char *host, size_t host_len, uint16_t port) {
	const hw_server_config *cfg = &c->w->server->cfg;
	if (port == 0) {
		conn_send_close(c, id, HW_CLOSE_INVALID_INFO);
		return;
	}
	if (type == HW_STREAM_UDP && c->w->server->proxy.kind != PROXY_NONE && !cfg->proxy_udp_direct) {
		// SOCKS5 UDP associate is not implemented; refuse rather than leak around the proxy unless
		// the operator asked for exactly that (proxy-udp = direct).
		conn_send_close(c, id, HW_CLOSE_BLOCKED);
		return;
	}
	if (filter_ok(cfg, host, host_len, port) != 0) {
		HW_INFO("filter", "%s: blocked %.*s:%u", c->ip, (int)host_len, host, port);
		HW_STAT_INC(c->w->server, blocked_filter);
		conn_send_close(c, id, HW_CLOSE_BLOCKED);
		return;
	}
	hw_stream *s = stream_new(c, id, type, host, host_len, port);
	if (!s) return;

	struct sockaddr_storage ss;
	socklen_t sl = 0;
	int literal = hw_addr_parse(s->host, port, &ss, &sl);
	if (literal < 0) {
		stream_close(s, HW_CLOSE_INVALID_INFO, 1);
		return;
	}
	s->literal_host = literal;
	if (literal) {
		enum hw_addr_class why;
		if (!cfg->allow_direct_ip) {
			HW_INFO("egress", "%s: blocked direct IP %s:%u", c->ip, s->host, port);
			HW_STAT_INC(c->w->server, blocked_egress);
			stream_close(s, HW_CLOSE_BLOCKED, 1);
			return;
		}
		if (egress_allowed(cfg, (struct sockaddr *)&ss, &why) != 0) {
			HW_INFO("egress", "%s: blocked %s:%u (%s)", c->ip, s->host, port, hw_addr_class_str(why));
			HW_STAT_INC(c->w->server, blocked_egress);
			conn_rep_source(c, HW_REP_PRIVATE_EGRESS);
			stream_close(s, HW_CLOSE_BLOCKED, 1);
			return;
		}
		memcpy(&s->addrs[0], &ss, sl);
		s->addr_lens[0] = sl;
		s->naddrs = 1;
		begin_dial(s);
		return;
	}
	s->state = STREAM_RESOLVING;
	s->resolve = hw_resolve(c->w->server->resolver, c->w->loop, s->host, port, resolve_cb, s);
	if (!s->resolve) {
		stream_close(s, HW_CLOSE_UNKNOWN, 1);
		return;
	}
	// The resolver has its own timeouts, but not for the time a request waits its turn.
	s->connect_timer = hw_loop_add_timer(c->w->loop, (uint64_t)cfg->connect_timeout_ms, 0, open_timeout_cb, s);
}

// ---------------------------------------------------------------------------------- client -> remote

// Drain s->out into the socket. Returns 0 when the stream is still alive, -1 when it was closed.
static int stream_flush(hw_stream *s) {
	hw_conn *c = s->conn;
	while (hw_buf_avail(&s->out) > 0) {
		const uint8_t *head = hw_buf_head(&s->out);
		size_t avail = hw_buf_avail(&s->out);
		size_t chunk = avail;
		size_t prefix = 0;
		if (s->type == HW_STREAM_UDP) {
			// Datagram boundaries are kept with a length prefix.
			if (avail < 4) break;
			chunk = hw_le32(head);
			prefix = 4;
			if (avail < 4 + chunk) break;
		}
		ssize_t n = stream_send(s, head + prefix, chunk);
		if (n >= 0) {
			size_t took = s->type == HW_STREAM_UDP ? prefix + chunk : (size_t)n;
			hw_buf_consume(&s->out, took);
			conn_queue_sub(c, took);
			continue;
		}
		if (errno == EINTR) continue;
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			stream_update_events(s);
			return 0;
		}
		stream_close(s, map_errno(errno), 1);
		return -1;
	}
	stream_update_events(s);
	hw_buf_shrink(&s->out, STREAM_OUT_KEEP); // drained: a burst's allocation is not kept for the stream's life
	if (s->continue_due) {
		s->continue_due = 0;
		conn_send_continue(c, s->id, s->remaining);
		if (c->closing) return -1;
	}
	return 0;
}

void stream_batch_flush(hw_worker *w) {
	int cnt = w->batch_n;
	if (cnt == 0) return;
	hw_stream *s = w->batch_stream;
	int pkts = w->batch_pkts;
	w->batch_n = 0;
	w->batch_pkts = 0;
	w->batch_stream = NULL;
	hw_conn *c = s->conn;
	size_t total = 0;
	for (int i = 0; i < cnt; i++) total += w->batch_iov[i].iov_len;

	ssize_t n;
	if (cnt == 1) {
		n = send(s->fd, w->batch_iov[0].iov_base, w->batch_iov[0].iov_len, HW_MSG_NOSIGNAL | MSG_DONTWAIT);
	} else {
		struct msghdr mh = {.msg_iov = w->batch_iov, .msg_iovlen = (size_t)cnt};
		n = sendmsg(s->fd, &mh, HW_MSG_NOSIGNAL | MSG_DONTWAIT);
	}
	if (n < 0) {
		if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
			stream_close(s, map_errno(errno), 1);
			return;
		}
		n = 0;
	}
	if ((size_t)n < total) {
		// The socket is full: the rest waits in s->out, which was empty when the batch began.
		size_t rest = total - (size_t)n;
		if (rest + 4 > c->w->server->cfg.stream_queue_max) {
			HW_DEBUG("stream", "%s: stream %u throttled (%zu bytes to queue)", c->peer, s->id, rest);
			stream_close(s, HW_CLOSE_THROTTLED, 1);
			return;
		}
		size_t skip = (size_t)n;
		for (int i = 0; i < cnt; i++) {
			const uint8_t *base = w->batch_iov[i].iov_base;
			size_t len = w->batch_iov[i].iov_len;
			if (skip >= len) {
				skip -= len;
				continue;
			}
			if (hw_buf_append(&s->out, base + skip, len - skip) != 0) {
				stream_close(s, HW_CLOSE_UNKNOWN, 1);
				return;
			}
			skip = 0;
		}
		conn_queue_add(c, rest);
		stream_update_events(s);
	}
	// Flow control, one count per packet: a CONTINUE once the window is spent, held back while
	// the remote is slow.
	int spent = 0;
	for (int i = 0; i < pkts; i++) {
		if (--s->remaining == 0) {
			s->remaining = conn_window(c);
			spent = 1;
		}
	}
	if (!spent) return;
	if (hw_buf_avail(&s->out) == 0) {
		conn_send_continue(c, s->id, s->remaining);
	} else {
		s->continue_due = 1;
	}
}

void stream_on_data(hw_stream *s, const uint8_t *data, size_t len) {
	stream_on_data_part(s, data, len, 1);
}

void stream_on_data_part(hw_stream *s, const uint8_t *data, size_t len, int final) {
	hw_conn *c = s->conn;
	hw_worker *w = c->w;
	const hw_server_config *cfg = &w->server->cfg;
	if (s->state == STREAM_CLOSED) return;
	s->heard = 0;

	if (w->batch_n > 0 && w->batch_stream != s) {
		stream_batch_flush(w);
		if (c->closing) return;
	}
	if (s->type == HW_STREAM_TCP && s->state == STREAM_OPEN && hw_buf_avail(&s->out) == 0) {
		// The common case: an idle socket. Consecutive packets for it go out in one write.
		w->batch_stream = s;
		w->batch_iov[w->batch_n].iov_base = (void *)(uintptr_t)data;
		w->batch_iov[w->batch_n].iov_len = len;
		w->batch_pkts += final;
		if (++w->batch_n == HW_BATCH_MAX) stream_batch_flush(w);
		return;
	}

	int queued = hw_buf_avail(&s->out) > 0 || s->state != STREAM_OPEN;
	if (!queued) {
		// Fast path: the socket is idle, hand the bytes straight to the kernel.
		ssize_t n = stream_send(s, data, len);
		if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
			if (s->type == HW_STREAM_UDP && (errno == EMSGSIZE || errno == ECONNREFUSED)) {
				n = (ssize_t)len; // the datagram is lost either way; the stream lives on
			} else {
				stream_close(s, map_errno(errno), 1);
				return;
			}
		}
		if (n < 0) n = 0;
		if (s->type == HW_STREAM_UDP) {
			n = (ssize_t)len; // a datagram is all or nothing
		}
		data += n;
		len -= (size_t)n;
		queued = len > 0;
	}
	if (queued && len > 0) {
		if (hw_buf_avail(&s->out) + len + 4 > cfg->stream_queue_max) {
			HW_DEBUG("stream", "%s: stream %u throttled (%zu bytes queued)", c->peer, s->id, hw_buf_avail(&s->out));
			stream_close(s, HW_CLOSE_THROTTLED, 1);
			return;
		}
		int r = 0;
		if (s->type == HW_STREAM_UDP) {
			uint8_t prefix[4];
			hw_put_le32(prefix, (uint32_t)len);
			r |= hw_buf_append(&s->out, prefix, 4);
		}
		r |= hw_buf_append(&s->out, data, len);
		if (r != 0) {
			stream_close(s, HW_CLOSE_UNKNOWN, 1);
			return;
		}
		conn_queue_add(c, s->type == HW_STREAM_UDP ? len + 4 : len);
		if (s->state == STREAM_OPEN) stream_update_events(s);
	}

	// Flow control: one CONTINUE per window of packets, held back while the remote is slow.
	if (s->type != HW_STREAM_UDP && final && --s->remaining == 0) {
		s->remaining = conn_window(c);
		if (hw_buf_avail(&s->out) == 0) {
			conn_send_continue(c, s->id, s->remaining);
		} else {
			s->continue_due = 1;
		}
	}
}

// ---------------------------------------------------------------------------------- remote -> client

// Two ways to move remote bytes to the client. Copying (recv into scratch, frame into wbuf) costs
// two syscalls and one copy per read and suits small or sporadic reads. Splicing through the
// worker's pipe costs three syscalls and no copy, which only pays off when every read is large,
// so a stream switches to it after a full read and back after a small one.
#define STREAM_BULK_ON     HW_READ_CHUNK
#define STREAM_BULK_OFF    (16 * 1024)
#define STREAM_BULK_MISSES 16

static void stream_read(hw_stream *s) {
	hw_conn *c = s->conn;
	if (s->type == HW_STREAM_TCP && s->bulk) {
		int copy = 0; // finish this event on the copying path
		// One event relays up to STREAM_MAX_READS_PER_EVENT pipes' worth, in however many packets
		// that takes: a connection that is given small packets does the same work per event.
		size_t done = 0;
		size_t budget = STREAM_MAX_READS_PER_EVENT * (size_t)1024 * 1024;
		while (done < budget && s->read_armed && !copy) {
			ssize_t n = conn_splice_data(c, s);
			if (s->pipe) budget = STREAM_MAX_READS_PER_EVENT * s->pipe->size;
			if (n == -3) {
				// The previous payload is still in the pipe, so the client is not keeping up.
				// The bytes stay in the kernel until the queue has written it.
				stream_park(s);
				return;
			}
			if (n == -2) { // no pipe to be had: copy
				copy = 1;
				break;
			}
			if (c->closing) return;
			if (n == 0) {
				stream_close(s, HW_CLOSE_VOLUNTARY, 1);
				return;
			}
			if (n < 0) {
				if (errno == EINTR) continue;
				if (errno == EAGAIN || errno == EWOULDBLOCK) return;
				stream_close(s, map_errno(errno), 1);
				return;
			}
			s->heard = 1;
			done += (size_t)n;
			// One small splice does not end bulk mode: right after a switch the remote's data is
			// still arriving in pieces, and leaving on the first of them would flap between the
			// two paths for the rest of the transfer. A run of them does.
			if ((size_t)n >= STREAM_BULK_OFF) {
				s->bulk_miss = 0;
			} else if (++s->bulk_miss >= STREAM_BULK_MISSES) {
				s->bulk = 0;
				s->bulk_miss = 0;
			}
			if ((size_t)n < HW_READ_CHUNK) return; // drained
		}
		if (!copy || !s->read_armed) return;
	}
	uint8_t *scratch = c->w->scratch;
	for (int i = 0; i < STREAM_MAX_READS_PER_EVENT && s->read_armed; i++) {
		ssize_t n = stream_recv(s, scratch, HW_READ_CHUNK);
		if (n < 0) {
			if (errno == EINTR) continue;
			if (errno == EAGAIN || errno == EWOULDBLOCK) return;
			if (s->type == HW_STREAM_UDP && errno == ECONNREFUSED) {
				stream_close(s, HW_CLOSE_UNREACHABLE, 1);
				return;
			}
			// A PTY master returns EIO when the child has exited: a clean close, not an error.
			if (s->type == HW_STREAM_TERM && errno == EIO) {
				stream_close(s, HW_CLOSE_VOLUNTARY, 1);
				return;
			}
			stream_close(s, map_errno(errno), 1);
			return;
		}
		if (n == 0 && s->type != HW_STREAM_UDP) {
			stream_close(s, HW_CLOSE_VOLUNTARY, 1);
			return;
		}
		s->heard = 1;
		conn_send_data(c, s->id, scratch, (size_t)n);
		if (c->closing) return;
		if ((size_t)n >= STREAM_BULK_ON && s->type == HW_STREAM_TCP) s->bulk = 1;
		if ((size_t)n < HW_READ_CHUNK && s->type != HW_STREAM_UDP) return; // drained
	}
}

static void stream_io_cb(hw_loop *loop, int fd, unsigned events, void *ud) {
	hw_stream *s = ud;
	hw_conn *c = s->conn;
	if (c->closing) return;

	if (s->state == STREAM_CONNECTING) {
		int err = 0;
		socklen_t el = sizeof(err);
		if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &el) != 0) err = errno;
		// An error event is a failed connect even when SO_ERROR reads clean: a backend may have
		// collected the error to report it. So is a hang-up on a socket that never became writable.
		if (err == 0 && ((events & HW_EV_ERROR) || ((events & HW_EV_HUP) && !(events & HW_EV_WRITE)))) {
			err = ECONNREFUSED;
		}
		if (s->connect_timer) {
			hw_loop_cancel_timer(loop, s->connect_timer);
			s->connect_timer = NULL;
		}
		if (err != 0) {
			syn_release(s);
			hw_loop_del_fd(loop, fd);
			close(fd);
			s->fd = -1;
			if (signature_record(s, 0)) return;
			stream_connect_next(s, err);
			return;
		}
		if (signature_record(s, 1)) return;
		connect_succeeded(s);
		return;
	}
	if (s->state == STREAM_PROXY) {
		if (events & (HW_EV_READ | HW_EV_HUP | HW_EV_ERROR)) {
			uint8_t buf[4096];
			ssize_t n = recv(fd, buf, sizeof(buf), MSG_DONTWAIT);
			if (n > 0) {
				proxy_on_data(s, buf, (size_t)n);
			} else if (n == 0) {
				stream_close(s, HW_CLOSE_NETWORK_ERROR, 1);
			} else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
				stream_close(s, map_errno(errno), 1);
			}
		}
		return;
	}
	if (s->state != STREAM_OPEN) return;
	if (!s->read_armed && (events & (HW_EV_HUP | HW_EV_ERROR))) {
		// The remote reset or hung up while this stream may not read (the client is not taking
		// what is already queued for it). The condition is level-triggered and nothing here can
		// clear it, so the loop would report it without end: stop watching the socket until
		// reads resume (stream_update_events). What the remote sent before stays in the kernel.
		hw_loop_del_fd(loop, fd);
		s->detached = 1;
		return;
	}
	if (events & HW_EV_WRITE) {
		if (stream_flush(s) != 0) return;
	}
	if (events & (HW_EV_READ | HW_EV_HUP | HW_EV_ERROR)) stream_read(s);
}
