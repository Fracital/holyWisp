/*
 * One relayed stream: resolve, apply the per-destination policy, connect (directly or through the
 * upstream proxy, trying each resolved address in turn), then shovel bytes both ways. Toward the
 * remote, bytes queue in s->out until the socket takes them; toward the client, they go straight
 * into the connection's write queue. Terminal (Twisp) streams arrive here already "connected" with
 * a PTY master as the fd and are relayed the same way.
 *
 * Re-entrancy rule: stream_close() frees the stream, and anything that writes to the client may
 * close the connection, which frees every stream. Callers read `hw_conn *c = s->conn` first and
 * test c->closing afterwards instead of touching s again.
 */
#include "holywisp/hw.h"
#include "holywisp/log.h"
#include "holywisp/wisp.h"

#include "internal.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define STREAM_MAX_READS_PER_EVENT 4

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
	return send(s->fd, buf, len, MSG_NOSIGNAL | MSG_DONTWAIT);
}

static ssize_t stream_recv(hw_stream *s, void *buf, size_t len) {
	if (s->type == HW_STREAM_TERM) return read(s->fd, buf, len);
	return recv(s->fd, buf, len, MSG_DONTWAIT);
}

static int stream_update_events(hw_stream *s) {
	unsigned ev = 0;
	if (s->read_armed) ev |= HW_EV_READ;
	if (hw_buf_avail(&s->out) > 0) ev |= HW_EV_WRITE;
	return hw_loop_mod_fd(s->conn->w->loop, s->fd, ev);
}

// ---------------------------------------------------------------------------------- lifecycle

hw_stream *stream_new(hw_conn *c, uint32_t id, uint8_t type, const char *host, size_t host_len, uint16_t port) {
	const hw_server_config *cfg = &c->w->server->cfg;
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
	s->remaining = cfg->buffer_remaining;
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
	if (s->syn_held) {
		hw_semaphore_release(&c->w->server->in_flight_syns);
		s->syn_held = 0;
	}
	if (s->type == HW_STREAM_TERM) twisp_kill(s);
	if (s->fd >= 0) {
		hw_loop_del_fd(c->w->loop, s->fd);
		close(s->fd);
		s->fd = -1;
	}
	hw_map_remove(&c->streams, s->id);
	atomic_fetch_sub(&c->w->server->streams_active, 1);
	HW_DEBUG("stream", "%s: stream %u closed: %s", c->peer, s->id, hw_close_reason_str(reason));
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
	if (s->state != STREAM_OPEN || s->read_armed) return;
	s->read_armed = 1;
	stream_update_events(s);
}

// ---------------------------------------------------------------------------------- SYN signature

static hw_sigdet *sigdet_for(hw_conn *c, const char *dest) {
	hw_sigdet *d = hw_smap_get(&c->sigdets, dest);
	if (d) return d;
	d = calloc(1, sizeof(*d));
	if (!d || hw_smap_put(&c->sigdets, dest, d) != 0) {
		free(d);
		return NULL;
	}
	return d;
}

// Record a connect outcome against the SYN-flood signature and act on a match. Returns 1 when the
// match closed the whole connection.
static int signature_record(hw_stream *s, int ok) {
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
	stream_connected(s);
}

void stream_connected(hw_stream *s) {
	hw_conn *c = s->conn;
	if (s->syn_held) {
		hw_semaphore_release(&c->w->server->in_flight_syns);
		s->syn_held = 0;
	}
	if (s->connect_timer) {
		hw_loop_cancel_timer(c->w->loop, s->connect_timer);
		s->connect_timer = NULL;
	}
	s->state = STREAM_OPEN;
	if (s->type == HW_STREAM_TCP) server_tune_socket(c->w->server, s->fd, 1);
	s->read_armed = !c->paused;
	if (stream_update_events(s) != 0) {
		stream_close(s, HW_CLOSE_NETWORK_ERROR, 1);
		return;
	}
	conn_rep_source(c, HW_REP_SUCCESSFUL_STREAM);
	HW_DEBUG("stream", "%s: stream %u open to %s:%u", c->peer, s->id, s->host, s->port);
	if (c->stream_confirm) {
		conn_send_continue(c, s->id, s->remaining);
		if (c->closing) return;
	}
	stream_flush(s);
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
		proxy_start(s); // closes the stream itself on a write error
		return;
	}
	stream_connected(s);
}

static void connect_timeout_cb(hw_loop *loop, void *ud) {
	hw_stream *s = ud;
	s->connect_timer = NULL;
	hw_loop_del_fd(loop, s->fd);
	close(s->fd);
	s->fd = -1;
	signature_record(s, 0);
	if (s->state == STREAM_CLOSED) return;
	stream_connect_next(s, ETIMEDOUT);
}

// Try the next resolved address. With the proxy on, "the address" is the proxy and we try it once.
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
			sa = (const struct sockaddr *)&srv->proxy.addr;
			sl = srv->proxy.addr_len;
		} else {
			if (s->addr_idx >= s->naddrs) break;
			sa = (const struct sockaddr *)&s->addrs[s->addr_idx];
			sl = s->addr_lens[s->addr_idx];
			s->addr_idx++;
		}
		int socktype = s->type == HW_STREAM_UDP ? SOCK_DGRAM : SOCK_STREAM;
		s->fd = hw_socket_nb(sa->sa_family, socktype, 0);
		if (s->fd < 0) {
			last_errno = errno;
			continue;
		}
		if (hw_loop_add_fd(c->w->loop, s->fd, 0, stream_io_cb, s) != 0) {
			last_errno = errno;
			close(s->fd);
			s->fd = -1;
			continue;
		}
		// In-flight SYN cap: held from here until the connect resolves (success, failure, timeout).
		if (s->type == HW_STREAM_TCP && !s->syn_held) {
			if (!hw_semaphore_try(&srv->in_flight_syns)) {
				HW_STAT_INC(srv, throttled_syns);
				hw_loop_del_fd(c->w->loop, s->fd);
				close(s->fd);
				s->fd = -1;
				conn_violation(c, "in_flight_syns");
				if (c->closing) return;
				stream_close(s, HW_CLOSE_THROTTLED, 1);
				return;
			}
			s->syn_held = 1;
		}
		int r = connect(s->fd, sa, sl);
		if (r == 0) {
			if (signature_record(s, 1)) return;
			connect_succeeded(s);
			return;
		}
		if (errno == EINPROGRESS) {
			s->state = STREAM_CONNECTING;
			hw_loop_mod_fd(c->w->loop, s->fd, HW_EV_WRITE);
			s->connect_timer = hw_loop_add_timer(c->w->loop, (uint64_t)srv->cfg.connect_timeout_ms, 0,
			                                     connect_timeout_cb, s);
			return;
		}
		last_errno = errno;
		if (s->syn_held) {
			hw_semaphore_release(&srv->in_flight_syns);
			s->syn_held = 0;
		}
		hw_loop_del_fd(c->w->loop, s->fd);
		close(s->fd);
		s->fd = -1;
	}
	if (signature_record(s, 0)) return;
	HW_DEBUG("stream", "%s: stream %u to %s:%u failed: %s", c->peer, s->id, s->host, s->port, strerror(last_errno));
	if (srv->cfg.flood.log_blocked_dials) {
		HW_INFO("flood", "%s: dial to %s:%u failed: %s", c->ip, s->host, s->port, strerror(last_errno));
	}
	stream_close(s, map_errno(last_errno), 1);
}

// Per-destination policy once the address set is known: rate caps and destination reputation.
// Returns 0 to proceed, -1 when the stream was closed.
static int dest_policy(hw_stream *s) {
	hw_conn *c = s->conn;
	hw_server *srv = c->w->server;
	char ipbuf[HW_IP_STR_LEN];
	hw_addr_ip_str((const struct sockaddr *)&s->addrs[0], ipbuf, sizeof(ipbuf));
	snprintf(s->dest, sizeof(s->dest), "%s:%u", ipbuf, s->port);

	if (srv->per_dest_sec && !hw_window_allow(srv->per_dest_sec, s->dest)) {
		HW_STAT_INC(srv, throttled_dest);
		conn_rep_source(c, HW_REP_BURST_RATE);
		conn_rep_dest(c, s->dest, HW_REP_BURST_RATE);
		conn_violation(c, "per_dest_sec");
		if (c->closing) return -1;
		stream_close(s, HW_CLOSE_THROTTLED, 1);
		return -1;
	}
	if (srv->per_dest_min && !hw_window_allow(srv->per_dest_min, s->dest)) {
		HW_STAT_INC(srv, throttled_dest);
		stream_close(s, HW_CLOSE_THROTTLED, 1);
		return -1;
	}
	if (srv->reputation) {
		int score = hw_reputation_dest_score(srv->reputation, s->dest);
		if (hw_reputation_tier(srv->reputation, score) == HW_TIER_STRICT) {
			HW_WARN("reputation", "%s: destination %s refused (score %d)", c->ip, s->dest, score);
			conn_rep_source(c, HW_REP_KNOWN_BAD_DEST);
			stream_close(s, HW_CLOSE_BLOCKED, 1);
			return -1;
		}
	}
	return 0;
}

static void begin_dial(hw_stream *s) {
	if (dest_policy(s) != 0) return;
	stream_connect_next(s, EHOSTUNREACH);
}

static void resolve_cb(hw_loop *loop, int gai_err, const hw_dns_result *res, void *ud) {
	hw_stream *s = ud;
	hw_conn *c = s->conn;
	s->resolve = NULL;
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
		if (!hw_hostlist_match(&cfg->allow_hosts, host, host_len)) return -1;
	} else if (hw_hostlist_match(&cfg->block_hosts, host, host_len)) {
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
	if (type == HW_STREAM_UDP && c->w->server->proxy.kind != PROXY_NONE) {
		// SOCKS5 UDP associate is not implemented; refuse rather than leak around the proxy.
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
	if (!s->resolve) stream_close(s, HW_CLOSE_UNKNOWN, 1);
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
			hw_buf_consume(&s->out, s->type == HW_STREAM_UDP ? prefix + chunk : (size_t)n);
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
	if (s->continue_due) {
		s->continue_due = 0;
		conn_send_continue(c, s->id, s->remaining);
		if (c->closing) return -1;
	}
	return 0;
}

void stream_on_data(hw_stream *s, const uint8_t *data, size_t len) {
	hw_conn *c = s->conn;
	const hw_server_config *cfg = &c->w->server->cfg;
	if (s->state == STREAM_CLOSED) return;

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
		if (s->state == STREAM_OPEN) stream_update_events(s);
	}

	// Flow control: one CONTINUE per window of packets, held back while the remote is slow.
	if (s->type != HW_STREAM_UDP && --s->remaining == 0) {
		s->remaining = cfg->buffer_remaining;
		if (hw_buf_avail(&s->out) == 0) {
			conn_send_continue(c, s->id, s->remaining);
		} else {
			s->continue_due = 1;
		}
	}
}

// ---------------------------------------------------------------------------------- remote -> client

static void stream_read(hw_stream *s) {
	hw_conn *c = s->conn;
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
		conn_send_data(c, s->id, scratch, (size_t)n);
		if (c->closing) return;
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
		if (err == 0 && (events & (HW_EV_ERROR | HW_EV_HUP)) && !(events & HW_EV_WRITE)) err = ECONNREFUSED;
		if (s->connect_timer) {
			hw_loop_cancel_timer(loop, s->connect_timer);
			s->connect_timer = NULL;
		}
		if (err != 0) {
			if (s->syn_held) {
				hw_semaphore_release(&c->w->server->in_flight_syns);
				s->syn_held = 0;
			}
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
	if (events & HW_EV_WRITE) {
		if (stream_flush(s) != 0) return;
	}
	if (events & (HW_EV_READ | HW_EV_HUP | HW_EV_ERROR)) stream_read(s);
}
