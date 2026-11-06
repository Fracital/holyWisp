/*
 * One relayed stream: resolve, connect (trying each address in turn), then shovel bytes both
 * ways. Toward the remote, bytes queue in s->out until the socket takes them; toward the client,
 * they go straight into the connection's write queue.
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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define STREAM_MAX_READS_PER_EVENT 4

static void stream_io_cb(hw_loop *loop, int fd, unsigned events, void *ud);
static void stream_connect_next(hw_stream *s, int last_errno);
static int stream_flush(hw_stream *s);

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

static int stream_update_events(hw_stream *s) {
	unsigned ev = 0;
	if (s->read_armed) ev |= HW_EV_READ;
	if (hw_buf_avail(&s->out) > 0) ev |= HW_EV_WRITE;
	return hw_loop_mod_fd(s->conn->w->loop, s->fd, ev);
}

// ---------------------------------------------------------------------------------- lifecycle

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
	if (s->fd >= 0) {
		hw_loop_del_fd(c->w->loop, s->fd);
		close(s->fd);
		s->fd = -1;
	}
	hw_map_remove(&c->streams, s->id);
	atomic_fetch_sub(&c->w->server->streams_active, 1);
	HW_DEBUG("stream", "%s: stream %u closed: %s", c->peer, s->id, hw_close_reason_str(reason));
	hw_buf_free(&s->out);
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

// ---------------------------------------------------------------------------------- connecting

static void stream_connected(hw_stream *s) {
	hw_conn *c = s->conn;
	s->state = STREAM_OPEN;
	if (s->type == HW_STREAM_TCP) hw_tcp_tune(s->fd, c->w->server->cfg.tcp_nodelay);
	s->read_armed = !c->paused;
	if (stream_update_events(s) != 0) {
		stream_close(s, HW_CLOSE_NETWORK_ERROR, 1);
		return;
	}
	HW_DEBUG("stream", "%s: stream %u open to %s:%u", c->peer, s->id, s->host, s->port);
	if (c->stream_confirm) {
		conn_send_continue(c, s->id, s->remaining);
		if (c->closing) return;
	}
	stream_flush(s);
}

static void connect_timeout_cb(hw_loop *loop, void *ud) {
	hw_stream *s = ud;
	s->connect_timer = NULL;
	hw_loop_del_fd(loop, s->fd);
	close(s->fd);
	s->fd = -1;
	stream_connect_next(s, ETIMEDOUT);
}

// Try the next resolved address. Closes the stream when none is left.
static void stream_connect_next(hw_stream *s, int last_errno) {
	hw_conn *c = s->conn;
	while (s->addr_idx < s->naddrs) {
		const struct sockaddr *sa = (const struct sockaddr *)&s->addrs[s->addr_idx];
		socklen_t sl = s->addr_lens[s->addr_idx];
		s->addr_idx++;
		int socktype = s->type == HW_STREAM_TCP ? SOCK_STREAM : SOCK_DGRAM;
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
		int r = connect(s->fd, sa, sl);
		if (r == 0) {
			stream_connected(s);
			return;
		}
		if (errno == EINPROGRESS) {
			s->state = STREAM_CONNECTING;
			hw_loop_mod_fd(c->w->loop, s->fd, HW_EV_WRITE);
			s->connect_timer = hw_loop_add_timer(c->w->loop, (uint64_t)c->w->server->cfg.connect_timeout_ms, 0,
			                                     connect_timeout_cb, s);
			return;
		}
		last_errno = errno;
		hw_loop_del_fd(c->w->loop, s->fd);
		close(s->fd);
		s->fd = -1;
	}
	HW_DEBUG("stream", "%s: stream %u to %s:%u failed: %s", c->peer, s->id, s->host, s->port, strerror(last_errno));
	stream_close(s, map_errno(last_errno), 1);
}

static void resolve_cb(hw_loop *loop, int gai_err, struct addrinfo *res, void *ud) {
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
	for (struct addrinfo *ai = res; ai && s->naddrs < HW_STREAM_MAX_ADDRS; ai = ai->ai_next) {
		if (ai->ai_addrlen > sizeof(s->addrs[0])) continue;
		if (egress_allowed(&c->w->server->cfg, ai->ai_addr, &blocked) != 0) {
			any_blocked = 1;
			continue;
		}
		memcpy(&s->addrs[s->naddrs], ai->ai_addr, ai->ai_addrlen);
		s->addr_lens[s->naddrs] = ai->ai_addrlen;
		s->naddrs++;
	}
	if (s->naddrs == 0) {
		if (any_blocked) {
			HW_INFO("egress", "%s: blocked %s:%u (%s)", c->peer, s->host, s->port, hw_addr_class_str(blocked));
		}
		stream_close(s, any_blocked ? HW_CLOSE_BLOCKED : HW_CLOSE_UNREACHABLE, 1);
		return;
	}
	stream_connect_next(s, EHOSTUNREACH);
}

void stream_open(hw_conn *c, uint32_t id, uint8_t type, const char *host, size_t host_len, uint16_t port) {
	const hw_server_config *cfg = &c->w->server->cfg;
	hw_stream *s = calloc(1, sizeof(*s));
	if (!s) {
		conn_send_close(c, id, HW_CLOSE_UNKNOWN);
		return;
	}
	s->conn = c;
	s->id = id;
	s->type = type;
	s->fd = -1;
	s->port = port;
	s->remaining = cfg->buffer_remaining;
	hw_buf_init(&s->out);
	memcpy(s->host, host, host_len);
	s->host[host_len] = '\0';
	if (hw_map_put(&c->streams, id, s) != 0) {
		free(s);
		conn_send_close(c, id, HW_CLOSE_UNKNOWN);
		return;
	}
	atomic_fetch_add(&c->w->server->streams_total, 1);
	atomic_fetch_add(&c->w->server->streams_active, 1);

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
			HW_INFO("egress", "%s: blocked direct IP %s:%u", c->peer, s->host, port);
			stream_close(s, HW_CLOSE_BLOCKED, 1);
			return;
		}
		if (egress_allowed(cfg, (struct sockaddr *)&ss, &why) != 0) {
			HW_INFO("egress", "%s: blocked %s:%u (%s)", c->peer, s->host, port, hw_addr_class_str(why));
			stream_close(s, HW_CLOSE_BLOCKED, 1);
			return;
		}
		memcpy(&s->addrs[0], &ss, sl);
		s->addr_lens[0] = sl;
		s->naddrs = 1;
		stream_connect_next(s, EHOSTUNREACH);
		return;
	}
	s->state = STREAM_RESOLVING;
	s->resolve = hw_resolve(c->w->server->resolver, c->w->loop, s->host, port,
	                        type == HW_STREAM_TCP ? SOCK_STREAM : SOCK_DGRAM, resolve_cb, s);
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
		ssize_t n = send(s->fd, head + prefix, chunk, MSG_NOSIGNAL | MSG_DONTWAIT);
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
		ssize_t n = send(s->fd, data, len, MSG_NOSIGNAL | MSG_DONTWAIT);
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
	if (s->type == HW_STREAM_TCP && --s->remaining == 0) {
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
		ssize_t n = recv(s->fd, scratch, HW_READ_CHUNK, MSG_DONTWAIT);
		if (n < 0) {
			if (errno == EINTR) continue;
			if (errno == EAGAIN || errno == EWOULDBLOCK) return;
			if (s->type == HW_STREAM_UDP && errno == ECONNREFUSED) {
				stream_close(s, HW_CLOSE_UNREACHABLE, 1);
				return;
			}
			stream_close(s, map_errno(errno), 1);
			return;
		}
		if (n == 0 && s->type == HW_STREAM_TCP) {
			stream_close(s, HW_CLOSE_VOLUNTARY, 1);
			return;
		}
		conn_send_data(c, s->id, scratch, (size_t)n);
		if (c->closing) return;
		if ((size_t)n < HW_READ_CHUNK && s->type == HW_STREAM_TCP) return; // drained
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
			hw_loop_del_fd(loop, fd);
			close(fd);
			s->fd = -1;
			stream_connect_next(s, err);
			return;
		}
		stream_connected(s);
		return;
	}
	if (s->state != STREAM_OPEN) return;
	if (events & HW_EV_WRITE) {
		if (stream_flush(s) != 0) return;
	}
	if (events & (HW_EV_READ | HW_EV_HUP | HW_EV_ERROR)) stream_read(s);
}
