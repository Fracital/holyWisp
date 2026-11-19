/*
 * client/wt_client.h implementation: the client roles of holywisp/quic.h and holywisp/webtransport.h
 * on a blocking caller's clock. Single-threaded, like the rest of the client.
 */
#include "wt_client.h"

#include "holywisp/buf.h"
#include "holywisp/hw.h"
#include "holywisp/net.h"
#include "holywisp/quic.h"
#include "holywisp/sys.h"
#include "holywisp/webtransport.h"
#include "holywisp/wisp.h"

#include <errno.h>
#include <limits.h>
#include <netdb.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>

#define WTC_RX_SLOT        4096
#define WTC_RX_GRO         16                  // receive slots with GRO, HW_SYS_GRO_SLOT each
#define WTC_SOCKET_BUFFER  (4 * 1024 * 1024)   // the server's flight, and ours, without drops (wt_listener.c)
#define WTC_WINDOW         (32u * 1024 * 1024) // the server's credit, and the client's own send buffer
#define WTC_SEND_MAX       (8u * 1024 * 1024)  // queued in hw_wt before a send waits
#define WTC_IDLE_MS        30000
#define WTC_KEEPALIVE      15000
#define WTC_ATTEMPT_MS     5000 // with no deadline, how long an address that gives no answer is waited for
#define WTC_PACING_TICK_US 100  // how late a wait for QUIC's timer ends: the listener's (wt_listener.c)
#define WTC_FOREVER        UINT64_MAX

struct hw_wtc {
	int fd;
	hw_quic_conn *q;
	hw_wt *wt;
	int closed;           // the session or the connection is over
	uint64_t close_error; // QUIC's error code when the connection closed, and whether it was the application's
	int close_app;
	int heard;     // a datagram came from the server (hw_wtc_connect: this address answers)
	int net_error; // the last error the socket reported (an ICMP unreachable), 0 for none
	int writable;  // hw_wt said its queue went down since the last look
	int paused;
	size_t max_queue;
	hw_buf in;      // packets not handed out yet: [u32 LE length][packet] each
	size_t pending; // bytes of `in` handed out by the last hw_wtc_next, consumed on the next
	uint8_t tx[HW_SYS_BATCH_MAX][HW_QUIC_MAX_DGRAM];
	hw_sys_dgram txd[HW_SYS_BATCH_MAX];
	uint8_t *rx; // rx_slots slots of rx_cap bytes: HW_SYS_BATCH_MAX small ones, or with GRO fewer large ones
	size_t rx_slots, rx_cap;
	hw_sys_dgram rxd[HW_SYS_BATCH_MAX];
	char authority[300];
};

// ---- callbacks: QUIC's go to hw_wt, hw_wt's are recorded

static void q_established(void *ud) {
	hw_wtc *t = ud;
	if (t->wt) hw_wt_on_established(t->wt);
}

static void q_stream_data(void *ud, uint64_t id, const uint8_t *data, size_t len, int fin) {
	hw_wtc *t = ud;
	if (t->wt) hw_wt_on_stream_data(t->wt, id, data, len, fin);
}

static void q_stream_reset(void *ud, uint64_t id, uint64_t app_error) {
	hw_wtc *t = ud;
	if (t->wt) hw_wt_on_stream_reset(t->wt, id, app_error);
}

static void q_stream_stop(void *ud, uint64_t id, uint64_t app_error) {
	hw_wtc *t = ud;
	if (t->wt) hw_wt_on_stream_stop(t->wt, id, app_error);
}

static void q_stream_writable(void *ud, uint64_t id) {
	hw_wtc *t = ud;
	if (t->wt) hw_wt_on_stream_writable(t->wt, id);
}

static void q_datagram(void *ud, const uint8_t *data, size_t len) {
	hw_wtc *t = ud;
	if (t->wt) hw_wt_on_datagram(t->wt, data, len);
}

static void q_cid(void *ud, const uint8_t cid[HW_QUIC_CID_LEN], int retire) {
	(void)ud;
	(void)cid;
	(void)retire;
}

static void q_closed(void *ud, uint64_t error, int app, const char *reason) {
	hw_wtc *t = ud;
	(void)reason; // the peer's bytes; err is printed
	t->closed = 1;
	t->close_error = error;
	t->close_app = app;
	if (t->wt) hw_wt_on_closed(t->wt);
}

static void w_packet(void *ud, const uint8_t *data, size_t len, int datagram) {
	hw_wtc *t = ud;
	(void)datagram;
	uint8_t hdr[4];
	hw_put_le32(hdr, (uint32_t)len);
	if (hw_buf_append(&t->in, hdr, sizeof(hdr)) != 0 || hw_buf_append(&t->in, data, len) != 0) {
		t->closed = 1; // out of memory: nothing sane can follow
		return;
	}
	// The caller is not taking them as fast as they come: hold the server back instead.
	if (!t->paused && hw_buf_avail(&t->in) > t->max_queue) {
		t->paused = 1;
		hw_wt_pause(t->wt, 1);
	}
}

static void w_writable(void *ud) {
	hw_wtc *t = ud;
	t->writable = 1;
}

static void w_session_closed(void *ud, uint32_t code, const char *reason) {
	hw_wtc *t = ud;
	(void)code;
	(void)reason;
	t->closed = 1;
}

// A lane that ends ends the Wisp connection, whichever it was (a LANE_REFUSED among them).
static void w_lane_ended(void *ud, int lane) {
	hw_wtc *t = ud;
	(void)lane;
	t->closed = 1;
}

// ---- I/O

// Send what is batched. A full socket buffer is waited on briefly; what still does not go is
// lost, and QUIC's loss recovery sends it again.
static void wtc_tx_flush(hw_wtc *t, size_t n) {
	size_t off = 0;
	int tries = 0;
	while (off < n) {
		int r = hw_sys_send_batch(t->fd, t->txd + off, n - off);
		if (r > 0) {
			off += (size_t)r;
			continue;
		}
		if ((errno != EAGAIN && errno != EWOULDBLOCK) || ++tries > 2) {
			if (errno != EAGAIN && errno != EWOULDBLOCK) t->net_error = errno;
			off++; // refused (no route, say) or still full: dropped, as the network would
			tries = 0;
			continue;
		}
		struct pollfd p = {.fd = t->fd, .events = POLLOUT};
		poll(&p, 1, 50);
	}
}

// Everything QUIC will send now, in batches (the socket is connected, so the destination is known).
// One call is one release of the pacer and starts a run of its own, as on the server.
static void wtc_output(hw_wtc *t) {
	uint64_t now = hw_now_us(); // BBR times its rate samples with this clock (holywisp/quic.h)
	size_t n = 0;
	int first = 1;
	for (;;) {
		hw_sys_dgram *d = &t->txd[n];
		struct sockaddr_storage to;
		socklen_t tl = sizeof(to);
		d->buf = t->tx[n];
		d->len = hw_quic_output_us(t->q, d->buf, sizeof(t->tx[n]), &to, &tl, now);
		if (d->len == 0) break;
		d->addr_len = 0;
		d->alone = hw_quic_output_alone(t->q);
		d->run_start = first;
		first = 0;
		if (++n == HW_SYS_BATCH_MAX) {
			wtc_tx_flush(t, n);
			n = 0;
		}
	}
	if (n) wtc_tx_flush(t, n);
}

// Microseconds from now until at (hw_now_us's clock), -1 for UINT64_MAX.
static int64_t wtc_wait_until(uint64_t at) {
	if (at == UINT64_MAX) return -1;
	uint64_t now = hw_now_us();
	return at <= now ? 0 : (int64_t)HW_MIN(at - now, (uint64_t)INT64_MAX);
}

// Wait for the socket or QUIC's next timer, at most until deadline, and act on what came. 1 when
// something was read or a timer ran, 0 when the deadline came first. QUIC's timer is waited for in
// microseconds: the pacer's next release is often a few hundred of them away.
static int wtc_pump(hw_wtc *t, uint64_t deadline) {
	uint64_t at = hw_quic_timeout_us(t->q);
	uint64_t until = deadline == WTC_FOREVER ? WTC_FOREVER : deadline * 1000;
	if (at < until) until = at;
	struct pollfd p = {.fd = t->fd, .events = POLLIN};
	int r = hw_sys_poll_us(&p, 1, wtc_wait_until(until));
	if (r < 0 && errno != EINTR) {
		t->closed = 1;
		return 1;
	}
	int did = 0;
	if (r > 0) {
		for (;;) {
			for (size_t i = 0; i < t->rx_slots; i++) {
				t->rxd[i].buf = t->rx + i * t->rx_cap;
				t->rxd[i].cap = t->rx_cap;
			}
			int n = hw_sys_recv_batch(t->fd, t->rxd, t->rx_slots);
			if (n < 0) {
				if (errno == EAGAIN || errno == EWOULDBLOCK) break;
				t->net_error = errno;
				continue; // an ICMP error taken off the socket; the next receive goes on
			}
			if (n > 0) t->heard = 1;
			uint64_t now_us = hw_now_us();
			for (int i = 0; i < n; i++) {
				// A coalesced read is the server's datagrams back to back, each taken on its own.
				hw_sys_dgram *d = &t->rxd[i];
				size_t seg = d->segment ? d->segment : d->len;
				for (size_t off = 0; off < d->len; off += seg) {
					hw_quic_input_us(t->q, d->buf + off, HW_MIN(seg, d->len - off), (struct sockaddr *)&d->addr,
					                 d->addr_len, now_us);
				}
			}
			did = 1;
			if ((size_t)n < t->rx_slots) break;
		}
	}
	uint64_t now_us = hw_now_us();
	if (now_us >= hw_quic_timeout_us(t->q)) {
		hw_quic_on_timeout_us(t->q, now_us);
		did = 1;
	}
	wtc_output(t);
	return did || now_us / 1000 < deadline;
}

// Let go of one address's attempt: the session, the connection, the socket and what they held.
static void wtc_reset(hw_wtc *t) {
	if (t->wt) hw_wt_free(t->wt);
	if (t->q) hw_quic_free(t->q);
	if (t->fd >= 0) close(t->fd);
	free(t->rx);
	t->wt = NULL;
	t->q = NULL;
	t->fd = -1;
	t->rx = NULL;
	t->closed = 0;
	t->close_error = 0;
	t->close_app = 0;
	t->heard = 0;
	t->net_error = 0;
	t->writable = 0;
	t->paused = 0;
	t->pending = 0;
	hw_buf_clear(&t->in);
}

// One address: the socket, QUIC and the session, until the session is open (0), the address has
// given no answer by give_up (1: the caller tries the next one), or the attempt has failed for
// good (-1: the server answered and refused, or the deadline came). err says why unless 0.
static int wtc_attempt(hw_wtc *t, const hw_wtc_opts *o, const struct addrinfo *ai, const char *sni, uint64_t give_up,
                       uint64_t deadline, char *err, size_t err_cap) {
	static const char *const alpn[] = {HW_WT_ALPN};
	t->fd = hw_sys_socket(ai->ai_family, SOCK_DGRAM, 0, 1);
	if (t->fd < 0 || connect(t->fd, ai->ai_addr, ai->ai_addrlen) != 0) {
		// No route for this family, say: the next address may have one.
		snprintf(err, err_cap, "udp %s:%u: %s", o->host, o->port, strerror(errno));
		return 1;
	}
	hw_sys_udp_buffers(t->fd, (int)HW_MIN(o->udp_buffer ? o->udp_buffer : WTC_SOCKET_BUFFER, (size_t)INT_MAX));
	(void)hw_sys_udp_no_fragment(t->fd); // the datagram size is probed, never left to fragmentation
	int gro = hw_sys_udp_gro(t->fd);
	t->rx_slots = gro ? WTC_RX_GRO : HW_SYS_BATCH_MAX;
	t->rx_cap = gro ? HW_SYS_GRO_SLOT : WTC_RX_SLOT;
	t->rx = malloc(t->rx_slots * t->rx_cap);
	if (!t->rx) {
		snprintf(err, err_cap, "out of memory");
		return -1;
	}
	hw_quic_config qc;
	memset(&qc, 0, sizeof(qc));
	qc.tls.alpn = alpn;
	qc.tls.alpn_count = 1;
	qc.tls.server_name = sni;
	qc.tls.pin_sha256 = o->pin_sha256;
	qc.tls.key_pins_sha256 = o->key_pins_sha256;
	qc.tls.key_pin_count = o->key_pin_count;
	qc.max_idle_ms = WTC_IDLE_MS;
	qc.initial_max_data = WTC_WINDOW;
	qc.initial_max_stream_data = WTC_WINDOW;
	qc.initial_max_streams_bidi = 16;
	qc.initial_max_streams_uni = 16;
	qc.max_datagram_frame_size = 65535;
	qc.stream_send_max = WTC_WINDOW;
	qc.conn_send_max = WTC_WINDOW;
	qc.datagram_queue_max = 256;
	qc.keepalive_ms = WTC_KEEPALIVE;
	unsigned tick = hw_sys_poll_resolution_us();
	qc.timer_tick_us = tick > WTC_PACING_TICK_US ? tick : WTC_PACING_TICK_US;
	hw_quic_callbacks cb = {
	    .ud = t,
	    .established = q_established,
	    .stream_data = q_stream_data,
	    .stream_reset = q_stream_reset,
	    .stream_stop = q_stream_stop,
	    .stream_writable = q_stream_writable,
	    .datagram = q_datagram,
	    .cid = q_cid,
	    .closed = q_closed,
	};
	t->q = hw_quic_connect(&qc, &cb, ai->ai_addr, ai->ai_addrlen, hw_now_ms());
	if (!t->q) {
		snprintf(err, err_cap, "cannot start a QUIC connection");
		return -1;
	}
	hw_wt_config wc = {
	    .max_packet = o->max_packet ? o->max_packet : 1024 * 1024 + HW_WISP_HEADER_LEN,
	    .send_max = WTC_SEND_MAX,
	    .is_client = 1,
	    .authority = t->authority,
	    .path = o->path && o->path[0] ? o->path : "/",
	    .origin = o->origin,
	    .protocols = o->protocols,
	};
	hw_wt_callbacks wcb = {
	    .ud = t,
	    .packet = w_packet,
	    .writable = w_writable,
	    .session_closed = w_session_closed,
	    .lane_ended = w_lane_ended,
	};
	t->wt = hw_wt_new(t->q, &wc, &wcb);
	if (!t->wt) {
		snprintf(err, err_cap, "out of memory");
		return -1;
	}
	wtc_output(t);
	while (!hw_wt_ready(t->wt)) {
		int status = hw_wt_status(t->wt);
		if (status != 0 && status != 200) {
			snprintf(err, err_cap, "server answered %d", status);
			return -1;
		}
		if (t->closed) {
			if (!t->close_app && t->close_error >= HW_QUIC_CRYPTO_ERROR(0) &&
			    t->close_error <= HW_QUIC_CRYPTO_ERROR(255)) {
				snprintf(err, err_cap, "TLS handshake failed (alert %u)%s",
				         (unsigned)(t->close_error - HW_QUIC_CRYPTO_ERROR(0)),
				         o->pin_sha256 || o->key_pin_count ? ": the certificate may not match the pin" : "");
			} else {
				snprintf(err, err_cap, "the connection closed during the handshake (error 0x%llx)",
				         (unsigned long long)t->close_error);
			}
			return -1;
		}
		if (!t->heard && t->net_error) {
			// Port or host unreachable, and nothing has come back from there.
			snprintf(err, err_cap, "udp %s:%u: %s", o->host, o->port, strerror(t->net_error));
			return 1;
		}
		// Until the address answers it has its share of the time; once it has, all of it.
		uint64_t until = t->heard ? deadline : HW_MIN(give_up, deadline);
		if (hw_now_ms() >= until || !wtc_pump(t, until)) {
			if (!t->heard && hw_now_ms() < deadline) {
				snprintf(err, err_cap, "no answer from %s:%u", o->host, o->port);
				return 1;
			}
			snprintf(err, err_cap, "webtransport handshake timed out");
			return -1;
		}
	}
	return 0;
}

hw_wtc *hw_wtc_connect(const hw_wtc_opts *o, uint64_t deadline, char *err, size_t err_cap) {
	hw_wtc *t = calloc(1, sizeof(*t));
	if (!t) {
		snprintf(err, err_cap, "out of memory");
		return NULL;
	}
	t->fd = -1;
	t->max_queue = o->max_queue ? o->max_queue : 32u * 1024 * 1024;
	hw_buf_init(&t->in);
	struct addrinfo hints, *res = NULL;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_NUMERICSERV;
	char service[8];
	snprintf(service, sizeof(service), "%u", o->port);
	if (getaddrinfo(o->host, service, &hints, &res) != 0 || !res) {
		snprintf(err, err_cap, "cannot resolve %s", o->host);
		goto fail;
	}
	const char *name = o->server_name && o->server_name[0] ? o->server_name : o->host;
	struct sockaddr_storage literal;
	socklen_t literal_len;
	const char *sni = hw_addr_parse(name, o->port, &literal, &literal_len) == 1 ? NULL
	                                                                            : name; // never an address (RFC 6066)
	if (strchr(name, ':')) {
		snprintf(t->authority, sizeof(t->authority), "[%s]:%u", name, o->port);
	} else {
		snprintf(t->authority, sizeof(t->authority), "%s:%u", name, o->port);
	}
	// Every address, in the resolver's order. One that gives no answer has its share of the time
	// that is left (the last one all of it), so a family without a route here costs a share and
	// not the whole handshake, and the next address still has time. An address that answers keeps
	// the rest: its server's refusal, or a TLS handshake that fails, is final.
	size_t left = 0;
	for (const struct addrinfo *ai = res; ai; ai = ai->ai_next) left++;
	int r = 1;
	for (const struct addrinfo *ai = res; ai && r == 1; ai = ai->ai_next, left--) {
		uint64_t now = hw_now_ms();
		if (ai != res) {
			if (now >= deadline) break;
			wtc_reset(t);
		}
		uint64_t share = deadline == WTC_FOREVER ? WTC_ATTEMPT_MS : (deadline > now ? deadline - now : 0) / left;
		uint64_t give_up = left == 1 ? deadline : now + share;
		r = wtc_attempt(t, o, ai, sni, give_up, deadline, err, err_cap);
	}
	freeaddrinfo(res);
	if (r != 0) goto fail;
	return t;
fail:
	hw_wtc_free(t);
	return NULL;
}

void hw_wtc_free(hw_wtc *t) {
	if (!t) return;
	if (t->wt && !t->closed && hw_wt_ready(t->wt)) {
		// The capsule and FIN go out; the client does not stay for the server's answer.
		hw_wt_close(t->wt, 0, "");
		wtc_output(t);
	}
	if (t->wt) hw_wt_free(t->wt);
	if (t->q) hw_quic_free(t->q);
	if (t->fd >= 0) close(t->fd);
	hw_buf_free(&t->in);
	free(t->rx);
	free(t);
}

int hw_wtc_send(hw_wtc *t, int lane, const uint8_t *pkt, size_t len, int unreliable, uint64_t deadline) {
	for (;;) {
		if (t->closed) return HW_ERR_CLOSED;
		int r = hw_wt_send_lane(t->wt, lane, pkt, len, unreliable);
		if (r == 0) {
			wtc_output(t);
			return 0;
		}
		if (r < 0) return HW_ERR_CLOSED;
		t->writable = 0;
		while (!t->writable && !t->closed) {
			if (hw_now_ms() >= deadline || !wtc_pump(t, deadline)) return HW_ERR_TIMEOUT;
		}
	}
}

int hw_wtc_next(hw_wtc *t, uint64_t deadline, int *has_read, const uint8_t **pkt, size_t *len) {
	if (t->pending) {
		hw_buf_consume(&t->in, t->pending);
		t->pending = 0;
		if (t->paused && hw_buf_avail(&t->in) < t->max_queue / 2) {
			t->paused = 0;
			hw_wt_pause(t->wt, 0);
			wtc_output(t);
		}
	}
	for (;;) {
		size_t avail = hw_buf_avail(&t->in);
		if (avail >= 4) {
			const uint8_t *p = hw_buf_head(&t->in);
			uint32_t n = hw_le32(p);
			*pkt = p + 4;
			*len = n;
			t->pending = 4 + (size_t)n;
			return 1;
		}
		if (t->closed) return HW_ERR_CLOSED;
		if (*has_read && hw_now_ms() >= deadline) return 0;
		int did = wtc_pump(t, deadline);
		*has_read = 1;
		if (!did && hw_buf_avail(&t->in) < 4 && !t->closed) return 0;
	}
}

int hw_wtc_open_lanes(hw_wtc *t, int lanes) {
	int open = 1;
	if (lanes > HW_WT_LANES_MAX) lanes = HW_WT_LANES_MAX;
	while (open < lanes && !t->closed && hw_wt_open_lane(t->wt, open) == 0) open++;
	wtc_output(t);
	return open;
}

int hw_wtc_server_stream(const hw_wtc *t) {
	return hw_wt_server_stream(t->wt);
}

const char *hw_wtc_protocol(const hw_wtc *t) {
	return hw_wt_protocol(t->wt);
}

int hw_wtc_fd(const hw_wtc *t) {
	return t->fd;
}

int hw_wtc_wait_ms(const hw_wtc *t) {
	uint64_t at = hw_quic_timeout(t->q);
	if (at == WTC_FOREVER) return -1;
	uint64_t now = hw_now_ms();
	return at <= now ? 0 : (int)HW_MIN(at - now, (uint64_t)INT_MAX);
}

int64_t hw_wtc_wait_us(const hw_wtc *t) {
	return wtc_wait_until(hw_quic_timeout_us(t->q));
}
