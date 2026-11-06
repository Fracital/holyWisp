/*
 * holywisp/client.h implementation. Blocking, single-threaded; see the header for the model.
 */
#include "holywisp/client.h"

#include "holywisp/base64.h"
#include "holywisp/buf.h"
#include "holywisp/hw.h"
#include "holywisp/net.h"
#include "holywisp/wisp.h"
#include "holywisp/ws.h"

#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define CLIENT_READ_CHUNK (64 * 1024)

typedef struct cstream {
	uint32_t id;
	uint8_t type;
	uint32_t remaining;
} cstream;

typedef struct qevent {
	hw_client_event ev;
	uint8_t *data; // owned copy of ev.data
	struct qevent *next;
} qevent;

struct hw_client {
	int fd;
	int closed;
	int is_v2;
	int server_udp;
	uint32_t buffer_size;
	char motd[512];
	size_t max_message;

	hw_buf rbuf;
	size_t pending_consume; // bytes of rbuf handed out by the last read, consumed on the next
	hw_buf frag;
	hw_buf sbuf; // scratch for masked frames

	cstream *streams;
	size_t nstreams;
	size_t streams_cap;
	uint32_t next_id;

	qevent *qhead;
	qevent *qtail;
	qevent *last; // the event handed out by the last poll; freed on the next
	uint64_t rng;
};

void hw_client_opts_defaults(hw_client_opts *o) {
	memset(o, 0, sizeof(*o));
	o->host = "127.0.0.1";
	o->port = 6001;
	o->path = "/";
	o->timeout_ms = 10000;
	o->max_message = 1024 * 1024 + HW_WISP_HEADER_LEN;
}

// ---------------------------------------------------------------------------------- helpers

static uint32_t rng_next(hw_client *c) {
	// xorshift64*: mask keys only need to be unpredictable enough to defeat proxy caches.
	c->rng ^= c->rng >> 12;
	c->rng ^= c->rng << 25;
	c->rng ^= c->rng >> 27;
	return (uint32_t)((c->rng * 0x2545F4914F6CDD1Dull) >> 32);
}

static void seed_rng(hw_client *c) {
	uint64_t seed = 0;
	FILE *f = fopen("/dev/urandom", "rb");
	if (f) {
		if (fread(&seed, sizeof(seed), 1, f) != 1) seed = 0;
		fclose(f);
	}
	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);
	seed ^= (uint64_t)ts.tv_nsec << 20 ^ (uint64_t)ts.tv_sec ^ (uint64_t)getpid() << 48;
	c->rng = seed ? seed : 0x9E3779B97F4A7C15ull;
}

static int send_all(hw_client *c, const uint8_t *data, size_t len) {
	while (len > 0) {
		ssize_t n = send(c->fd, data, len, MSG_NOSIGNAL);
		if (n < 0) {
			if (errno == EINTR) continue;
			c->closed = 1;
			return HW_ERR_CLOSED;
		}
		data += n;
		len -= (size_t)n;
	}
	return 0;
}

// Send one masked binary frame: the Wisp packet header followed by payload.
static int send_frame(hw_client *c, uint8_t opcode, const uint8_t *hdr, size_t hdr_len, const uint8_t *payload,
                      size_t len) {
	if (c->closed) return HW_ERR_CLOSED;
	size_t total = hdr_len + len;
	uint8_t mask[4];
	uint32_t m = rng_next(c);
	memcpy(mask, &m, 4);
	hw_buf_clear(&c->sbuf);
	if (hw_buf_reserve(&c->sbuf, HW_WS_MAX_HEADER + total) != 0) return HW_ERR_NOMEM;
	uint8_t *p = hw_buf_tail(&c->sbuf);
	size_t hl = hw_ws_write_header(p, 1, opcode, total, mask);
	memcpy(p + hl, hdr, hdr_len);
	if (len) memcpy(p + hl + hdr_len, payload, len);
	hw_ws_mask(p + hl, total, mask, 0);
	return send_all(c, p, hl + total);
}

static int send_packet(hw_client *c, const uint8_t *packet, size_t len) {
	return send_frame(c, HW_WS_BINARY, packet, len, NULL, 0);
}

static cstream *stream_find(hw_client *c, uint32_t id) {
	for (size_t i = 0; i < c->nstreams; i++) {
		if (c->streams[i].id == id) return &c->streams[i];
	}
	return NULL;
}

static void stream_forget(hw_client *c, uint32_t id) {
	for (size_t i = 0; i < c->nstreams; i++) {
		if (c->streams[i].id == id) {
			c->streams[i] = c->streams[c->nstreams - 1];
			c->nstreams--;
			return;
		}
	}
}

// Wait until the socket is readable. 1 ready, 0 timeout, <0 error.
static int wait_readable(hw_client *c, int timeout_ms) {
	struct pollfd pfd = {.fd = c->fd, .events = POLLIN};
	for (;;) {
		int r = poll(&pfd, 1, timeout_ms);
		if (r < 0 && errno == EINTR) continue;
		if (r < 0) return HW_ERR_IO;
		return r > 0;
	}
}

// Read one complete WebSocket message. *data points into rbuf/frag until the next call.
// 1 message, 0 timeout, HW_ERR_CLOSED, HW_ERR_PROTOCOL.
static int read_message(hw_client *c, int timeout_ms, const uint8_t **data, size_t *len) {
	if (c->pending_consume) {
		hw_buf_consume(&c->rbuf, c->pending_consume);
		c->pending_consume = 0;
	}
	if (c->closed) return HW_ERR_CLOSED;
	uint64_t deadline = timeout_ms < 0 ? 0 : hw_now_ms() + (uint64_t)timeout_ms;
	for (;;) {
		hw_ws_frame f;
		int r = hw_ws_parse_header(hw_buf_head(&c->rbuf), hw_buf_avail(&c->rbuf), &f);
		if (r > 0) {
			if (f.masked || f.payload_len > c->max_message) {
				c->closed = 1;
				return HW_ERR_PROTOCOL;
			}
			size_t total = f.header_len + (size_t)f.payload_len;
			if (hw_buf_avail(&c->rbuf) >= total) {
				const uint8_t *payload = hw_buf_head(&c->rbuf) + f.header_len;
				size_t plen = (size_t)f.payload_len;
				switch (f.opcode) {
				case HW_WS_BINARY:
					if (f.fin) {
						*data = payload;
						*len = plen;
						c->pending_consume = total;
						return 1;
					}
					c->frag.len = 0;
					c->frag.off = 0;
					if (hw_buf_append(&c->frag, payload, plen) != 0) return HW_ERR_NOMEM;
					hw_buf_consume(&c->rbuf, total);
					continue;
				case HW_WS_CONTINUATION:
					if (hw_buf_avail(&c->frag) + plen > c->max_message) {
						c->closed = 1;
						return HW_ERR_PROTOCOL;
					}
					if (hw_buf_append(&c->frag, payload, plen) != 0) return HW_ERR_NOMEM;
					hw_buf_consume(&c->rbuf, total);
					if (f.fin) {
						*data = hw_buf_head(&c->frag);
						*len = hw_buf_avail(&c->frag);
						return 1;
					}
					continue;
				case HW_WS_PING:
					send_frame(c, HW_WS_PONG, payload, plen, NULL, 0);
					hw_buf_consume(&c->rbuf, total);
					continue;
				case HW_WS_PONG:
					hw_buf_consume(&c->rbuf, total);
					continue;
				case HW_WS_CLOSE: {
					uint8_t reply[2] = {0x03, 0xE8};
					if (plen >= 2) memcpy(reply, payload, 2);
					send_frame(c, HW_WS_CLOSE, reply, 2, NULL, 0);
					c->closed = 1;
					return HW_ERR_CLOSED;
				}
				default:
					c->closed = 1;
					return HW_ERR_PROTOCOL;
				}
			}
			if (hw_buf_reserve(&c->rbuf, total - hw_buf_avail(&c->rbuf)) != 0) return HW_ERR_NOMEM;
		} else if (r != HW_ERR_AGAIN) {
			c->closed = 1;
			return HW_ERR_PROTOCOL;
		}

		// Even a zero timeout gets one poll: a readable socket must be drained, not reported as idle.
		int wait = -1;
		if (timeout_ms >= 0) {
			uint64_t now = hw_now_ms();
			wait = now >= deadline ? 0 : (int)(deadline - now);
		}
		int ready = wait_readable(c, wait);
		if (ready <= 0) return ready;
		if (hw_buf_reserve(&c->rbuf, CLIENT_READ_CHUNK) != 0) return HW_ERR_NOMEM;
		ssize_t n = recv(c->fd, hw_buf_tail(&c->rbuf), hw_buf_room(&c->rbuf), 0);
		if (n == 0 || (n < 0 && errno != EINTR && errno != EAGAIN)) {
			c->closed = 1;
			return HW_ERR_CLOSED;
		}
		if (n > 0) hw_buf_commit(&c->rbuf, (size_t)n);
	}
}

// Bookkeeping common to every incoming Wisp packet; fills ev (data pointing into the message).
static int packet_to_event(hw_client *c, const uint8_t *msg, size_t len, hw_client_event *ev) {
	hw_wisp_packet p;
	if (hw_wisp_parse(msg, len, &p) != 0) return 0;
	memset(ev, 0, sizeof(*ev));
	ev->stream_id = p.stream_id;
	switch (p.type) {
	case HW_WISP_DATA:
		ev->type = HW_CEV_DATA;
		ev->data = p.payload;
		ev->len = p.payload_len;
		return 1;
	case HW_WISP_CONTINUE: {
		if (p.payload_len < 4) return 0;
		ev->type = HW_CEV_CONTINUE;
		ev->buffer_remaining = hw_le32(p.payload);
		cstream *s = stream_find(c, p.stream_id);
		if (s) s->remaining = ev->buffer_remaining;
		if (p.stream_id == 0) c->buffer_size = ev->buffer_remaining;
		return 1;
	}
	case HW_WISP_CLOSE:
		if (p.payload_len < 1) return 0;
		ev->type = HW_CEV_CLOSE;
		ev->reason = p.payload[0];
		stream_forget(c, p.stream_id);
		if (p.stream_id == 0) c->closed = 1;
		return 1;
	default:
		return 0;
	}
}

static qevent *qevent_new(const hw_client_event *ev) {
	qevent *q = calloc(1, sizeof(*q));
	if (!q) return NULL;
	q->ev = *ev;
	if (ev->type == HW_CEV_DATA && ev->len) {
		q->data = malloc(ev->len);
		if (!q->data) {
			free(q);
			return NULL;
		}
		memcpy(q->data, ev->data, ev->len);
		q->ev.data = q->data;
	}
	return q;
}

static void queue_push(hw_client *c, qevent *q) {
	q->next = NULL;
	if (c->qtail) {
		c->qtail->next = q;
	} else {
		c->qhead = q;
	}
	c->qtail = q;
}

static qevent *queue_pop(hw_client *c) {
	qevent *q = c->qhead;
	if (!q) return NULL;
	c->qhead = q->next;
	if (!c->qhead) c->qtail = NULL;
	return q;
}

static void qevent_free(qevent *q) {
	if (!q) return;
	free(q->data);
	free(q);
}

// Read the next packet from the socket and queue it as an event. 1 queued, 0 timeout, <0 error.
static int pump_one(hw_client *c, int timeout_ms) {
	const uint8_t *msg;
	size_t len;
	for (;;) {
		int r = read_message(c, timeout_ms, &msg, &len);
		if (r <= 0) return r;
		hw_client_event ev;
		if (!packet_to_event(c, msg, len, &ev)) continue;
		qevent *q = qevent_new(&ev);
		if (!q) return HW_ERR_NOMEM;
		queue_push(c, q);
		return 1;
	}
}

// ---------------------------------------------------------------------------------- handshake

static int do_upgrade(hw_client *c, const hw_client_opts *o, char *err, size_t err_cap) {
	uint8_t raw[16];
	for (int i = 0; i < 4; i++) {
		uint32_t v = rng_next(c);
		memcpy(raw + i * 4, &v, 4);
	}
	char key[HW_BASE64_LEN(16)];
	hw_base64_encode(raw, sizeof(raw), key, sizeof(key));
	char req[1024];
	size_t n = hw_http_write_upgrade(req, sizeof(req), o->host, o->port, o->path, key,
	                                 o->v2 ? HW_WISP_V2_PROTOCOL : NULL);
	if (n == 0 || send_all(c, (const uint8_t *)req, n) != 0) {
		snprintf(err, err_cap, "cannot send upgrade request: %s", strerror(errno));
		return -1;
	}
	char accept[HW_WS_ACCEPT_LEN + 1];
	hw_ws_accept_key(key, accept);
	uint64_t deadline = hw_now_ms() + (uint64_t)o->timeout_ms;
	for (;;) {
		char proto[64];
		int r = hw_http_parse_upgrade_response(hw_buf_head(&c->rbuf), hw_buf_avail(&c->rbuf), accept, proto,
		                                       sizeof(proto));
		if (r > 0) {
			hw_buf_consume(&c->rbuf, (size_t)r);
			c->is_v2 = strcmp(proto, HW_WISP_V2_PROTOCOL) == 0;
			if (o->v2 && !c->is_v2) {
				snprintf(err, err_cap, "server did not accept %s", HW_WISP_V2_PROTOCOL);
				return -1;
			}
			return 0;
		}
		if (r != HW_ERR_AGAIN) {
			snprintf(err, err_cap, "bad upgrade response: %.*s", (int)HW_MIN(hw_buf_avail(&c->rbuf), 64),
			         (const char *)hw_buf_head(&c->rbuf));
			return -1;
		}
		uint64_t now = hw_now_ms();
		if (now >= deadline) {
			snprintf(err, err_cap, "upgrade timed out");
			return -1;
		}
		int ready = wait_readable(c, (int)(deadline - now));
		if (ready <= 0) {
			snprintf(err, err_cap, "upgrade timed out");
			return -1;
		}
		if (hw_buf_reserve(&c->rbuf, 4096) != 0) return -1;
		ssize_t got = recv(c->fd, hw_buf_tail(&c->rbuf), hw_buf_room(&c->rbuf), 0);
		if (got <= 0) {
			snprintf(err, err_cap, "server closed during upgrade");
			return -1;
		}
		hw_buf_commit(&c->rbuf, (size_t)got);
	}
}

// Wait for the server's CONTINUE on stream 0 (v1 and the tail of v2). On v2 also handles INFO.
static int do_wisp_handshake(hw_client *c, const hw_client_opts *o, char *err, size_t err_cap) {
	uint64_t deadline = hw_now_ms() + (uint64_t)o->timeout_ms;
	int sent_info = !c->is_v2;
	for (;;) {
		uint64_t now = hw_now_ms();
		if (now >= deadline) {
			snprintf(err, err_cap, "wisp handshake timed out");
			return -1;
		}
		const uint8_t *msg;
		size_t len;
		int r = read_message(c, (int)(deadline - now), &msg, &len);
		if (r == 0) continue;
		if (r < 0) {
			snprintf(err, err_cap, "connection lost during handshake");
			return -1;
		}
		hw_wisp_packet p;
		if (hw_wisp_parse(msg, len, &p) != 0 || p.stream_id != 0) continue;
		if (p.type == HW_WISP_CLOSE) {
			uint8_t reason = p.payload_len ? p.payload[0] : 0;
			snprintf(err, err_cap, "server closed: %s (0x%02x)", hw_close_reason_str(reason), reason);
			c->closed = 1;
			return -1;
		}
		if (p.type == HW_WISP_INFO && c->is_v2 && !sent_info) {
			hw_wisp_info info;
			if (hw_wisp_parse_info(&p, &info) != 0 || info.major != HW_WISP_MAJOR) {
				snprintf(err, err_cap, "incompatible server INFO");
				return -1;
			}
			c->server_udp = info.has_udp;
			if (info.motd) {
				size_t ml = HW_MIN(info.motd_len, sizeof(c->motd) - 1);
				memcpy(c->motd, info.motd, ml);
				c->motd[ml] = '\0';
			}
			uint8_t pkt[HW_WISP_HEADER_LEN + 2 + 5 + 5 + 5 + 256 + 128];
			size_t n = hw_wisp_build_info(pkt, HW_WISP_MAJOR, HW_WISP_MINOR);
			n += hw_wisp_build_extension(pkt + n, sizeof(pkt) - n, HW_EXT_UDP, NULL, 0);
			if (o->stream_confirm) {
				n += hw_wisp_build_extension(pkt + n, sizeof(pkt) - n, HW_EXT_STREAM_CONFIRM, NULL, 0);
			}
			if (o->user && o->pass) {
				uint8_t meta[1 + 255 + 127];
				size_t ul = HW_MIN(strlen(o->user), 255);
				size_t pl = HW_MIN(strlen(o->pass), 127);
				meta[0] = (uint8_t)ul;
				memcpy(meta + 1, o->user, ul);
				memcpy(meta + 1 + ul, o->pass, pl);
				n += hw_wisp_build_extension(pkt + n, sizeof(pkt) - n, HW_EXT_PASSWORD, meta, (uint32_t)(1 + ul + pl));
			}
			if (send_packet(c, pkt, n) != 0) {
				snprintf(err, err_cap, "cannot send INFO");
				return -1;
			}
			sent_info = 1;
			continue;
		}
		if (p.type == HW_WISP_CONTINUE && p.payload_len >= 4) {
			c->buffer_size = hw_le32(p.payload);
			return 0;
		}
	}
}

// ---------------------------------------------------------------------------------- public API

hw_client *hw_client_connect(const hw_client_opts *o, char *err, size_t err_cap) {
	hw_client *c = calloc(1, sizeof(*c));
	if (!c) {
		snprintf(err, err_cap, "out of memory");
		return NULL;
	}
	hw_buf_init(&c->rbuf);
	hw_buf_init(&c->frag);
	hw_buf_init(&c->sbuf);
	c->max_message = o->max_message ? o->max_message : 1024 * 1024 + HW_WISP_HEADER_LEN;
	c->next_id = 1;
	seed_rng(c);
	c->fd = hw_connect_tcp(o->host, o->port, o->timeout_ms);
	if (c->fd < 0) {
		snprintf(err, err_cap, "connect %s:%u: %s", o->host, o->port, strerror(errno));
		free(c);
		return NULL;
	}
	hw_tcp_tune(c->fd, 1);
	if (do_upgrade(c, o, err, err_cap) != 0 || do_wisp_handshake(c, o, err, err_cap) != 0) {
		hw_client_free(c);
		return NULL;
	}
	return c;
}

void hw_client_free(hw_client *c) {
	if (!c) return;
	if (!c->closed && c->fd >= 0) {
		uint8_t reply[2] = {0x03, 0xE8};
		send_frame(c, HW_WS_CLOSE, reply, 2, NULL, 0);
	}
	if (c->fd >= 0) close(c->fd);
	hw_buf_free(&c->rbuf);
	hw_buf_free(&c->frag);
	hw_buf_free(&c->sbuf);
	free(c->streams);
	qevent *q;
	while ((q = queue_pop(c))) qevent_free(q);
	qevent_free(c->last);
	free(c);
}

int hw_client_is_v2(const hw_client *c) {
	return c->is_v2;
}

const char *hw_client_motd(const hw_client *c) {
	return c->motd;
}

int hw_client_server_has_udp(const hw_client *c) {
	return c->server_udp;
}

uint32_t hw_client_buffer_size(const hw_client *c) {
	return c->buffer_size;
}

int hw_client_fd(const hw_client *c) {
	return c->fd;
}

int hw_client_open(hw_client *c, uint8_t stream_type, const char *host, uint16_t port, uint32_t *stream_id) {
	if (c->closed) return HW_ERR_CLOSED;
	if (c->nstreams == c->streams_cap) {
		size_t cap = c->streams_cap ? c->streams_cap * 2 : 16;
		cstream *p = realloc(c->streams, cap * sizeof(*p));
		if (!p) return HW_ERR_NOMEM;
		c->streams = p;
		c->streams_cap = cap;
	}
	uint32_t id = c->next_id++;
	if (c->next_id == 0) c->next_id = 1;
	size_t hl = strlen(host);
	uint8_t pkt[HW_WISP_HEADER_LEN + 3 + 255];
	size_t n = hw_wisp_build_connect(pkt, sizeof(pkt), id, stream_type, port, host, HW_MIN(hl, 255));
	if (n == 0) return HW_ERR_INVALID;
	cstream *s = &c->streams[c->nstreams++];
	s->id = id;
	s->type = stream_type;
	s->remaining = c->buffer_size;
	int r = send_packet(c, pkt, n);
	if (r != 0) {
		c->nstreams--;
		return r;
	}
	*stream_id = id;
	return 0;
}

int hw_client_send(hw_client *c, uint32_t stream_id, const void *data, size_t len) {
	if (c->closed) return HW_ERR_CLOSED;
	cstream *s = stream_find(c, stream_id);
	if (!s) return HW_ERR_CLOSED;
	if (s->type == HW_STREAM_TCP) {
		// The window is counted in packets; wait for a CONTINUE when it is spent.
		while (s->remaining == 0) {
			int r = pump_one(c, -1);
			if (r < 0) return r;
			s = stream_find(c, stream_id);
			if (!s) return HW_ERR_CLOSED;
		}
		s->remaining--;
	}
	uint8_t hdr[HW_WISP_HEADER_LEN];
	hw_wisp_write_header(hdr, HW_WISP_DATA, stream_id);
	return send_frame(c, HW_WS_BINARY, hdr, sizeof(hdr), data, len);
}

int hw_client_close_stream(hw_client *c, uint32_t stream_id, uint8_t reason) {
	if (c->closed) return HW_ERR_CLOSED;
	stream_forget(c, stream_id);
	uint8_t pkt[HW_WISP_HEADER_LEN + 1];
	return send_packet(c, pkt, hw_wisp_build_close(pkt, stream_id, reason));
}

int hw_client_poll(hw_client *c, int timeout_ms, hw_client_event *ev) {
	qevent_free(c->last);
	c->last = NULL;
	qevent *q = queue_pop(c);
	if (!q) {
		if (c->closed) return HW_ERR_CLOSED;
		const uint8_t *msg;
		size_t len;
		for (;;) {
			int r = read_message(c, timeout_ms, &msg, &len);
			if (r <= 0) return r;
			if (packet_to_event(c, msg, len, ev)) return 1;
		}
	}
	*ev = q->ev;
	c->last = q;
	return 1;
}

long hw_client_read_exact(hw_client *c, uint32_t stream_id, uint8_t *out, size_t want, int timeout_ms) {
	size_t got = 0;
	qevent *side_head = NULL;
	qevent *side_tail = NULL;
	long result = 0;
	uint64_t deadline = timeout_ms < 0 ? 0 : hw_now_ms() + (uint64_t)timeout_ms;
	while (got < want) {
		int wait = -1;
		if (timeout_ms >= 0) {
			uint64_t now = hw_now_ms();
			if (now >= deadline) {
				result = HW_ERR_TIMEOUT;
				break;
			}
			wait = (int)(deadline - now);
		}
		hw_client_event ev;
		int r = hw_client_poll(c, wait, &ev);
		if (r == 0) {
			result = HW_ERR_TIMEOUT;
			break;
		}
		if (r < 0) {
			result = r;
			break;
		}
		if (ev.stream_id == stream_id && ev.type == HW_CEV_DATA) {
			size_t take = HW_MIN(ev.len, want - got);
			memcpy(out + got, ev.data, take);
			got += take;
			if (take < ev.len) {
				// Keep the rest for the caller's next read.
				hw_client_event rest = ev;
				rest.data = ev.data + take;
				rest.len = ev.len - take;
				qevent *q = qevent_new(&rest);
				if (!q) {
					result = HW_ERR_NOMEM;
					break;
				}
				q->next = c->qhead;
				c->qhead = q;
				if (!c->qtail) c->qtail = q;
			}
			continue;
		}
		if (ev.stream_id == stream_id && ev.type == HW_CEV_CLOSE) {
			qevent *q = qevent_new(&ev); // the caller still gets to see the CLOSE
			if (q) {
				q->next = c->qhead;
				c->qhead = q;
				if (!c->qtail) c->qtail = q;
			}
			break;
		}
		qevent *q = qevent_new(&ev);
		if (!q) {
			result = HW_ERR_NOMEM;
			break;
		}
		q->next = NULL;
		if (side_tail) {
			side_tail->next = q;
		} else {
			side_head = q;
		}
		side_tail = q;
	}
	// Events for other streams go back to the front, in the order they arrived.
	if (side_head) {
		side_tail->next = c->qhead;
		c->qhead = side_head;
		if (!c->qtail) c->qtail = side_tail;
	}
	if (result < 0 && got == 0) return result;
	return (long)got;
}
