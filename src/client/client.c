/*
 * holywisp/client.h implementation. Blocking, single-threaded; see the header for the model.
 */
#include "holywisp/client.h"

#include "holywisp/base64.h"
#include "holywisp/buf.h"
#include "holywisp/hw.h"
#include "holywisp/net.h"
#include "holywisp/sys.h"
#include "holywisp/wisp.h"
#include "holywisp/ws.h"

#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define CLIENT_READ_CHUNK   (64 * 1024)
#define CLIENT_QUEUE_BYTES  ((size_t)32 * 1024 * 1024) // default opts.max_queue_bytes
#define CLIENT_QUEUE_EVENTS ((size_t)65536)            // default opts.max_queue_events
#define CLIENT_ERR_EXCERPT  64                         // bytes of a bad upgrade response quoted in the error
#define CLIENT_USER_MAX     255                        // the password extension carries the user's length in a u8
#define CLIENT_PASS_MAX     127
#define CLIENT_HOST_MAX     255 // the longest hostname a server takes in a CONNECT
#define TIMER_FOREVER       UINT64_MAX

typedef struct cstream {
	uint32_t id;
	uint8_t type;
	uint32_t remaining;
} cstream;

typedef struct qevent {
	hw_client_event ev;
	uint8_t *data; // owned copy of the payload; ev.data points into it
	size_t size;   // bytes charged to the queue budget
	struct qevent *next;
} qevent;

// One per public call: when the call has to return, and whether it has read the socket yet. Every
// wait inside the call runs against the same deadline, so nothing the server sends can restart it.
// A call whose time is up is still owed one read (a zero timeout must drain a readable socket, not
// report it idle) and gets none after that.
typedef struct ctimer {
	uint64_t deadline; // on the hw_now_ms() clock; TIMER_FOREVER never comes
	int has_read;
} ctimer;

struct hw_client {
	int fd;
	int closed;
	int is_v2;
	int server_udp;
	int authenticated; // the password extension went out and the server completed the handshake
	int timeout_ms;    // opts.timeout_ms: the longest a send waits for a CONTINUE
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
	// Every qevent alive, queued or handed out, counts against a budget: the server decides how
	// much arrives while a call waits for something else, so it must not decide how much is kept.
	size_t queue_bytes;
	size_t queue_events;
	size_t max_queue_bytes;
	size_t max_queue_events;
	uint64_t rng;
};

void hw_client_opts_defaults(hw_client_opts *o) {
	memset(o, 0, sizeof(*o));
	o->host = "127.0.0.1";
	o->port = 6001;
	o->path = "/";
	o->timeout_ms = 10000;
	o->max_message = 1024 * 1024 + HW_WISP_HEADER_LEN;
	o->max_queue_bytes = CLIENT_QUEUE_BYTES;
	o->max_queue_events = CLIENT_QUEUE_EVENTS;
}

size_t hw_client_printable(char *out, size_t cap, const void *data, size_t len) {
	static const char hex[] = "0123456789abcdef";
	const uint8_t *p = data;
	size_t n = 0;
	if (cap == 0) return 0;
	for (size_t i = 0; i < len; i++) {
		// Printable ASCII only. Bytes from 0x80 up are escaped too: a terminal in UTF-8 mode takes
		// U+0080 to U+009F (0xc2 0x9b is CSI) for the same controls as the ones below 0x20.
		if (p[i] >= 0x20 && p[i] < 0x7f) {
			if (n + 1 >= cap) break;
			out[n++] = (char)p[i];
		} else {
			if (n + 4 >= cap) break;
			out[n++] = '\\';
			out[n++] = 'x';
			out[n++] = hex[p[i] >> 4];
			out[n++] = hex[p[i] & 15];
		}
	}
	out[n] = '\0';
	return n;
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
		ssize_t n = send(c->fd, data, len, HW_MSG_NOSIGNAL);
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

static ctimer timer_start(int timeout_ms) {
	ctimer t = {.deadline = timeout_ms < 0 ? TIMER_FOREVER : hw_now_ms() + (uint64_t)timeout_ms, .has_read = 0};
	return t;
}

// What is left of the call's time, as poll(2) takes it: -1 without bound, 0 when it is up.
static int timer_left(const ctimer *t) {
	if (t->deadline == TIMER_FOREVER) return -1;
	uint64_t now = hw_now_ms();
	if (now >= t->deadline) return 0;
	return (int)HW_MIN(t->deadline - now, (uint64_t)INT_MAX);
}

// Wait until the socket is readable or the timer runs out. 1 ready, 0 time is up, <0 error.
static int wait_readable(hw_client *c, const ctimer *t) {
	struct pollfd pfd = {.fd = c->fd, .events = POLLIN};
	for (;;) {
		int r = poll(&pfd, 1, timer_left(t));
		if (r < 0 && errno == EINTR) continue;
		if (r < 0) return HW_ERR_IO;
		return r > 0;
	}
}

// Read one complete WebSocket message. *data points into rbuf/frag until the next call.
// 1 message, 0 when the caller's time is up, HW_ERR_CLOSED, HW_ERR_PROTOCOL.
//
// The timer bounds the socket, not the buffer: frames that are already here are always taken, so 0
// means that no complete message is left in rbuf and a caller may go back to poll(2) on the fd.
// Frames that produce no message (PING, PONG, fragments) therefore cannot keep the call past its
// deadline by more than the time it takes to walk one buffer of them.
static int read_message(hw_client *c, ctimer *t, const uint8_t **data, size_t *len) {
	if (c->pending_consume) {
		hw_buf_consume(&c->rbuf, c->pending_consume);
		c->pending_consume = 0;
	}
	if (c->closed) return HW_ERR_CLOSED;
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

		if (t->has_read && timer_left(t) == 0) return 0;
		int ready = wait_readable(c, t);
		if (ready <= 0) return ready;
		if (hw_buf_reserve(&c->rbuf, CLIENT_READ_CHUNK) != 0) return HW_ERR_NOMEM;
		ssize_t n = recv(c->fd, hw_buf_tail(&c->rbuf), hw_buf_room(&c->rbuf), 0);
		if (n == 0 || (n < 0 && errno != EINTR && errno != EAGAIN)) {
			c->closed = 1;
			return HW_ERR_CLOSED;
		}
		if (n > 0) {
			hw_buf_commit(&c->rbuf, (size_t)n);
			t->has_read = 1;
		}
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

// Copy an event so that it outlives the read buffer. 0 and *out, HW_ERR_NOMEM, or HW_ERR_TOOBIG
// when the copy would take the queue past its budget: the server is making the client hold more
// than its caller agreed to, and the client is failed instead of grown.
static int qevent_new(hw_client *c, const hw_client_event *ev, qevent **out) {
	size_t size = ev->type == HW_CEV_DATA ? ev->len : 0;
	if (c->queue_events >= c->max_queue_events || size > c->max_queue_bytes - c->queue_bytes) {
		c->closed = 1;
		return HW_ERR_TOOBIG;
	}
	qevent *q = calloc(1, sizeof(*q));
	if (!q) return HW_ERR_NOMEM;
	q->ev = *ev;
	if (size) {
		q->data = malloc(size);
		if (!q->data) {
			free(q);
			return HW_ERR_NOMEM;
		}
		memcpy(q->data, ev->data, size);
	}
	q->ev.data = q->data;
	q->size = size;
	c->queue_events++;
	c->queue_bytes += size;
	*out = q;
	return 0;
}

static void qevent_free(hw_client *c, qevent *q) {
	if (!q) return;
	c->queue_events--;
	c->queue_bytes -= q->size;
	free(q->data);
	free(q);
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

static void queue_push_front(hw_client *c, qevent *q) {
	q->next = c->qhead;
	c->qhead = q;
	if (!c->qtail) c->qtail = q;
}

static qevent *queue_pop(hw_client *c) {
	qevent *q = c->qhead;
	if (!q) return NULL;
	c->qhead = q->next;
	if (!c->qhead) c->qtail = NULL;
	return q;
}

// Read packets until one is an event. 1 and ev filled (its data pointing into the message, valid
// until the next read), 0 when the caller's time is up, <0 error.
static int next_event(hw_client *c, ctimer *t, hw_client_event *ev) {
	for (;;) {
		const uint8_t *msg;
		size_t len;
		int r = read_message(c, t, &msg, &len);
		if (r <= 0) return r;
		if (packet_to_event(c, msg, len, ev)) return 1;
	}
}

// Read the next event from the socket and queue it. 1 queued, 0 time is up, <0 error.
static int pump_one(hw_client *c, ctimer *t) {
	hw_client_event ev;
	int r = next_event(c, t, &ev);
	if (r <= 0) return r;
	qevent *q;
	r = qevent_new(c, &ev, &q);
	if (r != 0) return r;
	queue_push(c, q);
	return 1;
}

// ---------------------------------------------------------------------------------- handshake

static int do_upgrade(hw_client *c, const hw_client_opts *o, ctimer *t, char *err, size_t err_cap) {
	uint8_t raw[16];
	for (int i = 0; i < 4; i++) {
		uint32_t v = rng_next(c);
		memcpy(raw + i * 4, &v, 4);
	}
	char key[HW_BASE64_LEN(16)];
	hw_base64_encode(raw, sizeof(raw), key, sizeof(key));
	char req[1024];
	size_t n = hw_http_write_upgrade(req, sizeof(req), o->host, o->port, o->path, key,
	                                 o->v2 ? HW_WISP_V2_PROTOCOL : NULL, NULL);
	if (n == 0) {
		// Nothing was sent and no call failed: the request could not be written as it stands.
		snprintf(err, err_cap,
		         "the host or path cannot go into an upgrade request (too long, empty, or a space in it)");
		return -1;
	}
	if (send_all(c, (const uint8_t *)req, n) != 0) {
		snprintf(err, err_cap, "cannot send upgrade request: %s", strerror(errno));
		return -1;
	}
	char accept[HW_WS_ACCEPT_LEN + 1];
	hw_ws_accept_key(key, accept);
	for (;;) {
		char proto[64];
		int r = hw_http_parse_upgrade_response(hw_buf_head(&c->rbuf), hw_buf_avail(&c->rbuf), accept, proto,
		                                       sizeof(proto));
		if (r > 0) {
			hw_buf_consume(&c->rbuf, (size_t)r);
			// RFC 6455 4.1: a subprotocol the client did not offer fails the connection. Taking it
			// for v2 would let the server choose the protocol, and with it whether an INFO is sent.
			if (!o->v2 && proto[0]) {
				snprintf(err, err_cap, "server chose a subprotocol that was not offered");
				return -1;
			}
			c->is_v2 = o->v2 && strcasecmp(proto, HW_WISP_V2_PROTOCOL) == 0;
			if (o->v2 && !c->is_v2) {
				snprintf(err, err_cap, "server did not accept %s", HW_WISP_V2_PROTOCOL);
				return -1;
			}
			return 0;
		}
		if (r != HW_ERR_AGAIN) {
			// The excerpt is the server's bytes and err is headed for a terminal or a log.
			char shown[CLIENT_ERR_EXCERPT * 4 + 1];
			hw_client_printable(shown, sizeof(shown), hw_buf_head(&c->rbuf),
			                    HW_MIN(hw_buf_avail(&c->rbuf), (size_t)CLIENT_ERR_EXCERPT));
			snprintf(err, err_cap, "bad upgrade response: %s", shown);
			return -1;
		}
		int ready = timer_left(t) ? wait_readable(c, t) : 0;
		if (ready <= 0) {
			snprintf(err, err_cap, "upgrade timed out");
			return -1;
		}
		if (hw_buf_reserve(&c->rbuf, 4096) != 0) {
			snprintf(err, err_cap, "out of memory");
			return -1;
		}
		ssize_t got = recv(c->fd, hw_buf_tail(&c->rbuf), hw_buf_room(&c->rbuf), 0);
		if (got <= 0) {
			snprintf(err, err_cap, "server closed during upgrade");
			return -1;
		}
		hw_buf_commit(&c->rbuf, (size_t)got);
	}
}

// Wait for the server's CONTINUE on stream 0 (v1 and the tail of v2). On v2 also handles INFO.
static int do_wisp_handshake(hw_client *c, const hw_client_opts *o, ctimer *t, char *err, size_t err_cap) {
	int sent_info = !c->is_v2;
	int sent_password = 0;
	for (;;) {
		const uint8_t *msg;
		size_t len;
		int r = read_message(c, t, &msg, &len);
		if (r == 0) {
			snprintf(err, err_cap, "wisp handshake timed out");
			return -1;
		}
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
			uint8_t meta[1 + CLIENT_USER_MAX + CLIENT_PASS_MAX];
			uint8_t pkt[HW_WISP_HEADER_LEN + 2 + 3 * 5 + sizeof(meta)];
			size_t n = hw_wisp_build_info(pkt, HW_WISP_MAJOR, HW_WISP_MINOR);
			n += hw_wisp_build_extension(pkt + n, sizeof(pkt) - n, HW_EXT_UDP, NULL, 0);
			if (o->stream_confirm) {
				n += hw_wisp_build_extension(pkt + n, sizeof(pkt) - n, HW_EXT_STREAM_CONFIRM, NULL, 0);
			}
			// Credentials go only to a server that asked for them. One that did not advertise the
			// extension has no use for a password, and would get it in clear all the same.
			if (o->user && o->pass && info.has_password) {
				size_t ul = strlen(o->user); // both fit: hw_client_connect checked
				size_t pl = strlen(o->pass);
				meta[0] = (uint8_t)ul;
				memcpy(meta + 1, o->user, ul);
				memcpy(meta + 1 + ul, o->pass, pl);
				n += hw_wisp_build_extension(pkt + n, sizeof(pkt) - n, HW_EXT_PASSWORD, meta, (uint32_t)(1 + ul + pl));
				sent_password = 1;
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
			c->authenticated = sent_password;
			return 0;
		}
	}
}

// ---------------------------------------------------------------------------------- public API

hw_client *hw_client_connect(const hw_client_opts *o, char *err, size_t err_cap) {
	// Cutting either one to fit would send the server something the caller did not configure.
	if (o->user && o->pass && (strlen(o->user) > CLIENT_USER_MAX || strlen(o->pass) > CLIENT_PASS_MAX)) {
		snprintf(err, err_cap, "user over %d bytes or password over %d", CLIENT_USER_MAX, CLIENT_PASS_MAX);
		return NULL;
	}
	hw_client *c = calloc(1, sizeof(*c));
	if (!c) {
		snprintf(err, err_cap, "out of memory");
		return NULL;
	}
	hw_buf_init(&c->rbuf);
	hw_buf_init(&c->frag);
	hw_buf_init(&c->sbuf);
	c->max_message = o->max_message ? o->max_message : 1024 * 1024 + HW_WISP_HEADER_LEN;
	c->max_queue_bytes = o->max_queue_bytes ? o->max_queue_bytes : CLIENT_QUEUE_BYTES;
	c->max_queue_events = o->max_queue_events ? o->max_queue_events : CLIENT_QUEUE_EVENTS;
	c->timeout_ms = o->timeout_ms;
	c->next_id = 1;
	seed_rng(c);
	// One deadline for the TCP connect, the upgrade and the Wisp handshake together.
	ctimer t = timer_start(o->timeout_ms);
	c->fd = hw_connect_tcp(o->host, o->port, o->timeout_ms);
	if (c->fd < 0) {
		snprintf(err, err_cap, "connect %s:%u: %s", o->host, o->port, strerror(errno));
		free(c);
		return NULL;
	}
	hw_tcp_tune(c->fd, 1);
	if (do_upgrade(c, o, &t, err, err_cap) != 0 || do_wisp_handshake(c, o, &t, err, err_cap) != 0) {
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
	while ((q = queue_pop(c))) qevent_free(c, q);
	qevent_free(c, c->last);
	free(c);
}

int hw_client_is_v2(const hw_client *c) {
	return c->is_v2;
}

int hw_client_authenticated(const hw_client *c) {
	return c->authenticated;
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
	// A host that does not fit is refused, never cut: the caller may have checked the name it
	// passed (its suffix, say), and a prefix of it is a different name.
	size_t hl = strlen(host);
	if (hl == 0 || hl > CLIENT_HOST_MAX) return HW_ERR_INVALID;
	if (c->nstreams == c->streams_cap) {
		size_t cap = c->streams_cap ? c->streams_cap * 2 : 16;
		cstream *p = realloc(c->streams, cap * sizeof(*p));
		if (!p) return HW_ERR_NOMEM;
		c->streams = p;
		c->streams_cap = cap;
	}
	uint8_t pkt[HW_WISP_HEADER_LEN + 3 + CLIENT_HOST_MAX];
	size_t n = hw_wisp_build_connect(pkt, sizeof(pkt), c->next_id, stream_type, port, host, hl);
	if (n == 0) return HW_ERR_INVALID;
	uint32_t id = c->next_id++;
	if (c->next_id == 0) c->next_id = 1;
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
		// The window is counted in packets; wait for a CONTINUE when it is spent, for as long as
		// the client was told to wait for anything. What arrives meanwhile is queued, within the
		// queue's budget: a server that withholds the CONTINUE decides neither how long this
		// takes nor how much memory it costs.
		ctimer t = timer_start(c->timeout_ms);
		while (s->remaining == 0) {
			int r = pump_one(c, &t);
			if (r == 0) return HW_ERR_TIMEOUT;
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
	qevent_free(c, c->last);
	c->last = NULL;
	qevent *q = queue_pop(c);
	if (q) {
		*ev = q->ev;
		c->last = q;
		return 1;
	}
	if (c->closed) return HW_ERR_CLOSED;
	ctimer t = timer_start(timeout_ms);
	return next_event(c, &t, ev);
}

long long hw_client_read_exact(hw_client *c, uint32_t stream_id, uint8_t *out, size_t want, int timeout_ms) {
	size_t got = 0;
	qevent *side_head = NULL;
	qevent *side_tail = NULL;
	int result = 0;
	ctimer t = timer_start(timeout_ms);
	qevent_free(c, c->last);
	c->last = NULL;
	while (got < want) {
		// Queued events first, then the socket. q is the event's copy when it has one: a queued
		// event is moved, never copied again, and one from the socket is copied only if it has to
		// wait, so everything this call sets aside is inside the queue's budget.
		qevent *q = queue_pop(c);
		hw_client_event ev;
		if (q) {
			ev = q->ev;
		} else {
			result = c->closed ? HW_ERR_CLOSED : next_event(c, &t, &ev);
			if (result == 0) result = HW_ERR_TIMEOUT;
			if (result < 0) break;
			result = 0;
		}
		if (ev.stream_id == stream_id && ev.type == HW_CEV_DATA) {
			size_t take = HW_MIN(ev.len, want - got);
			if (take) memcpy(out + got, ev.data, take);
			got += take;
			if (take == ev.len) {
				qevent_free(c, q);
				continue;
			}
			// Keep the rest for the caller's next read.
			if (q) {
				q->ev.data += take;
				q->ev.len -= take;
			} else {
				hw_client_event rest = ev;
				rest.data = ev.data + take;
				rest.len = ev.len - take;
				result = qevent_new(c, &rest, &q);
				if (result != 0) break;
			}
			queue_push_front(c, q);
			continue;
		}
		if (!q) {
			result = qevent_new(c, &ev, &q);
			if (result != 0) break;
		}
		if (ev.stream_id == stream_id && ev.type == HW_CEV_CLOSE) {
			queue_push_front(c, q); // the caller still gets to see the CLOSE
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
	return (long long)got;
}
