/*
 * tests/test_wt_quic.c - WebTransport sessions (holywisp/webtransport.h) on real QUIC
 * connections (holywisp/quic.h): a client hw_wt and a server hw_wt, each on its own
 * hw_quic_conn, joined by an in-memory path that can delay, drop and reorder datagrams from a
 * seed. Wisp packets go both ways on the Wisp stream and as datagrams, a session is refused, a
 * GET gets its 404, each side closes once, and a paused server stops the client's credit.
 */
#include "holywisp/buf.h"
#include "holywisp/cert.h"
#include "holywisp/ecc.h"
#include "holywisp/hw.h"
#include "holywisp/quic.h"
#include "holywisp/sha256.h"
#include "holywisp/webtransport.h"
#include "holywisp/wisp.h"

#include "quic/h3.h"
#include "test.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

// ---- The path -------------------------------------------------------------------------------

typedef struct {
	uint64_t at, seq;
	int to_server;
	size_t len;
	uint8_t *data;
} path_pkt;

#define RAW_STREAMS 32
#define SIDE_PKTS   512

typedef struct net net;

// One end: a QUIC connection, the hw_wt on it (none for a raw client, whose streams the test
// drives itself), and what the hw_wt callbacks saw.
typedef struct {
	net *n;
	int server;
	hw_quic_conn *q;
	hw_wt *w;
	int established, quic_closed;
	uint64_t quic_error;
	int requests;
	char authority[128], path[128], protocols[128];
	int answer;
	const char *answer_protocol;
	int packets, dgram_packets;
	uint8_t *pkt[SIDE_PKTS];
	size_t pkt_len[SIDE_PKTS];
	int pkt_dgram[SIDE_PKTS];
	int writable;
	int closed;
	uint32_t close_code;
	char close_reason[HW_H3_CLOSE_REASON_MAX + 1];
	int echo;     // send every packet back the way it came
	int pause_at; // pause once this many packets arrived
	// A raw end: what arrived on each stream.
	struct {
		uint64_t id;
		hw_buf rx;
		int fin;
		int64_t reset;
	} raw[RAW_STREAMS];
	size_t n_raw;
} side;

struct net {
	uint64_t now, rng, seq;
	uint32_t loss_ppm, reorder_ppm;
	path_pkt *q;
	size_t n, cap;
	side c, s;
	hw_quic_config ccfg, scfg;
	hw_wt_config cwt, swt;
	struct sockaddr_in caddr, saddr;
	uint8_t reset_key[HW_QUIC_KEY_LEN];
};

static uint64_t net_rand(net *n) {
	n->rng = n->rng * 6364136223846793005ull + 1442695040888963407ull;
	return n->rng >> 33;
}

static void net_send(net *n, int to_server, const uint8_t *d, size_t len) {
	if (n->loss_ppm && net_rand(n) % 1000000 < n->loss_ppm) return;
	if (n->n == n->cap) {
		n->cap = n->cap ? 2 * n->cap : 64;
		path_pkt *grown = realloc(n->q, n->cap * sizeof(*n->q));
		CHECK(grown != NULL, "oom");
		n->q = grown;
	}
	path_pkt *p = &n->q[n->n++];
	p->at = n->now + 10;
	if (n->reorder_ppm && net_rand(n) % 1000000 < n->reorder_ppm) p->at += 1 + net_rand(n) % 20;
	p->seq = n->seq++;
	p->to_server = to_server;
	p->len = len;
	p->data = malloc(len);
	memcpy(p->data, d, len);
}

// ---- The callbacks: QUIC's go to hw_wt, hw_wt's are recorded ------------------------------------

static void q_established(void *ud) {
	side *e = ud;
	e->established = 1;
	if (e->w) hw_wt_on_established(e->w);
}

static void q_stream_data(void *ud, uint64_t id, const uint8_t *data, size_t len, int fin) {
	side *e = ud;
	if (e->w) {
		hw_wt_on_stream_data(e->w, id, data, len, fin);
		return;
	}
	size_t i = 0;
	while (i < e->n_raw && e->raw[i].id != id) i++;
	if (i == e->n_raw) {
		CHECK(e->n_raw < RAW_STREAMS, "raw streams");
		e->raw[i].id = id;
		hw_buf_init(&e->raw[i].rx);
		e->raw[i].reset = -1;
		e->n_raw++;
	}
	if (len) hw_buf_append(&e->raw[i].rx, data, len);
	if (fin) e->raw[i].fin = 1;
	hw_quic_stream_consumed(e->q, id, len);
}

static void q_stream_reset(void *ud, uint64_t id, uint64_t err) {
	side *e = ud;
	if (e->w) hw_wt_on_stream_reset(e->w, id, err);
	for (size_t i = 0; i < e->n_raw; i++) {
		if (e->raw[i].id == id) e->raw[i].reset = (int64_t)err;
	}
}

static void q_stream_stop(void *ud, uint64_t id, uint64_t err) {
	side *e = ud;
	if (e->w) hw_wt_on_stream_stop(e->w, id, err);
}

static void q_writable(void *ud, uint64_t id) {
	side *e = ud;
	if (e->w) hw_wt_on_stream_writable(e->w, id);
}

static void q_datagram(void *ud, const uint8_t *data, size_t len) {
	side *e = ud;
	if (e->w) hw_wt_on_datagram(e->w, data, len);
}

static void q_cid(void *ud, const uint8_t cid[HW_QUIC_CID_LEN], int retire) {
	(void)ud;
	(void)cid;
	(void)retire;
}

static void q_closed(void *ud, uint64_t err, int app, const char *reason) {
	(void)app;
	(void)reason;
	side *e = ud;
	e->quic_closed = 1;
	e->quic_error = err;
	if (e->w) hw_wt_on_closed(e->w);
}

static int w_request(void *ud, const hw_wt_request *req, const char **protocol_out) {
	side *e = ud;
	e->requests++;
	snprintf(e->authority, sizeof(e->authority), "%s", req->authority);
	snprintf(e->path, sizeof(e->path), "%s", req->path);
	snprintf(e->protocols, sizeof(e->protocols), "%s", req->protocols ? req->protocols : "");
	*protocol_out = e->answer_protocol;
	return e->answer;
}

static void w_packet(void *ud, const uint8_t *data, size_t len, int datagram) {
	side *e = ud;
	CHECK(e->packets < SIDE_PKTS, "too many packets");
	e->pkt[e->packets] = malloc(len ? len : 1);
	if (len) memcpy(e->pkt[e->packets], data, len);
	e->pkt_len[e->packets] = len;
	e->pkt_dgram[e->packets] = datagram;
	e->packets++;
	e->dgram_packets += datagram;
	if (e->echo) CHECK(hw_wt_send(e->w, data, len, datagram) >= 0, "echo");
	if (e->pause_at && e->packets == e->pause_at) hw_wt_pause(e->w, 1);
}

static void w_writable(void *ud) {
	side *e = ud;
	e->writable++;
}

static void w_closed(void *ud, uint32_t code, const char *reason) {
	side *e = ud;
	e->closed++;
	e->close_code = code;
	snprintf(e->close_reason, sizeof(e->close_reason), "%s", reason);
}

static const hw_quic_callbacks QCB = {NULL,       q_established, q_stream_data, q_stream_reset, q_stream_stop,
                                      q_writable, q_datagram,    q_cid,         q_closed};

// ---- Setting up -------------------------------------------------------------------------------

static hw_der g_cert;
static uint8_t g_key[HW_P256_PRIV_LEN];
static uint8_t g_pin[HW_SHA256_LEN];
static const char *const ALPN[] = {HW_WT_ALPN};

static void cert_make(void) {
	uint8_t pub[HW_P256_PUB_LEN];
	CHECK_EQ(hw_p256_keygen(g_key, pub), 0);
	int64_t now = (int64_t)time(NULL);
	CHECK_EQ(hw_cert_selfsigned(g_key, pub, "localhost", now - 3600, now + 13 * 86400, &g_cert), 0);
	hw_sha256(g_cert.der, g_cert.len, g_pin);
}

static void quic_config(hw_quic_config *c, int server, uint64_t stream_window) {
	memset(c, 0, sizeof(*c));
	c->is_server = server;
	c->tls.is_server = server;
	c->tls.alpn = ALPN;
	c->tls.alpn_count = 1;
	if (server) {
		c->tls.chain = &g_cert;
		c->tls.chain_len = 1;
		c->tls.key = g_key;
	} else {
		c->tls.server_name = "localhost";
		c->tls.pin_sha256 = g_pin;
	}
	c->max_idle_ms = 30000;
	c->initial_max_data = 8u << 20;
	c->initial_max_stream_data = stream_window;
	c->initial_max_streams_bidi = 100;
	c->initial_max_streams_uni = 100;
	c->max_datagram_frame_size = 65536;
	c->stream_send_max = 1u << 20;
	c->conn_send_max = 8u << 20;
	c->datagram_queue_max = 64;
}

static net *net_new(uint64_t seed, uint64_t stream_window) {
	net *n = calloc(1, sizeof(*n));
	CHECK(n != NULL, "oom");
	n->rng = seed;
	n->now = 1000;
	n->c.n = n->s.n = n;
	n->s.server = 1;
	n->c.answer = n->s.answer = 200;
	n->caddr.sin_family = n->saddr.sin_family = AF_INET;
	n->caddr.sin_port = htons(50000);
	n->caddr.sin_addr.s_addr = htonl(0x7f000001);
	n->saddr.sin_port = htons(4433);
	n->saddr.sin_addr.s_addr = htonl(0x7f000002);
	for (size_t i = 0; i < sizeof(n->reset_key); i++) n->reset_key[i] = (uint8_t)net_rand(n);
	quic_config(&n->ccfg, 0, stream_window);
	quic_config(&n->scfg, 1, stream_window);
	n->scfg.cid_prefix = 3;
	n->scfg.reset_key = n->reset_key;
	n->cwt.max_packet = n->swt.max_packet = 1 << 20;
	n->cwt.is_client = 1;
	n->cwt.authority = "localhost:4433";
	n->cwt.path = "/wisp/";
	n->cwt.origin = "https://localhost";
	n->cwt.protocols = "\"wisp-v2\"";
	return n;
}

static hw_wt *side_wt(side *e, const hw_wt_config *cfg) {
	hw_wt_callbacks cb = {e, w_request, w_packet, w_writable, w_closed};
	hw_wt *w = hw_wt_new(e->q, cfg, &cb);
	CHECK(w != NULL, "hw_wt_new");
	return w;
}

// raw = 1: the client has no hw_wt; the test writes its streams.
static void net_start(net *n, int raw) {
	hw_quic_callbacks cb = QCB;
	cb.ud = &n->c;
	n->c.q = hw_quic_connect(&n->ccfg, &cb, (const struct sockaddr *)&n->saddr, sizeof(n->saddr), n->now);
	CHECK(n->c.q != NULL, "connect");
	if (!raw) n->c.w = side_wt(&n->c, &n->cwt);
}

static void net_free(net *n) {
	hw_wt_free(n->c.w);
	hw_wt_free(n->s.w);
	hw_quic_free(n->c.q);
	hw_quic_free(n->s.q);
	for (size_t i = 0; i < n->n; i++) free(n->q[i].data);
	free(n->q);
	side *sides[] = {&n->c, &n->s};
	for (int k = 0; k < 2; k++) {
		for (int i = 0; i < sides[k]->packets; i++) free(sides[k]->pkt[i]);
		for (size_t i = 0; i < sides[k]->n_raw; i++) hw_buf_free(&sides[k]->raw[i].rx);
	}
	free(n);
}

// ---- Running it -------------------------------------------------------------------------------

static void net_deliver(net *n, path_pkt *p) {
	if (!p->to_server) {
		hw_quic_input(n->c.q, p->data, p->len, (const struct sockaddr *)&n->saddr, sizeof(n->saddr), n->now);
		return;
	}
	if (!n->s.q) {
		hw_quic_header h;
		if (hw_quic_parse_header(p->data, p->len, &h) < 0 || !h.long_header || h.type != 0) return;
		hw_quic_callbacks cb = QCB;
		cb.ud = &n->s;
		n->s.q = hw_quic_accept(&n->scfg, &cb, &h, (const struct sockaddr *)&n->caddr, sizeof(n->caddr), 0, NULL, 0,
		                        n->now);
		CHECK(n->s.q != NULL, "accept");
		n->s.w = side_wt(&n->s, &n->swt);
	}
	hw_quic_input(n->s.q, p->data, p->len, (const struct sockaddr *)&n->caddr, sizeof(n->caddr), n->now);
}

static void net_flush(net *n) {
	uint8_t out[HW_QUIC_MAX_DGRAM];
	struct sockaddr_storage to;
	socklen_t to_len;
	side *sides[] = {&n->c, &n->s};
	for (int k = 0; k < 2; k++) {
		if (!sides[k]->q) continue;
		size_t len;
		while ((len = hw_quic_output(sides[k]->q, out, sizeof(out), &to, &to_len, n->now)) > 0) {
			net_send(n, k == 0, out, len);
		}
	}
}

// One step of the clock, to the next event but never past limit: everything due is delivered
// and every due timer runs. 0 when nothing happens before limit.
static int net_step_until(net *n, uint64_t limit) {
	net_flush(n);
	uint64_t t = UINT64_MAX;
	for (size_t i = 0; i < n->n; i++) t = HW_MIN(t, n->q[i].at);
	if (n->c.q) t = HW_MIN(t, hw_quic_timeout(n->c.q));
	if (n->s.q) t = HW_MIN(t, hw_quic_timeout(n->s.q));
	if (t > limit) {
		if (limit != UINT64_MAX && limit > n->now) n->now = limit;
		return 0;
	}
	if (t > n->now) n->now = t;
	for (;;) {
		size_t best = n->n;
		for (size_t i = 0; i < n->n; i++) {
			if (n->q[i].at > n->now) continue;
			if (best == n->n || n->q[i].at < n->q[best].at ||
			    (n->q[i].at == n->q[best].at && n->q[i].seq < n->q[best].seq)) {
				best = i;
			}
		}
		if (best == n->n) break;
		path_pkt p = n->q[best];
		n->q[best] = n->q[--n->n];
		net_deliver(n, &p);
		free(p.data);
	}
	if (n->c.q && hw_quic_timeout(n->c.q) <= n->now) hw_quic_on_timeout(n->c.q, n->now);
	if (n->s.q && hw_quic_timeout(n->s.q) <= n->now) hw_quic_on_timeout(n->s.q, n->now);
	net_flush(n);
	return 1;
}

typedef int (*net_cond)(net *n);

static int net_run(net *n, net_cond done, uint64_t max_ms) {
	uint64_t end = n->now + max_ms;
	uint64_t steps = 0;
	while (!done(n)) {
		if (!net_step_until(n, end)) return done(n);
		CHECK(++steps < 5000000, "the run never ends");
	}
	return 1;
}

static int cond_ready(net *n) {
	return n->c.w && hw_wt_ready(n->c.w) && n->s.w && hw_wt_ready(n->s.w);
}

static int cond_established(net *n) {
	return n->c.established && n->s.established;
}

static int cond_client_closed(net *n) {
	return n->c.closed > 0;
}

static int cond_server_closed(net *n) {
	return n->s.closed > 0;
}

static int cond_quic_closed(net *n) {
	return n->c.quic_closed && n->s.quic_closed;
}

static size_t g_want_packets;

static int cond_server_packets(net *n) {
	return (size_t)n->s.packets >= g_want_packets;
}

static int cond_client_packets(net *n) {
	return (size_t)n->c.packets >= g_want_packets;
}

static size_t make_packet(uint8_t *out, uint8_t type, uint32_t stream, size_t n, uint8_t seed) {
	hw_wisp_write_header(out, type, stream);
	for (size_t i = 0; i < n; i++) out[HW_WISP_HEADER_LEN + i] = (uint8_t)(seed + i * 13);
	return HW_WISP_HEADER_LEN + n;
}

// ---- Cases ------------------------------------------------------------------------------------

// A v1-style exchange: the server's stream-0 CONTINUE when the session is ready, a CONNECT, its
// CONTINUE, DATA both ways on the stream (some larger than a stream window), UDP DATA by
// datagram both ways, then the client's close.
static void session_run(uint64_t seed, uint32_t loss_ppm, uint32_t reorder_ppm) {
	net *n = net_new(seed, 256 * 1024);
	n->loss_ppm = loss_ppm;
	n->reorder_ppm = reorder_ppm;
	n->s.answer_protocol = "wisp-v2";
	net_start(n, 0);
	CHECK(net_run(n, cond_ready, 30000), "seed %llu: the session opens", (unsigned long long)seed);
	CHECK_EQ(n->s.requests, 1);
	CHECK_STR(n->s.authority, "localhost:4433");
	CHECK_STR(n->s.path, "/wisp/");
	CHECK_STR(n->s.protocols, "\"wisp-v2\"");
	CHECK_EQ(hw_wt_status(n->c.w), 200);
	CHECK_STR(hw_wt_protocol(n->c.w), "wisp-v2");
	CHECK(n->s.writable >= 1 && n->c.writable >= 1, "ready announced");
	CHECK(hw_wt_datagram_max(n->c.w) > 1000 && hw_wt_datagram_max(n->s.w) > 1000, "datagrams fit");

	uint8_t p[64];
	size_t len = make_packet(p, HW_WISP_CONTINUE, 0, 4, 0);
	hw_put_le32(p + 5, 128);
	CHECK_EQ(hw_wt_send(n->s.w, p, len, 0), 0);
	uint8_t conn[64];
	size_t cl = make_packet(conn, HW_WISP_CONNECT, 1, 0, 0);
	conn[cl++] = HW_STREAM_TCP;
	hw_put_le16(conn + cl, 80);
	cl += 2;
	memcpy(conn + cl, "example.com", 11);
	cl += 11;
	CHECK_EQ(hw_wt_send(n->c.w, conn, cl, 0), 0);
	g_want_packets = 1;
	CHECK(net_run(n, cond_client_packets, 30000) && net_run(n, cond_server_packets, 30000), "opening");
	CHECK(n->c.pkt_len[0] == len && memcmp(n->c.pkt[0], p, len) == 0, "the stream-0 CONTINUE");
	CHECK(n->s.pkt_len[0] == cl && memcmp(n->s.pkt[0], conn, cl) == 0, "the CONNECT");

	static uint8_t big[600000];
	static const size_t sizes[] = {10, 1500, 300000, 1, 70000, 9000};
	n->s.echo = 1;
	for (size_t i = 0; i < HW_ARRAY_LEN(sizes); i++) {
		size_t bl = make_packet(big, HW_WISP_DATA, 1, sizes[i], (uint8_t)i);
		CHECK_EQ(hw_wt_send(n->c.w, big, bl, 0), 0);
	}
	g_want_packets = 1 + HW_ARRAY_LEN(sizes);
	CHECK(net_run(n, cond_client_packets, 60000), "seed %llu: echoed, %d of %zu", (unsigned long long)seed,
	      n->c.packets, g_want_packets);
	for (size_t i = 0; i < HW_ARRAY_LEN(sizes); i++) {
		size_t bl = make_packet(big, HW_WISP_DATA, 1, sizes[i], (uint8_t)i);
		CHECK(n->s.pkt_len[1 + i] == bl && memcmp(n->s.pkt[1 + i], big, bl) == 0, "to the server %zu", i);
		CHECK(n->c.pkt_len[1 + i] == bl && memcmp(n->c.pkt[1 + i], big, bl) == 0, "echoed %zu", i);
		CHECK(!n->c.pkt_dgram[1 + i], "on the stream");
	}
	// UDP DATA by datagram: the server echoes each one as a datagram.
	int sent = 0;
	int before = n->c.packets;
	for (int i = 0; i < 20; i++) {
		size_t bl = make_packet(big, HW_WISP_DATA, 3, 200 + (size_t)i, (uint8_t)i);
		CHECK_EQ(hw_wt_send(n->c.w, big, bl, 1), 0);
		sent++;
		net_step_until(n, n->now + 5);
	}
	g_want_packets = (size_t)before + (size_t)sent;
	net_run(n, cond_client_packets, 3000); // with loss, some never come
	int got = n->c.packets - before;
	CHECK(got > 0 && got <= sent, "datagrams came back: %d of %d", got, sent);
	if (!loss_ppm) CHECK_EQ(got, sent);
	for (int i = before; i < n->c.packets; i++) CHECK(n->c.pkt_dgram[i], "as datagrams");
	CHECK(n->s.dgram_packets > 0, "the server read datagrams");

	// The client closes: the server hears the code and reason, then both connections end.
	n->s.echo = 0;
	hw_wt_close(n->c.w, 42, "bye");
	CHECK(net_run(n, cond_server_closed, 30000), "the server hears the close");
	CHECK_EQ(n->s.close_code, 42);
	CHECK_STR(n->s.close_reason, "bye");
	CHECK(net_run(n, cond_quic_closed, 40000), "seed %llu: both connections closed", (unsigned long long)seed);
	CHECK_EQ(n->c.quic_error, HW_H3_NO_ERROR);
	CHECK_EQ(n->c.closed, 0); // its own close is not reported back
	net_free(n);
}

static void test_wt_session(void) {
	session_run(1, 0, 0);
}

static void test_wt_session_lossy(void) {
	for (uint64_t seed = 2; seed < 6; seed++) session_run(seed, 20000, 100000);
}

static void test_wt_server_close(void) {
	net *n = net_new(7, 256 * 1024);
	net_start(n, 0);
	CHECK(net_run(n, cond_ready, 30000), "ready");
	hw_wt_close(n->s.w, 7, "server");
	CHECK(net_run(n, cond_client_closed, 30000), "the client hears the close");
	CHECK_EQ(n->c.close_code, 7);
	CHECK_STR(n->c.close_reason, "server");
	CHECK(!hw_wt_ready(n->c.w), "over");
	// The client answered with its FIN, so the server closes the connection.
	CHECK(net_run(n, cond_quic_closed, 40000), "both connections closed");
	CHECK_EQ(n->s.closed, 0);
	net_free(n);
}

static void test_wt_refused(void) {
	net *n = net_new(8, 256 * 1024);
	n->s.answer = 403;
	net_start(n, 0);
	CHECK(net_run(n, cond_client_closed, 30000), "the client hears the refusal");
	CHECK_EQ(n->s.requests, 1);
	CHECK_EQ(hw_wt_status(n->c.w), 403);
	CHECK(!hw_wt_ready(n->c.w) && !hw_wt_ready(n->s.w), "no session");
	CHECK_EQ(n->s.closed, 0);
	net_free(n);
}

// A raw client, as Chrome's bytes: its SETTINGS, then a GET, which gets a 404 and FIN.
static void test_wt_get_404(void) {
	net *n = net_new(9, 256 * 1024);
	net_start(n, 1);
	CHECK(net_run(n, cond_established, 30000), "handshake");
	uint8_t b[64];
	size_t len = 0;
	static const uint8_t settings[] = {0x00, 0x04, 0x09, 0x01, 0x00, 0x33, 0x01, 0xab, 0x60, 0x37, 0x42, 0x01};
	int64_t ctrl = hw_quic_stream_open(n->c.q, 0);
	CHECK(ctrl >= 0, "control stream");
	CHECK_EQ(hw_quic_stream_write(n->c.q, (uint64_t)ctrl, settings, sizeof(settings), 0), (int64_t)sizeof(settings));
	static const uint8_t get[] = {0x01, 0x08, 0x00, 0x00, 0xd1, 0xd7, 0xc1, 0x50, 0x01, 0x61};
	memcpy(b, get, sizeof(get));
	len = sizeof(get);
	int64_t req = hw_quic_stream_open(n->c.q, 1);
	CHECK_EQ(req, 0);
	CHECK_EQ(hw_quic_stream_write(n->c.q, 0, b, len, 1), (int64_t)len);
	for (int i = 0; i < 2000; i++) {
		int done = 0;
		for (size_t k = 0; k < n->c.n_raw; k++) done |= n->c.raw[k].id == 0 && n->c.raw[k].fin;
		if (done) break;
		net_step_until(n, n->now + 50);
	}
	size_t k = 0;
	while (k < n->c.n_raw && n->c.raw[k].id != 0) k++;
	CHECK(k < n->c.n_raw && n->c.raw[k].fin, "the response ends");
	const uint8_t *r = hw_buf_head(&n->c.raw[k].rx);
	size_t rl = hw_buf_avail(&n->c.raw[k].rx);
	CHECK(rl >= 5 && r[0] == HW_H3_FRAME_HEADERS && r[2] == 0 && r[3] == 0 && r[4] == 0xdb, "HEADERS :status 404");
	CHECK_EQ(n->s.requests, 0);
	// The server's control stream carried its SETTINGS.
	int saw = 0;
	for (size_t i = 0; i < n->c.n_raw; i++) {
		const uint8_t *c = hw_buf_head(&n->c.raw[i].rx);
		if (n->c.raw[i].id == 3 && hw_buf_avail(&n->c.raw[i].rx) > 2 && c[0] == 0 && c[1] == HW_H3_FRAME_SETTINGS) {
			saw = 1;
		}
	}
	CHECK(saw, "server SETTINGS on stream 3");
	CHECK(!n->s.quic_closed, "a GET does not end the connection");
	net_free(n);
}

// A paused server stops granting credit: the client's queue fills and hw_wt_send refuses, the
// path goes quiet, and a resume delivers everything in order.
static void test_wt_pause(void) {
	net *n = net_new(10, 64 * 1024);
	n->cwt.send_max = 50000;
	net_start(n, 0);
	CHECK(net_run(n, cond_ready, 30000), "ready");
	n->s.pause_at = 2;
	static uint8_t p[5000];
	int sent = 0, refused = 0;
	for (int i = 0; i < 2000 && !refused; i++) {
		size_t len = make_packet(p, HW_WISP_DATA, 1, 4000, (uint8_t)i);
		int r = hw_wt_send(n->c.w, p, len, 0);
		CHECK(r >= 0, "send %d", i);
		if (r == 1) {
			refused = 1;
		} else {
			sent++;
		}
		uint64_t until = n->now + 50; // a quiet path's next event is the idle timer: do not jump to it
		while (net_step_until(n, until)) {
		}
	}
	CHECK(refused, "the client is pushed back after %d packets", sent);
	CHECK_EQ(n->s.packets, 2);
	size_t queued = hw_wt_queued(n->c.w);
	CHECK(queued >= 50000, "queued %zu", queued);
	int writable = n->c.writable;
	uint64_t until = n->now + 2000;
	while (net_step_until(n, until)) {
	}
	CHECK_EQ(n->s.packets, 2);
	CHECK_EQ(n->c.writable, writable); // still blocked
	hw_wt_pause(n->s.w, 0);
	g_want_packets = (size_t)sent;
	CHECK(net_run(n, cond_server_packets, 60000), "resumed: %d of %d", n->s.packets, sent);
	CHECK(n->c.writable > writable, "the client hears it may send again");
	for (int i = 0; i < sent; i++) {
		size_t len = make_packet(p, HW_WISP_DATA, 1, 4000, (uint8_t)i);
		CHECK(n->s.pkt_len[i] == len && memcmp(n->s.pkt[i], p, len) == 0, "packet %d", i);
	}
	net_free(n);
}

int main(void) {
	cert_make();
	RUN(test_wt_session);
	RUN(test_wt_session_lossy);
	RUN(test_wt_server_close);
	RUN(test_wt_refused);
	RUN(test_wt_get_404);
	RUN(test_wt_pause);
	hw_der_free(&g_cert);
	return 0;
}
