/*
 * End to end over WebTransport: a real server with its UDP listener on an ephemeral port, real
 * echo services, the real client library speaking QUIC (hw_client_opts.webtransport). The same
 * Wisp as test_e2e.c, so what is here is what differs: the session, its admission, datagrams,
 * the certificate a page pins, and backpressure without a socket to stop reading.
 */
#include "holywisp/base64.h"
#include "holywisp/cert.h"
#include "holywisp/client.h"
#include "holywisp/ecc.h"
#include "holywisp/hw.h"
#include "holywisp/log.h"
#include "holywisp/net.h"
#include "holywisp/quic.h"
#include "holywisp/server.h"
#include "holywisp/sha256.h"
#include "holywisp/sys.h"
#include "holywisp/webtransport.h"
#include "holywisp/wisp.h"

#include "credit_cases.h"
#include "test.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <time.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/stat.h>

// ---------------------------------------------------------------------------------- services

static uint16_t g_tcp_echo_port;
static uint16_t g_udp_echo_port;
static uint16_t g_source_port; // writes without end to whoever connects, until they go
static _Atomic unsigned long long g_source_sent;

static void *tcp_echo_conn(void *arg) {
	int fd = (int)(intptr_t)arg;
	uint8_t buf[65536];
	for (;;) {
		ssize_t n = read(fd, buf, sizeof(buf));
		if (n <= 0) break;
		size_t off = 0;
		while (off < (size_t)n) {
			ssize_t w = write(fd, buf + off, (size_t)n - off);
			if (w <= 0) goto out;
			off += (size_t)w;
		}
	}
out:
	close(fd);
	return NULL;
}

static void *source_conn(void *arg) {
	int fd = (int)(intptr_t)arg;
	uint8_t buf[65536];
	memset(buf, 'x', sizeof(buf));
	for (;;) {
		ssize_t w = write(fd, buf, sizeof(buf));
		if (w <= 0) break;
		g_source_sent += (unsigned long long)w;
	}
	close(fd);
	return NULL;
}

typedef struct {
	int lfd;
	void *(*serve)(void *);
} acceptor;

static void *acceptor_main(void *arg) {
	acceptor *a = arg;
	for (;;) {
		struct pollfd pfd = {.fd = a->lfd, .events = POLLIN};
		if (poll(&pfd, 1, -1) < 0) continue;
		struct sockaddr_storage ss;
		socklen_t sl = sizeof(ss);
		int fd = accept(a->lfd, (struct sockaddr *)&ss, &sl);
		if (fd < 0) continue;
		int fl = fcntl(fd, F_GETFL, 0);
		fcntl(fd, F_SETFL, fl & ~O_NONBLOCK);
		pthread_t th;
		pthread_attr_t attr;
		pthread_attr_init(&attr);
		pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
		pthread_create(&th, &attr, a->serve, (void *)(intptr_t)fd);
		pthread_attr_destroy(&attr);
	}
	return NULL;
}

static void *udp_echo_main(void *arg) {
	int fd = (int)(intptr_t)arg;
	uint8_t buf[65536];
	for (;;) {
		struct sockaddr_storage ss;
		socklen_t sl = sizeof(ss);
		ssize_t n = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr *)&ss, &sl);
		if (n < 0) continue;
		sendto(fd, buf, (size_t)n, 0, (struct sockaddr *)&ss, sl);
	}
	return NULL;
}

static uint16_t start_tcp_service(void *(*serve)(void *)) {
	static acceptor acceptors[4];
	static int nacceptors;
	uint16_t port = 0;
	int lfd = hw_listen_tcp("127.0.0.1", 0, 0, 128, &port);
	CHECK(lfd >= 0, "listen: %s", strerror(errno));
	acceptor *a = &acceptors[nacceptors++];
	a->lfd = lfd;
	a->serve = serve;
	pthread_t th;
	pthread_create(&th, NULL, acceptor_main, a);
	pthread_detach(th);
	return port;
}

static void start_services(void) {
	g_tcp_echo_port = start_tcp_service(tcp_echo_conn);
	g_source_port = start_tcp_service(source_conn);
	int ufd = socket(AF_INET, SOCK_DGRAM, 0);
	CHECK(ufd >= 0, "udp socket: %s", strerror(errno));
	struct sockaddr_in sin = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK), .sin_port = 0};
	CHECK_EQ(bind(ufd, (struct sockaddr *)&sin, sizeof(sin)), 0);
	socklen_t sl = sizeof(sin);
	getsockname(ufd, (struct sockaddr *)&sin, &sl);
	g_udp_echo_port = ntohs(sin.sin_port);
	pthread_t th;
	pthread_create(&th, NULL, udp_echo_main, (void *)(intptr_t)ufd);
	pthread_detach(th);
}

// ---------------------------------------------------------------------------------- helpers

static hw_server *g_server;

static void base_config(hw_server_config *cfg) {
	hw_server_config_defaults(cfg);
	strcpy(cfg->host, "127.0.0.1");
	cfg->port = 0;
	cfg->workers = 2;
	cfg->allow_direct_ip = 1;
	cfg->allow_loopback = 1;
	cfg->buffer_remaining = 16;
	cfg->stream_queue_max = 32u * 1024 * 1024;
	cfg->log_level = HW_LOG_WARN;
	cfg->webtransport = 1;
	strcpy(cfg->webtransport_host, "127.0.0.1");
	cfg->webtransport_port = 0;
}

static hw_server *server_with(const hw_server_config *cfg) {
	hw_server *s = hw_server_new(cfg);
	CHECK(s != NULL, "server: %s", strerror(errno));
	CHECK_EQ(hw_server_start(s), 0);
	CHECK(hw_server_wt_port(s) != 0, "webtransport port");
	return s;
}

typedef struct {
	int v2;
	const char *origin;
	const uint8_t *pin;
	size_t max_queue;
	const char *name; // SNI and :authority, the server still reached at 127.0.0.1
	const char *path;
	int server_stream; // offer "wisp-v2-server-stream" (with v2)
	int lanes;         // ride up to this many lanes (with v2)
} wt_opts;

static hw_client *wt_try(hw_server *s, const wt_opts *w, char *err, size_t err_cap) {
	hw_client_opts o;
	hw_client_opts_defaults(&o);
	o.host = "127.0.0.1";
	o.port = hw_server_wt_port(s);
	o.webtransport = 1;
	o.v2 = w ? w->v2 : 0;
	o.origin = w ? w->origin : NULL;
	o.pin_sha256 = w ? w->pin : NULL;
	if (w && w->max_queue) o.max_queue_bytes = w->max_queue;
	if (w && w->name) o.server_name = w->name;
	if (w && w->path) o.path = w->path;
	o.wt_server_stream = w ? w->server_stream : 0;
	o.wt_lanes = w ? w->lanes : 0;
	o.timeout_ms = 5000;
	return hw_client_connect(&o, err, err_cap);
}

static hw_client *wt_connect(hw_server *s, const wt_opts *w) {
	char err[256];
	hw_client *c = wt_try(s, w, err, sizeof(err));
	CHECK(c != NULL, "connect: %s", err);
	return c;
}

static int wait_event(hw_client *c, uint32_t sid, int type, hw_client_event *out, int timeout_ms) {
	uint64_t deadline = hw_now_ms() + (uint64_t)timeout_ms;
	for (;;) {
		uint64_t now = hw_now_ms();
		if (now >= deadline) return 0;
		int r = hw_client_poll(c, (int)(deadline - now), out);
		if (r <= 0) return r;
		if (out->stream_id == sid && (type == 0 || out->type == type)) return 1;
	}
}

static void fill_pattern(uint8_t *buf, size_t n, uint32_t seed) {
	uint32_t x = seed * 2654435761u + 1;
	for (size_t i = 0; i < n; i++) {
		x ^= x << 13;
		x ^= x >> 17;
		x ^= x << 5;
		buf[i] = (uint8_t)x;
	}
}

static hw_server_stats stats(hw_server *s) {
	hw_server_stats st;
	hw_server_stats_get(s, &st);
	return st;
}

// Wait until the server has no session (and so no stream) left.
static void wait_sessions_gone(hw_server *s, int timeout_ms) {
	uint64_t deadline = hw_now_ms() + (uint64_t)timeout_ms;
	while (hw_now_ms() < deadline) {
		hw_server_stats st = stats(s);
		if (st.wt_sessions_active == 0 && st.streams_active == 0 && st.connections_active == 0) return;
		usleep(10000);
	}
	hw_server_stats st = stats(s);
	CHECK(st.wt_sessions_active == 0 && st.streams_active == 0 && st.connections_active == 0,
	      "sessions %llu streams %llu connections %llu still active", (unsigned long long)st.wt_sessions_active,
	      (unsigned long long)st.streams_active, (unsigned long long)st.connections_active);
}

// One plain HTTP request to the server's TCP port; the whole response into buf.
static size_t http_get(hw_server *s, const char *path, char *buf, size_t cap) {
	int fd = hw_connect_tcp("127.0.0.1", hw_server_port(s), 2000);
	CHECK(fd >= 0, "connect");
	char req[256];
	int n = snprintf(req, sizeof(req), "GET %s HTTP/1.1\r\nHost: x\r\n\r\n", path);
	CHECK_EQ(write(fd, req, (size_t)n), n);
	size_t got = 0;
	for (;;) {
		ssize_t r = read(fd, buf + got, cap - 1 - got);
		if (r <= 0) break;
		got += (size_t)r;
	}
	buf[got] = '\0';
	close(fd);
	return got;
}

static int b64_value(char ch) {
	static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	const char *p = ch ? strchr(b64, ch) : NULL;
	return p ? (int)(p - b64) : -1;
}

// The hashes /webtransport.json lists, decoded. Returns how many.
static int json_hashes(hw_server *s, uint8_t out[][32], int max, char *json, size_t cap) {
	http_get(s, "/webtransport.json", json, cap);
	const char *p = json;
	int n = 0;
	while (n < max && (p = strstr(p, "\"value\":\""))) {
		p += 9;
		uint32_t acc = 0;
		int bits = 0;
		size_t got = 0;
		for (; *p && *p != '"' && *p != '='; p++) {
			int v = b64_value(*p);
			CHECK(v >= 0, "base64 in %s", json);
			acc = acc << 6 | (uint32_t)v;
			bits += 6;
			if (bits >= 8) {
				bits -= 8;
				CHECK(got < 32, "hash longer than 32 bytes");
				out[n][got++] = (uint8_t)(acc >> bits);
			}
		}
		CHECK_EQ(got, 32);
		n++;
	}
	return n;
}

// ---------------------------------------------------------------------------------- cases

static void test_v1_tcp_echo(void) {
	hw_client *c = wt_connect(g_server, NULL);
	CHECK(!hw_client_is_v2(c), "v1");
	CHECK_EQ(hw_client_buffer_size(c), 16);
	CHECK(hw_client_wait_ms(c) >= 0, "QUIC has a timer");
	// In microseconds the same deadline, not rounded to a millisecond (asked second, so it is no later).
	int wait_ms = hw_client_wait_ms(c);
	int64_t wait_us = hw_client_wait_us(c);
	CHECK(wait_us >= 0 && wait_us <= ((int64_t)wait_ms + 1) * 1000, "wait %lld us, %d ms", (long long)wait_us, wait_ms);
	uint32_t sid;
	CHECK_EQ(hw_client_open(c, HW_STREAM_TCP, "127.0.0.1", g_tcp_echo_port, &sid), 0);
	CHECK_EQ(hw_client_send(c, sid, "hello wisp", 10), 0);
	uint8_t buf[10];
	CHECK_EQ(hw_client_read_exact(c, sid, buf, 10, 5000), 10);
	CHECK(memcmp(buf, "hello wisp", 10) == 0, "echo");

	// Enough to run the window down many times and to be framed into many packets each way.
	const size_t total = 4 * 1024 * 1024;
	const size_t chunk = 60 * 1024;
	uint8_t *data = malloc(total);
	uint8_t *back = malloc(total);
	fill_pattern(data, total, 7);
	size_t sent = 0, got = 0;
	while (got < total) {
		if (sent < total) {
			size_t n = HW_MIN(chunk, total - sent);
			CHECK_EQ(hw_client_send(c, sid, data + sent, n), 0);
			sent += n;
		}
		hw_client_event ev;
		int r;
		while ((r = hw_client_poll(c, sent < total ? 0 : 5000, &ev)) > 0) {
			if (ev.type == HW_CEV_DATA && ev.stream_id == sid) {
				CHECK(got + ev.len <= total, "overflow");
				memcpy(back + got, ev.data, ev.len);
				got += ev.len;
			}
			CHECK(ev.type != HW_CEV_CLOSE, "closed 0x%02x", ev.reason);
			if (got == total) break;
		}
		CHECK(r >= 0, "poll %d", r);
		CHECK(r > 0 || sent < total, "timed out at %zu/%zu", got, total);
	}
	CHECK(memcmp(data, back, total) == 0, "echo intact");
	free(data);
	free(back);
	CHECK_EQ(hw_client_close_stream(c, sid, HW_CLOSE_VOLUNTARY), 0);
	hw_server_stats st = stats(g_server);
	CHECK(st.wt_sessions_active >= 1, "a session is counted");
	hw_client_free(c);
	wait_sessions_gone(g_server, 5000);
}

static void test_v2_handshake(void) {
	wt_opts w = {.v2 = 1};
	hw_client *c = wt_connect(g_server, &w);
	CHECK(hw_client_is_v2(c), "v2 negotiated");
	CHECK_STR(hw_client_motd(c), "welcome to the webtransport test server");
	CHECK(hw_client_server_has_udp(c), "udp advertised");
	uint32_t sid;
	CHECK_EQ(hw_client_open(c, HW_STREAM_TCP, "127.0.0.1", g_tcp_echo_port, &sid), 0);
	CHECK_EQ(hw_client_send(c, sid, "v2 over quic", 12), 0);
	uint8_t buf[12];
	CHECK_EQ(hw_client_read_exact(c, sid, buf, 12, 5000), 12);
	CHECK(memcmp(buf, "v2 over quic", 12) == 0, "echo");
	hw_client_free(c);
	wait_sessions_gone(g_server, 5000);
}

// UDP stream DATA travels as QUIC datagrams both ways; a datagram may be lost, so a few tries.
static void test_udp_datagram_echo(void) {
	hw_client *c = wt_connect(g_server, NULL);
	uint32_t sid;
	CHECK_EQ(hw_client_open(c, HW_STREAM_UDP, "127.0.0.1", g_udp_echo_port, &sid), 0);
	int echoed = 0;
	for (int i = 0; i < 20 && !echoed; i++) {
		char msg[32];
		int n = snprintf(msg, sizeof(msg), "datagram %d", i);
		CHECK_EQ(hw_client_send(c, sid, msg, (size_t)n), 0);
		hw_client_event ev;
		uint64_t until = hw_now_ms() + 300;
		while (!echoed && hw_now_ms() < until) {
			int r = wait_event(c, sid, 0, &ev, (int)(until - hw_now_ms()));
			if (r <= 0) break;
			CHECK(ev.type != HW_CEV_CLOSE, "closed 0x%02x", ev.reason);
			if (ev.type == HW_CEV_DATA) {
				CHECK(ev.len >= 9 && memcmp(ev.data, "datagram ", 9) == 0, "payload");
				echoed = 1;
			}
		}
	}
	CHECK(echoed, "a datagram came back");
	// Larger than one datagram: it goes on the Wisp stream instead, and arrives whole.
	uint8_t big[4000];
	fill_pattern(big, sizeof(big), 3);
	echoed = 0;
	for (int i = 0; i < 10 && !echoed; i++) {
		CHECK_EQ(hw_client_send(c, sid, big, sizeof(big)), 0);
		hw_client_event ev;
		if (wait_event(c, sid, HW_CEV_DATA, &ev, 500) == 1) {
			CHECK_EQ(ev.len, sizeof(big));
			CHECK(memcmp(ev.data, big, sizeof(big)) == 0, "payload");
			echoed = 1;
		}
	}
	CHECK(echoed, "a large datagram came back");
	hw_client_free(c);
	wait_sessions_gone(g_server, 5000);
}

static void test_egress_blocked(void) {
	hw_server_config cfg;
	base_config(&cfg);
	cfg.workers = 1;
	cfg.allow_loopback = 0;
	cfg.log_level = HW_LOG_NONE;
	hw_server *s = server_with(&cfg);
	hw_client *c = wt_connect(s, NULL);
	uint32_t sid;
	hw_client_event ev;
	CHECK_EQ(hw_client_open(c, HW_STREAM_TCP, "127.0.0.1", g_tcp_echo_port, &sid), 0);
	CHECK_EQ(wait_event(c, sid, HW_CEV_CLOSE, &ev, 5000), 1);
	CHECK_EQ(ev.reason, HW_CLOSE_BLOCKED);
	CHECK_EQ(hw_client_open(c, HW_STREAM_UDP, "10.1.2.3", 53, &sid), 0);
	CHECK_EQ(wait_event(c, sid, HW_CEV_CLOSE, &ev, 5000), 1);
	CHECK_EQ(ev.reason, HW_CLOSE_BLOCKED);
	hw_client_free(c);
	hw_server_free(s);
}

// The upgrade's connection checks, at the CONNECT: per-IP gauge (429) and origin list (403).
static void test_admission(void) {
	hw_server_config cfg;
	base_config(&cfg);
	cfg.workers = 1;
	cfg.flood.enabled = 1;
	cfg.flood.max_concurrent_connections = 100;
	cfg.flood.max_concurrent_connections_per_ip = 1;
	strcpy(cfg.allow_origins[0], "https://good.example");
	cfg.allow_origin_count = 1;
	cfg.log_level = HW_LOG_NONE;
	hw_server *s = server_with(&cfg);
	char err[256];

	wt_opts bad = {.origin = "https://evil.example"};
	hw_client *c = wt_try(s, &bad, err, sizeof(err));
	CHECK(c == NULL, "an origin not on the list is refused");
	CHECK(strstr(err, "403") != NULL, "403: %s", err);

	wt_opts good = {.origin = "https://good.example"};
	hw_client *first = wt_connect(s, &good);
	hw_client *second = wt_try(s, NULL, err, sizeof(err)); // no origin: not a browser, never refused for it
	CHECK(second == NULL, "a second session from the address is over its share");
	CHECK(strstr(err, "429") != NULL, "429: %s", err);
	hw_client_free(first);
	wait_sessions_gone(s, 5000);
	second = wt_connect(s, NULL);
	hw_client_free(second);
	hw_server_free(s);
}

// The certificate a page pins is the one served, and nothing else is accepted under a pin.
static void test_certificate_json(void) {
	char json[2048];
	uint8_t hashes[2][32];
	int n = json_hashes(g_server, hashes, 2, json, sizeof(json));
	CHECK(strstr(json, "HTTP/1.1 200") == json, "status: %.40s", json);
	CHECK(strstr(json, "Access-Control-Allow-Origin: *") != NULL, "CORS: %s", json);
	CHECK(strstr(json, "no-store") != NULL, "not cached: %s", json);
	CHECK(strstr(json, "\"url\":\"https://wt.example:4433/\"") != NULL, "url: %s", json);
	CHECK_EQ(n, 1);

	wt_opts pinned = {.pin = hashes[0]};
	hw_client *c = wt_connect(g_server, &pinned);
	hw_client_free(c);

	uint8_t wrong[32];
	memcpy(wrong, hashes[0], 32);
	wrong[0] ^= 1;
	wt_opts mispinned = {.pin = wrong};
	char err[256];
	c = wt_try(g_server, &mispinned, err, sizeof(err));
	CHECK(c == NULL, "a pin that does not match is refused");
	wait_sessions_gone(g_server, 5000);
}

// Past the threshold every unvalidated Initial gets a Retry, and the client goes on with the
// token.
static void test_retry(void) {
	hw_server_config cfg;
	base_config(&cfg);
	cfg.workers = 1;
	cfg.webtransport_retry_threshold = 0;
	cfg.log_level = HW_LOG_NONE;
	hw_server *s = server_with(&cfg);
	hw_client *c = wt_connect(s, NULL);
	uint32_t sid;
	CHECK_EQ(hw_client_open(c, HW_STREAM_TCP, "127.0.0.1", g_tcp_echo_port, &sid), 0);
	CHECK_EQ(hw_client_send(c, sid, "retried", 7), 0);
	uint8_t buf[7];
	CHECK_EQ(hw_client_read_exact(c, sid, buf, 7, 5000), 7);
	CHECK(memcmp(buf, "retried", 7) == 0, "echo");
	hw_server_stats st = stats(s);
	CHECK(st.wt_retries >= 1, "a Retry was sent");
	CHECK_EQ(st.wt_sessions_total, 1);
	hw_client_free(c);
	hw_server_free(s);
}

// A client that goes quiet is gone after the idle timeout, session and streams.
static void test_idle_timeout(void) {
	hw_server_config cfg;
	base_config(&cfg);
	cfg.workers = 1;
	cfg.webtransport_idle_timeout_s = 1;
	cfg.log_level = HW_LOG_NONE;
	hw_server *s = server_with(&cfg);
	hw_client *c = wt_connect(s, NULL);
	uint32_t sid;
	CHECK_EQ(hw_client_open(c, HW_STREAM_TCP, "127.0.0.1", g_tcp_echo_port, &sid), 0);
	hw_client_event ev;
	CHECK_EQ(hw_client_send(c, sid, "x", 1), 0);
	CHECK_EQ(wait_event(c, sid, HW_CEV_DATA, &ev, 5000), 1);
	CHECK_EQ(stats(s).wt_sessions_active, 1);
	// Not called, the client acknowledges nothing and sends no keepalive.
	usleep(200 * 1000);
	wait_sessions_gone(s, 5000);
	hw_client_free(c);
	hw_server_free(s);
}

// A client that stops reading: the session's credit runs out, the server's queue toward it stops
// at the high-water mark and the remote is paused, so what the server holds is bounded; reading
// again drains it and the stream goes on.
static void test_stalled_reader(void) {
	hw_server_config cfg;
	base_config(&cfg);
	cfg.workers = 1;
	cfg.ws_write_high_water = 1024 * 1024;
	cfg.log_level = HW_LOG_NONE;
	hw_server *s = server_with(&cfg);
	wt_opts w = {.max_queue = 4 * 1024 * 1024};
	hw_client *c = wt_connect(s, &w);
	uint32_t sid;
	CHECK_EQ(hw_client_open(c, HW_STREAM_TCP, "127.0.0.1", g_source_port, &sid), 0);
	hw_client_event ev;
	CHECK_EQ(wait_event(c, sid, HW_CEV_DATA, &ev, 5000), 1);

	// Not read for a while: the client's queue fills, it withholds credit, and the server stops.
	usleep(1500 * 1000);
	hw_server_stats a = stats(s);
	usleep(1000 * 1000);
	hw_server_stats b = stats(s);
	CHECK(b.bytes_out - a.bytes_out < 1024 * 1024, "the server kept sending: %llu bytes in a second",
	      (unsigned long long)(b.bytes_out - a.bytes_out));
	// The client holds its queue, its window, and the server's queue; nothing grows past those.
	// 4 MiB queue + 16 MiB QUIC window + 2x the high-water mark, and slack for the pipes.
	CHECK(b.bytes_out < 32ull * 1024 * 1024, "bytes out %llu", (unsigned long long)b.bytes_out);
	unsigned long long src_a = g_source_sent;
	usleep(500 * 1000);
	CHECK(g_source_sent - src_a < 1024 * 1024, "the remote is still read: %llu",
	      (unsigned long long)(g_source_sent - src_a));

	// Reading again: the queue drains and the stream moves. Past what the queues held (32 MiB at
	// most), so this is new data; not a throughput figure (macOS's sanitized build on CI did 62 MiB
	// in 5 s).
	size_t got = 0;
	uint64_t until = hw_now_ms() + 10000;
	while (got < 48ull * 1024 * 1024 && hw_now_ms() < until) {
		int r = hw_client_poll(c, 1000, &ev);
		CHECK(r > 0, "poll %d", r);
		CHECK(ev.type != HW_CEV_CLOSE, "closed 0x%02x", ev.reason);
		if (ev.type == HW_CEV_DATA) got += ev.len;
	}
	CHECK(got >= 48ull * 1024 * 1024, "resumed: %zu bytes in 10 s", got);
	hw_client_free(c);
	wait_sessions_gone(s, 5000);
	hw_server_free(s);
}

// A PEM block of der under label, written to a new temporary file whose path goes to path.
static void write_pem(char *path, size_t cap, const char *label, const uint8_t *der, size_t len) {
	hw_test_tmp(path, cap, "hw-wt-pem");
	int fd = mkstemp(path);
	CHECK(fd >= 0, "mkstemp: %s", strerror(errno));
	size_t b64_cap = HW_BASE64_LEN(len);
	char *b64 = malloc(b64_cap);
	CHECK(b64 != NULL, "malloc");
	size_t n = hw_base64_encode(der, len, b64, b64_cap);
	FILE *f = fdopen(fd, "w");
	CHECK(f != NULL, "fdopen");
	fprintf(f, "-----BEGIN %s-----\n", label);
	for (size_t i = 0; i < n; i += 64) fprintf(f, "%.*s\n", (int)HW_MIN((size_t)64, n - i), b64 + i);
	fprintf(f, "-----END %s-----\n", label);
	fclose(f);
	free(b64);
}

// A SEC 1 ECPrivateKey for P-256 (RFC 5915), with its public key.
static size_t sec1_key(const uint8_t priv[HW_P256_PRIV_LEN], const uint8_t pub[HW_P256_PUB_LEN], uint8_t *out) {
	static const uint8_t head[] = {0x30, 0x77, 0x02, 0x01, 0x01, 0x04, 0x20};
	static const uint8_t curve[] = {0xa0, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07};
	static const uint8_t pub_head[] = {0xa1, 0x44, 0x03, 0x42, 0x00};
	size_t n = 0;
	memcpy(out + n, head, sizeof(head));
	n += sizeof(head);
	memcpy(out + n, priv, HW_P256_PRIV_LEN);
	n += HW_P256_PRIV_LEN;
	memcpy(out + n, curve, sizeof(curve));
	n += sizeof(curve);
	memcpy(out + n, pub_head, sizeof(pub_head));
	n += sizeof(pub_head);
	memcpy(out + n, pub, HW_P256_PUB_LEN);
	return n + HW_P256_PUB_LEN;
}

// The operator's certificate and key, loaded once: served as they are, nothing listed in
// /webtransport.json (the Web PKI verifies such a certificate, not a pin), and a key that is not
// the certificate's keeps the server from starting.
static void test_operator_certificate(void) {
	uint8_t priv[HW_P256_PRIV_LEN], pub[HW_P256_PUB_LEN];
	CHECK_EQ(hw_p256_keygen(priv, pub), 0);
	hw_der cert = {0};
	int64_t now = (int64_t)time(NULL);
	CHECK_EQ(hw_cert_selfsigned(priv, pub, "wt.example", now - 3600, now + 7 * 86400, &cert), 0);
	uint8_t key[128];
	size_t key_len = sec1_key(priv, pub, key);
	char cert_path[512], key_path[512];
	write_pem(cert_path, sizeof(cert_path), "CERTIFICATE", cert.der, cert.len);
	write_pem(key_path, sizeof(key_path), "EC PRIVATE KEY", key, key_len);

	hw_server_config cfg;
	base_config(&cfg);
	cfg.workers = 1;
	cfg.log_level = HW_LOG_NONE;
	snprintf(cfg.webtransport_cert, sizeof(cfg.webtransport_cert), "%s", cert_path);
	snprintf(cfg.webtransport_key, sizeof(cfg.webtransport_key), "%s", key_path);
	char err[512];
	CHECK(hw_server_config_check(&cfg, err, sizeof(err)) == 0, "the pair passes the check: %s", err);
	hw_server *s = server_with(&cfg);
	char json[2048];
	uint8_t hashes[2][32];
	CHECK_EQ(json_hashes(s, hashes, 2, json, sizeof(json)), 0);
	CHECK(strstr(json, "\"hashes\":[]") != NULL, "json: %s", json);
	uint8_t pin[32];
	hw_sha256(cert.der, cert.len, pin);
	wt_opts pinned = {.pin = pin};
	hw_client *c = wt_connect(s, &pinned);
	hw_client_free(c);
	hw_server_free(s);

	// Another key: refused at start, not at the first handshake.
	uint8_t other[HW_P256_PRIV_LEN], other_pub[HW_P256_PUB_LEN];
	CHECK_EQ(hw_p256_keygen(other, other_pub), 0);
	key_len = sec1_key(other, other_pub, key);
	unlink(key_path);
	write_pem(key_path, sizeof(key_path), "EC PRIVATE KEY", key, key_len);
	snprintf(cfg.webtransport_key, sizeof(cfg.webtransport_key), "%s", key_path);
	// --check-config says so before a start would, and binds nothing to say it.
	CHECK(hw_server_config_check(&cfg, err, sizeof(err)) != 0, "a key that is not the certificate's is checked");
	CHECK(strstr(err, "not the key of the first certificate") != NULL, "the reason: %s", err);
	CHECK(hw_server_new(&cfg) == NULL, "a key that is not the certificate's is refused");
	unlink(cert_path);
	unlink(key_path);
	hw_der_free(&cert);
}

// ---------------------------------------------------------------------------------- a raw client
//
// The client role of the stack driven by hand, for what the client library would never do: end
// the Wisp stream and keep the session, go silent after a close, or ignore the server's close and
// keep sending.

typedef struct {
	int fd;
	hw_quic_conn *q;
	hw_wt *wt;
	int quic_closed;     // QUIC's closed callback has run
	int session_closed;  // hw_wt's session_closed has run (the server's capsule, or its FIN)
	int heard_close;     // ... and before the connection closed, so not because it did
	uint32_t close_code; // ... with this code
	int dgrams;          // datagrams taken in
	int packet_dgram;    // the datagram the last Wisp packet came in, and the one that closed the session
	int close_dgram;
	char quic_reason[32]; // the reason in the server's CONNECTION_CLOSE
	int deaf;             // the session is open: what arrives on the CONNECT stream is dropped unread
	int packets;          // Wisp packets from the server
	uint8_t last_type;
	uint32_t last_stream;
	uint8_t last_reason; // the first payload byte of the last packet (a CLOSE's reason)
	int data_packets;
	char authority[64];
	uint8_t types[16]; // the first packets' types and streams, in order
	uint32_t streams[16];
	int info_lanes;                       // HW_EXT_LANES in the server's INFO
	uint64_t lane_bytes[HW_WT_LANES_MAX]; // DATA payload bytes from the server, by lane
	int stalling;                         // what arrives on stall_id is dropped unread and never credited
	uint64_t stall_id;
	uint64_t stalled;
} raw_wt;

static void raw_q_established(void *ud) {
	raw_wt *r = ud;
	hw_wt_on_established(r->wt);
}

static void raw_q_stream_data(void *ud, uint64_t id, const uint8_t *data, size_t len, int fin) {
	raw_wt *r = ud;
	// Stream 0 is the CONNECT's: deaf, the client never sees the capsule and never answers it.
	if (r->deaf && id == 0) {
		hw_quic_stream_consumed(r->q, id, len);
		return;
	}
	// A lane whose reader has stopped: its stream window runs out at the server.
	if (r->stalling && id == r->stall_id) {
		r->stalled += len;
		return;
	}
	hw_wt_on_stream_data(r->wt, id, data, len, fin);
}

static void raw_q_stream_reset(void *ud, uint64_t id, uint64_t app_error) {
	raw_wt *r = ud;
	hw_wt_on_stream_reset(r->wt, id, app_error);
}

static void raw_q_stream_stop(void *ud, uint64_t id, uint64_t app_error) {
	raw_wt *r = ud;
	hw_wt_on_stream_stop(r->wt, id, app_error);
}

static void raw_q_stream_writable(void *ud, uint64_t id) {
	raw_wt *r = ud;
	hw_wt_on_stream_writable(r->wt, id);
}

static void raw_q_datagram(void *ud, const uint8_t *data, size_t len) {
	raw_wt *r = ud;
	hw_wt_on_datagram(r->wt, data, len);
}

static void raw_q_cid(void *ud, const uint8_t cid[HW_QUIC_CID_LEN], int retire) {
	(void)ud;
	(void)cid;
	(void)retire;
}

static void raw_q_closed(void *ud, uint64_t error, int app, const char *reason) {
	raw_wt *r = ud;
	(void)error;
	(void)app;
	snprintf(r->quic_reason, sizeof(r->quic_reason), "%s", reason ? reason : "");
	r->quic_closed = 1;
	hw_wt_on_closed(r->wt);
}

static void raw_w_packet(void *ud, const uint8_t *data, size_t len, int datagram) {
	raw_wt *r = ud;
	(void)datagram;
	hw_wisp_packet p;
	if (hw_wisp_parse(data, len, &p) != 0) return;
	r->packet_dgram = r->dgrams;
	if (r->packets < 16) {
		r->types[r->packets] = p.type;
		r->streams[r->packets] = p.stream_id;
	}
	r->packets++;
	r->last_type = p.type;
	r->last_stream = p.stream_id;
	r->last_reason = p.payload_len ? p.payload[0] : 0;
	hw_wisp_info info;
	if (p.type == HW_WISP_INFO && hw_wisp_parse_info(&p, &info) == 0) r->info_lanes = info.lanes;
	if (p.type == HW_WISP_DATA) {
		r->data_packets++;
		int lane = hw_wt_packet_lane(r->wt);
		if (lane >= 0) r->lane_bytes[lane] += p.payload_len;
	}
}

static void raw_w_session_closed(void *ud, uint32_t code, const char *reason) {
	raw_wt *r = ud;
	(void)reason;
	r->session_closed = 1;
	r->close_dgram = r->dgrams;
	r->heard_close = !r->quic_closed;
	r->close_code = code;
}

static void raw_output(raw_wt *r) {
	uint8_t out[HW_QUIC_MAX_DGRAM];
	for (;;) {
		struct sockaddr_storage to;
		socklen_t tl = sizeof(to);
		size_t n = hw_quic_output(r->q, out, sizeof(out), &to, &tl, hw_now_ms());
		if (n == 0) return;
		ssize_t w = send(r->fd, out, n, 0);
		(void)w; // a datagram the socket refuses is lost, and QUIC sends it again
	}
}

// Receive, run the timers and send for up to ms milliseconds, or until *until becomes nonzero.
static void raw_pump(raw_wt *r, int ms, const int *until) {
	uint64_t deadline = hw_now_ms() + (uint64_t)ms;
	for (;;) {
		raw_output(r);
		if (until && *until) return;
		uint64_t now = hw_now_ms();
		if (now >= deadline) return;
		uint64_t at = hw_quic_timeout(r->q);
		uint64_t wake = at < deadline ? at : deadline;
		struct pollfd p = {r->fd, POLLIN, 0};
		poll(&p, 1, wake > now ? (int)(wake - now) : 0);
		uint8_t buf[2048];
		ssize_t n;
		while ((n = recv(r->fd, buf, sizeof(buf), MSG_DONTWAIT)) > 0) {
			struct sockaddr_in from;
			socklen_t fl = sizeof(from);
			getpeername(r->fd, (struct sockaddr *)&from, &fl);
			r->dgrams++;
			hw_quic_input(r->q, buf, (size_t)n, (struct sockaddr *)&from, fl, hw_now_ms());
		}
		if (hw_now_ms() >= hw_quic_timeout(r->q)) hw_quic_on_timeout(r->q, hw_now_ms());
	}
}

// A session with the server offering protocols (NULL for none: v1), opened, and the server's first
// packet received. stream_window is the credit each stream gives the server (0: 4 MiB).
static void raw_open_with(raw_wt *r, hw_server *s, const char *protocols, size_t stream_window) {
	static const char *const alpn[] = {HW_WT_ALPN};
	memset(r, 0, sizeof(*r));
	struct sockaddr_in to = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
	to.sin_port = htons(hw_server_wt_port(s));
	r->fd = socket(AF_INET, SOCK_DGRAM, 0);
	CHECK(r->fd >= 0, "socket");
	CHECK_EQ(connect(r->fd, (struct sockaddr *)&to, sizeof(to)), 0);
	hw_quic_config qc;
	memset(&qc, 0, sizeof(qc));
	qc.tls.alpn = alpn;
	qc.tls.alpn_count = 1;
	qc.max_idle_ms = 60000;
	qc.initial_max_data = 4u << 20;
	qc.initial_max_stream_data = stream_window ? stream_window : 4u << 20;
	qc.initial_max_streams_bidi = 16;
	qc.initial_max_streams_uni = 16;
	qc.max_datagram_frame_size = 65535;
	qc.stream_send_max = 4u << 20;
	qc.conn_send_max = 4u << 20;
	qc.datagram_queue_max = 64;
	hw_quic_callbacks cb = {
	    .ud = r,
	    .established = raw_q_established,
	    .stream_data = raw_q_stream_data,
	    .stream_reset = raw_q_stream_reset,
	    .stream_stop = raw_q_stream_stop,
	    .stream_writable = raw_q_stream_writable,
	    .datagram = raw_q_datagram,
	    .cid = raw_q_cid,
	    .closed = raw_q_closed,
	};
	r->q = hw_quic_connect(&qc, &cb, (struct sockaddr *)&to, sizeof(to), hw_now_ms());
	CHECK(r->q != NULL, "quic connect");
	snprintf(r->authority, sizeof(r->authority), "127.0.0.1:%u", hw_server_wt_port(s));
	hw_wt_config wc = {
	    .max_packet = 1u << 20,
	    .is_client = 1,
	    .authority = r->authority,
	    .path = "/",
	    .protocols = protocols,
	};
	hw_wt_callbacks wcb = {.ud = r, .packet = raw_w_packet, .session_closed = raw_w_session_closed};
	r->wt = hw_wt_new(r->q, &wc, &wcb);
	CHECK(r->wt != NULL, "hw_wt");
	uint64_t until = hw_now_ms() + 5000;
	while (r->packets == 0 && !r->quic_closed && hw_now_ms() < until) raw_pump(r, 20, &r->packets);
	CHECK(r->packets > 0, "the server's opening (ready %d, status %d)", hw_wt_ready(r->wt), hw_wt_status(r->wt));
}

// A session, v1 or v2 ("wisp-v2" alone), opened (and for v1, its CONTINUE received).
static void raw_open(raw_wt *r, hw_server *s, int v2) {
	raw_open_with(r, s, v2 ? "\"wisp-v2\"" : NULL, 0);
}

static void raw_free(raw_wt *r) {
	hw_wt_free(r->wt);
	hw_quic_free(r->q);
	close(r->fd);
}

static void raw_send(raw_wt *r, const uint8_t *pkt, size_t len) {
	CHECK_EQ(hw_wt_send(r->wt, pkt, len, 0), 0);
	raw_output(r);
}

// Server stats that hold for a while, with the client pumped meanwhile (it has to answer).
static int raw_wait_server(raw_wt *r, hw_server *s, int ms, int want_sessions, int want_conns) {
	uint64_t until = hw_now_ms() + (uint64_t)ms;
	while (hw_now_ms() < until) {
		hw_server_stats st = stats(s);
		if ((int)st.wt_sessions_active == want_sessions && (int)st.connections_active == want_conns) return 1;
		if (r) {
			raw_pump(r, 10, NULL);
		} else {
			usleep(10000);
		}
	}
	return 0;
}

// A client that ends its Wisp stream but leaves the CONNECT stream open has said all it will: the
// session closes at once with the capsule (code 0), as a WebSocket closes at its client's EOF, and
// the session and its streams are gone long before the 30 s idle timeout.
static void test_wisp_stream_end(void) {
	hw_server_config cfg;
	base_config(&cfg);
	cfg.log_level = HW_LOG_NONE;
	hw_server *s = server_with(&cfg);
	raw_wt r;
	raw_open(&r, s, 0);
	uint8_t pkt[64];
	size_t n = hw_wisp_build_connect(pkt, sizeof(pkt), 1, HW_STREAM_TCP, g_tcp_echo_port, "127.0.0.1", 9);
	raw_send(&r, pkt, n);
	static const uint8_t abc[3] = {'a', 'b', 'c'};
	uint8_t data[HW_WISP_HEADER_LEN + sizeof(abc)];
	hw_wisp_write_header(data, HW_WISP_DATA, 1);
	memcpy(data + HW_WISP_HEADER_LEN, abc, sizeof(abc));
	raw_send(&r, data, sizeof(data));
	uint64_t until = hw_now_ms() + 5000;
	while (r.data_packets == 0 && hw_now_ms() < until) raw_pump(&r, 20, &r.data_packets);
	CHECK(r.data_packets > 0, "echo");
	CHECK_EQ(stats(s).streams_active, 1);

	// The Wisp stream is the client's second bidirectional one (0 is the CONNECT's): its FIN alone.
	CHECK(hw_quic_stream_write(r.q, 4, NULL, 0, 1) >= 0, "FIN on the Wisp stream");
	uint64_t t0 = hw_now_ms();
	raw_pump(&r, 3000, &r.session_closed);
	CHECK(r.session_closed, "the session was not closed in 3 s");
	CHECK_EQ(r.close_code, 0);
	// The client's hw_wt answers the capsule with its FIN, and that ends the connection: well before
	// WT_CLOSE_MS (3 s), which is only for a client that does not answer.
	CHECK(raw_wait_server(&r, s, 3000, 0, 0), "the session and its connection are still there");
	CHECK_EQ(stats(s).streams_active, 0);
	CHECK(hw_now_ms() - t0 < 2000, "took %llu ms", (unsigned long long)(hw_now_ms() - t0));
	raw_free(&r);
	hw_server_free(s);
}

// ---------------------------------------------------------------------------------- lanes

#define OFFER_SERVER_STREAM "\"wisp-v2\", \"wisp-v2-server-stream\""

static void raw_info(raw_wt *r, const char *user, const char *pass) {
	uint8_t pkt[128];
	size_t n = hw_wisp_build_info(pkt, HW_WISP_MAJOR, 0);
	if (user) {
		char meta[64]; // u8 user length, user, password
		int len = snprintf(meta, sizeof(meta), "%c%s%s", (char)strlen(user), user, pass);
		CHECK(len > 0 && (size_t)len < sizeof(meta), "credentials fit");
		n += hw_wisp_build_extension(pkt + n, sizeof(pkt) - n, HW_EXT_PASSWORD, meta, (uint32_t)len);
	}
	raw_send(r, pkt, n);
}

static void raw_connect(raw_wt *r, int lane, uint32_t id, uint16_t port) {
	uint8_t pkt[64];
	size_t n = hw_wisp_build_connect(pkt, sizeof(pkt), id, HW_STREAM_TCP, port, "127.0.0.1", 9);
	CHECK_EQ(hw_wt_send_lane(r->wt, lane, pkt, n, 0), 0);
	raw_output(r);
}

static void raw_data(raw_wt *r, int lane, uint32_t id, const char *s) {
	uint8_t pkt[64];
	hw_wisp_write_header(pkt, HW_WISP_DATA, id);
	int n = snprintf((char *)pkt + HW_WISP_HEADER_LEN, sizeof(pkt) - HW_WISP_HEADER_LEN, "%s", s);
	CHECK(n > 0 && (size_t)n < sizeof(pkt) - HW_WISP_HEADER_LEN, "DATA fits");
	CHECK_EQ(hw_wt_send_lane(r->wt, lane, pkt, HW_WISP_HEADER_LEN + (size_t)n, 0), 0);
	raw_output(r);
}

static void raw_wait_packets(raw_wt *r, int want, int ms) {
	uint64_t until = hw_now_ms() + (uint64_t)ms;
	while (r->packets < want && !r->quic_closed && hw_now_ms() < until) raw_pump(r, 10, NULL);
}

// A client that offers "wisp-v2-server-stream" gets it, and the server's stream brings INFO (with
// the lanes) and CONTINUE before the client has sent anything on a stream at all: the Wisp
// handshake costs no round trip. With a password required the CONTINUE waits for the INFO that
// carries it, as before.
static void test_server_stream_opening(void) {
	for (int pass = 0; pass <= 1; pass++) {
		hw_server_config cfg;
		base_config(&cfg);
		cfg.log_level = HW_LOG_NONE;
		if (pass) {
			CHECK_EQ(hw_server_config_add_user(&cfg, "alice", "s3cret"), 0);
			cfg.password_required = 1;
		}
		hw_server *s = server_with(&cfg);
		raw_wt r;
		raw_open_with(&r, s, OFFER_SERVER_STREAM, 0);
		CHECK(hw_wt_server_stream(r.wt), "the server opened the Wisp stream");
		CHECK_STR(hw_wt_protocol(r.wt), HW_WT_SERVER_STREAM);
		raw_wait_packets(&r, 2, pass ? 500 : 3000);
		CHECK(r.types[0] == HW_WISP_INFO && r.streams[0] == 0, "INFO first (%d)", r.types[0]);
		CHECK_EQ(r.info_lanes, 8);
		if (!pass) {
			CHECK(r.packets == 2 && r.types[1] == HW_WISP_CONTINUE && r.streams[1] == 0, "and CONTINUE, unasked");
		} else {
			CHECK_EQ(r.packets, 1); // no CONTINUE before the password
		}
		raw_info(&r, pass ? "alice" : NULL, "s3cret");
		if (pass) {
			raw_wait_packets(&r, 2, 3000);
			CHECK(r.packets == 2 && r.types[1] == HW_WISP_CONTINUE && r.streams[1] == 0, "CONTINUE after the INFO");
		}
		raw_connect(&r, 0, 1, g_tcp_echo_port);
		raw_data(&r, 0, 1, "abc");
		uint64_t until = hw_now_ms() + 5000;
		while (r.data_packets == 0 && hw_now_ms() < until) raw_pump(&r, 20, &r.data_packets);
		CHECK(r.data_packets > 0, "pass %d: echo", pass);
		raw_free(&r);
		hw_server_free(s);
	}
}

// On a server-opened Wisp stream the client's first packet must be its INFO: anything else is
// answered with CLOSE 0x04 on stream 0, and the session ends. The capsule waits for the CLOSE to be
// acknowledged (Chrome drops what a stream holds unread once it has the capsule) and carries 0x04.
static void test_server_stream_info_first(void) {
	hw_server_config cfg;
	base_config(&cfg);
	cfg.log_level = HW_LOG_NONE;
	hw_server *s = server_with(&cfg);
	raw_wt r;
	raw_open_with(&r, s, OFFER_SERVER_STREAM, 0);
	raw_wait_packets(&r, 2, 3000);
	CHECK_EQ(r.packets, 2);
	raw_connect(&r, 0, 1, g_tcp_echo_port);
	raw_pump(&r, 3000, &r.session_closed);
	CHECK(r.last_type == HW_WISP_CLOSE && r.last_stream == 0 && r.last_reason == HW_CLOSE_INCOMPATIBLE,
	      "CLOSE 0x04 (type %d stream %u reason 0x%02x)", r.last_type, r.last_stream, r.last_reason);
	CHECK(r.session_closed, "the session ended");
	CHECK_EQ(r.close_code, HW_CLOSE_INCOMPATIBLE);
	CHECK(r.close_dgram > r.packet_dgram,
	      "the capsule came after the CLOSE was acknowledged (datagram %d, CLOSE in %d)", r.close_dgram,
	      r.packet_dgram);
	CHECK(raw_wait_server(&r, s, 3000, 0, 0), "the session is gone");
	CHECK_EQ(stats(s).streams_active, 0);
	raw_free(&r);
	hw_server_free(s);
}

// A lane the client opens on the early CONTINUE can reach the server before the INFO does: what is
// on it waits for the INFO and is then acted on, never dropped.
static void test_lane_before_info(void) {
	hw_server_config cfg;
	base_config(&cfg);
	cfg.log_level = HW_LOG_NONE;
	hw_server *s = server_with(&cfg);
	raw_wt r;
	raw_open_with(&r, s, OFFER_SERVER_STREAM, 0);
	raw_wait_packets(&r, 2, 3000);
	CHECK_EQ(r.packets, 2);
	CHECK_EQ(hw_wt_open_lane(r.wt, 1), 0);
	raw_connect(&r, 1, 1, g_tcp_echo_port);
	raw_data(&r, 1, 1, "early");
	raw_pump(&r, 200, NULL); // there long before the INFO
	CHECK_EQ(stats(s).streams_active, 0);
	raw_info(&r, NULL, NULL);
	uint64_t until = hw_now_ms() + 5000;
	while (r.data_packets == 0 && hw_now_ms() < until) raw_pump(&r, 20, &r.data_packets);
	CHECK(r.data_packets > 0, "the lane's CONNECT was acted on after the INFO");
	CHECK(r.lane_bytes[1] == 5 && r.lane_bytes[0] == 0, "and its DATA came back on its lane");
	raw_free(&r);
	hw_server_free(s);
}

// The client library on lanes: streams spread over them (the fewest open first), several bulk
// echoes at once, every byte back on its stream. With and without the server-opened stream, with
// the server's number below the client's, and with 16 lanes (the server leaves room for them).
static void test_lanes_echo(void) {
	for (int round = 0; round < 4; round++) {
		hw_server *s = g_server;
		int want = 8;
		if (round >= 2) {
			hw_server_config cfg;
			base_config(&cfg);
			cfg.log_level = HW_LOG_NONE;
			want = round == 2 ? 3 : HW_WT_LANES_MAX; // fewer than asked for; the most there may be
			cfg.webtransport_lanes = want;
			s = server_with(&cfg);
		}
		wt_opts w = {.v2 = 1, .server_stream = round == 1, .lanes = round == 3 ? HW_WT_LANES_MAX : 8};
		hw_client *c = wt_connect(s, &w);
		CHECK_EQ(hw_client_lanes(c), want);
		CHECK_EQ(hw_client_server_stream(c), round == 1);
		enum {
			N = 20,
			SIZE = 256 * 1024,
			CHUNK = 32 * 1024
		};
		uint32_t sid[N];
		static uint8_t data[N][SIZE], back[N][SIZE];
		size_t sent[N] = {0}, got[N] = {0};
		for (int k = 0; k < N; k++) {
			CHECK_EQ(hw_client_open(c, HW_STREAM_TCP, "127.0.0.1", g_tcp_echo_port, &sid[k]), 0);
			CHECK_EQ(hw_client_stream_lane(c, sid[k]), k % want);
			fill_pattern(data[k], SIZE, (uint32_t)(k + 100 * round));
		}
		size_t done = 0;
		uint64_t until = hw_now_ms() + 20000;
		while (done < N && hw_now_ms() < until) {
			for (int k = 0; k < N; k++) {
				if (sent[k] < SIZE) {
					CHECK_EQ(hw_client_send(c, sid[k], data[k] + sent[k], CHUNK), 0);
					sent[k] += CHUNK;
				}
			}
			hw_client_event ev;
			int r;
			while ((r = hw_client_poll(c, 0, &ev)) > 0) {
				CHECK(ev.type != HW_CEV_CLOSE, "closed 0x%02x", ev.reason);
				if (ev.type != HW_CEV_DATA) continue;
				int k = 0;
				while (k < N && sid[k] != ev.stream_id) k++;
				CHECK(k < N && got[k] + ev.len <= SIZE, "stream %u", ev.stream_id);
				memcpy(back[k] + got[k], ev.data, ev.len);
				got[k] += ev.len;
				if (got[k] == SIZE) done++;
			}
			CHECK(r >= 0, "poll %d", r);
			if (r == 0 && sent[0] >= SIZE) usleep(1000);
		}
		for (int k = 0; k < N; k++) {
			CHECK(got[k] == SIZE && memcmp(data[k], back[k], SIZE) == 0, "round %d: stream %d intact (%zu)", round, k,
			      got[k]);
		}
		hw_client_free(c);
		wait_sessions_gone(s, 5000);
		if (s != g_server) hw_server_free(s);
	}
}

// Backpressure is per lane: a lane whose client has stopped reading pauses the remotes of its own
// streams, and a stream on another lane goes on at full speed. Built as test_stalled_reader, with
// the reader stopped for one lane's QUIC stream only.
static void test_lane_backpressure(void) {
	hw_server_config cfg;
	base_config(&cfg);
	cfg.workers = 1;
	cfg.ws_write_high_water = 1024 * 1024;
	cfg.webtransport_lanes = 4;
	cfg.log_level = HW_LOG_NONE;
	hw_server *s = server_with(&cfg);
	raw_wt r;
	raw_open_with(&r, s, "\"wisp-v2\"", 1024 * 1024);
	CHECK_EQ(r.info_lanes, 4);
	raw_info(&r, NULL, NULL);
	raw_wait_packets(&r, 2, 3000);
	CHECK(r.types[1] == HW_WISP_CONTINUE, "the handshake");
	// The client's streams: 0 the CONNECT's, 4 lane 0, then 8 and 12 for lanes 1 and 2.
	CHECK_EQ(hw_wt_open_lane(r.wt, 1), 0);
	CHECK_EQ(hw_wt_open_lane(r.wt, 2), 0);
	r.stall_id = 8;
	r.stalling = 1;
	raw_connect(&r, 1, 1, g_source_port);
	raw_connect(&r, 2, 2, g_source_port);
	raw_pump(&r, 1500, NULL);
	CHECK(r.stalled > 0, "lane 1 had bytes");
	CHECK(r.lane_bytes[2] > 0, "lane 2 has bytes");
	uint64_t before = r.lane_bytes[2];
	raw_pump(&r, 1000, NULL);
	uint64_t moved = r.lane_bytes[2] - before;
	CHECK(moved >= 4ull * 1024 * 1024, "lane 2 moved %llu bytes in a second behind a stalled lane 1",
	      (unsigned long long)moved);
	CHECK(r.stalled <= 1024 * 1024, "lane 1 past its window: %llu", (unsigned long long)r.stalled);
	CHECK_EQ(stats(s).streams_active, 2);
	raw_free(&r);
	hw_server_free(s);
}

// Clients that ask for neither extension see what they saw before: v1 gets its CONTINUE first and
// no INFO; v2 with one token (epoxy's random one too) gets it echoed, opens the Wisp stream itself
// and is sent INFO first (0xE1 among its extensions, which it skips); a server with lanes off
// sends no 0xE1.
static void test_old_clients(void) {
	hw_server_config cfg;
	base_config(&cfg);
	cfg.log_level = HW_LOG_NONE;
	hw_server *o = server_with(&cfg); // the raw clients leave their sessions to the idle timeout
	raw_wt r;
	raw_open_with(&r, o, NULL, 0);
	CHECK(r.types[0] == HW_WISP_CONTINUE && r.streams[0] == 0, "v1: CONTINUE first");
	CHECK(!hw_wt_server_stream(r.wt) && hw_wt_protocol(r.wt)[0] == '\0', "v1: no protocol");
	raw_free(&r);
	raw_open_with(&r, o, "\"wisp-v2\"", 0);
	CHECK(r.types[0] == HW_WISP_INFO && r.info_lanes == 8, "v2: INFO first, with the lanes");
	CHECK(!hw_wt_server_stream(r.wt), "v2: the client's stream");
	CHECK_STR(hw_wt_protocol(r.wt), "wisp-v2");
	raw_pump(&r, 200, NULL);
	CHECK_EQ(r.packets, 1); // no CONTINUE before the client's INFO
	raw_free(&r);
	raw_open_with(&r, o, "\"6f9619ff-8b86-d011-b42d-00c04fc964ff\"", 0);
	CHECK_STR(hw_wt_protocol(r.wt), "6f9619ff-8b86-d011-b42d-00c04fc964ff");
	CHECK(r.types[0] == HW_WISP_INFO && !hw_wt_server_stream(r.wt), "a random token: v2 as before");
	raw_free(&r);
	wt_opts w = {.v2 = 1};
	hw_client *c = wt_connect(o, &w);
	CHECK(hw_client_is_v2(c) && hw_client_lanes(c) == 1 && !hw_client_server_stream(c), "the library's default");
	hw_client_free(c);
	hw_server_free(o);
	cfg.webtransport_lanes = 1;
	hw_server *s = server_with(&cfg);
	raw_open_with(&r, s, "\"wisp-v2\"", 0);
	CHECK(r.types[0] == HW_WISP_INFO && r.info_lanes == 0, "lanes off: no 0xE1");
	raw_free(&r);
	w.lanes = 8;
	w.server_stream = 1;
	c = wt_connect(s, &w);
	CHECK(hw_client_lanes(c) == 1 && hw_client_server_stream(c), "lanes asked for, none offered");
	hw_client_free(c);
	hw_server_free(s);
}

// Chrome never sends CONNECTION_CLOSE: a session it ends gets the capsule and FIN, and then
// nothing at all, not even an ACK. The server closes QUIC itself and frees everything well before
// the idle timeout.
static void test_client_close_then_silent(void) {
	hw_server_config cfg;
	base_config(&cfg);
	cfg.log_level = HW_LOG_NONE;
	hw_server *s = server_with(&cfg);
	raw_wt r;
	raw_open(&r, s, 0);
	CHECK_EQ(stats(s).wt_sessions_active, 1);
	hw_wt_close(r.wt, 7, "bye");
	raw_output(&r);
	// Silent from here on: nothing received, nothing acknowledged, nothing sent.
	uint64_t t0 = hw_now_ms();
	CHECK(raw_wait_server(NULL, s, 3000, 0, 0), "a silent closed session is still held");
	CHECK(hw_now_ms() - t0 < 3000, "took %llu ms", (unsigned long long)(hw_now_ms() - t0));
	raw_free(&r);
	hw_server_free(s);
}

// A client that ends its session and goes on answering gets a CONNECTION_CLOSE that says nothing
// went wrong, once the server's FIN on the CONNECT stream is acknowledged (Chrome logged the
// session as failed on "refused", sent with that FIN still in flight).
static void test_client_close_answered(void) {
	hw_server_config cfg;
	base_config(&cfg);
	cfg.log_level = HW_LOG_NONE;
	hw_server *s = server_with(&cfg);
	raw_wt r;
	raw_open(&r, s, 0);
	hw_wt_close(r.wt, 7, "bye");
	raw_pump(&r, 3000, &r.quic_closed);
	CHECK(r.quic_closed, "QUIC was not closed in 3 s");
	CHECK_STR(r.quic_reason, "");
	CHECK(raw_wait_server(&r, s, 3000, 0, 0), "the session is gone");
	raw_free(&r);
	hw_server_free(s);
}

// The server closes a session (here for an incompatible v2 INFO) and the client never answers the
// capsule, and keeps the connection busy so that no idle timeout comes: it is closed anyway, a few
// seconds after the capsule.
static void test_close_unanswered(void) {
	hw_server_config cfg;
	base_config(&cfg);
	cfg.enable_v2 = 1;
	cfg.log_level = HW_LOG_NONE;
	hw_server *s = server_with(&cfg);
	raw_wt r;
	raw_open(&r, s, 1);
	CHECK_EQ(r.last_type, HW_WISP_INFO);
	r.deaf = 1;
	uint8_t info[HW_WISP_HEADER_LEN + 2];
	raw_send(&r, info, hw_wisp_build_info(info, 9, 0)); // a major version the server does not speak
	uint64_t t0 = hw_now_ms();
	uint8_t junk[HW_WISP_HEADER_LEN + 8];
	hw_wisp_write_header(junk, HW_WISP_DATA, 77);
	memset(junk + HW_WISP_HEADER_LEN, 'j', 8);
	while (!r.quic_closed && hw_now_ms() - t0 < 10000) {
		hw_wt_send(r.wt, junk, sizeof(junk), 0);        // on the Wisp stream while it takes them
		hw_quic_datagram_send(r.q, junk, sizeof(junk)); // and as datagrams: never idle
		raw_pump(&r, 50, &r.quic_closed);
	}
	uint64_t took = hw_now_ms() - t0;
	CHECK(r.quic_closed, "the connection is still open after %llu ms", (unsigned long long)took);
	CHECK(!r.heard_close, "the client heard the capsule after all");
	CHECK(took >= 2000 && took < 6000, "closed after %llu ms", (unsigned long long)took);
	CHECK(raw_wait_server(&r, s, 3000, 0, 0), "the session is still held");
	raw_free(&r);
	hw_server_free(s);
}

// webtransport-reset-key-file: a server that went away without a word (a crash; here the client
// never reads the closes it sent) is followed by one on the same port with the same file, and the
// new one's stateless reset ends the old session at its client at once. Without the file the key
// is new at each start, and the client takes the reset for noise and waits for its idle timeout.
static int reset_after_restart(const char *key_file) {
	hw_server_config cfg;
	base_config(&cfg);
	cfg.workers = 1;
	cfg.log_level = HW_LOG_NONE;
	if (key_file) snprintf(cfg.webtransport_reset_key_file, sizeof(cfg.webtransport_reset_key_file), "%s", key_file);
	hw_server *s = server_with(&cfg);
	raw_wt r;
	raw_open(&r, s, 0);
	cfg.webtransport_port = hw_server_wt_port(s);
	hw_server_free(s);
	uint8_t junk[2048];
	while (recv(r.fd, junk, sizeof(junk), MSG_DONTWAIT) > 0) {
	}
	s = server_with(&cfg);
	uint8_t pkt[HW_WISP_HEADER_LEN + 64];
	hw_wisp_write_header(pkt, HW_WISP_DATA, 1);
	memset(pkt + HW_WISP_HEADER_LEN, 'x', 64);
	raw_send(&r, pkt, sizeof(pkt));
	raw_pump(&r, 1500, &r.quic_closed);
	int reset = r.quic_closed && !strcmp(r.quic_reason, "stateless reset");
	raw_free(&r);
	hw_server_free(s);
	return reset;
}

static void test_reset_key_file(void) {
	char dir[512], path[600];
	hw_test_tmp(dir, sizeof(dir), "hw-wt-reset");
	CHECK(mkdtemp(dir) != NULL, "mkdtemp: %s", strerror(errno));
	snprintf(path, sizeof(path), "%s/reset.key", dir);
	CHECK(reset_after_restart(path), "no stateless reset from the server that came after");
	struct stat st;
	CHECK_EQ(stat(path, &st), 0);
	CHECK_EQ(st.st_mode & 0777, 0600);
	CHECK_EQ(st.st_size, 65);
	char key[65], again[65];
	FILE *f = fopen(path, "r");
	CHECK(f && fread(key, 1, sizeof(key), f) == sizeof(key), "read the key");
	fclose(f);
	CHECK(!reset_after_restart(NULL), "a key drawn at each start still reset the earlier session");
	// The same file on the next start: read, not made again.
	CHECK(reset_after_restart(path), "no stateless reset with the file already there");
	f = fopen(path, "r");
	CHECK(f && fread(again, 1, sizeof(again), f) == sizeof(again), "read the key");
	fclose(f);
	CHECK(memcmp(key, again, sizeof(key)) == 0, "the key was made again");
	// A file that holds anything else is the operator's: left alone, and the server still starts.
	f = fopen(path, "w");
	CHECK(f != NULL, "rewrite");
	fputs("not a key\n", f);
	fclose(f);
	CHECK(!reset_after_restart(path), "a key out of a file that holds none");
	f = fopen(path, "r");
	CHECK(f && fread(again, 1, 10, f) == 10 && !memcmp(again, "not a key\n", 10), "the file was replaced");
	fclose(f);
	unlink(path);
	rmdir(dir);
}

// The 6-day renewal, made to happen now: a session pinned to the old certificate goes on across the
// rotation, a new one pinned to the new certificate connects (one pinned to the old one alone no
// longer does: new handshakes take the new certificate, which is why the page is given both),
// /webtransport.json lists both, and after a second rotation the oldest is gone.
static int json_wait(hw_server *s, uint8_t want0[32], const uint8_t not0[32], int want_n, uint8_t out[2][32]) {
	char json[2048];
	uint64_t until = hw_now_ms() + 5000;
	int same = 0;
	while (hw_now_ms() < until) {
		int n = json_hashes(s, out, 2, json, sizeof(json));
		if (n == want_n && memcmp(out[0], not0, 32) != 0) {
			// Each worker answers from its own copy: seen several times over, every worker has it.
			if (++same >= 6) {
				memcpy(want0, out[0], 32);
				return 1;
			}
		} else {
			same = 0;
		}
		usleep(20000);
	}
	return 0;
}

static void echo_check(hw_client *c, uint32_t sid, const char *msg) {
	size_t n = strlen(msg);
	CHECK_EQ(hw_client_send(c, sid, msg, n), 0);
	uint8_t buf[64];
	CHECK_EQ(hw_client_read_exact(c, sid, buf, n, 5000), (int)n);
	CHECK(memcmp(buf, msg, n) == 0, "echo of %s", msg);
}

// A stop closes every session toward its client before the process goes: the session's capsule,
// then QUIC's CONNECTION_CLOSE. Before, nothing was sent, and every client of a restarted server
// sat out its idle timeout (30 s on the edges) before it reconnected.
static void test_stop_closes_sessions(void) {
	hw_server_config cfg;
	base_config(&cfg);
	cfg.log_level = HW_LOG_NONE;
	hw_server *s = server_with(&cfg);
	raw_wt r;
	raw_open(&r, s, 0);
	hw_client *c = wt_connect(s, NULL);
	uint32_t sid;
	CHECK_EQ(hw_client_open(c, HW_STREAM_TCP, "127.0.0.1", g_tcp_echo_port, &sid), 0);
	echo_check(c, sid, "before the stop");
	uint64_t t0 = hw_now_ms();
	hw_server_free(s);
	CHECK(hw_now_ms() - t0 < 2000, "the stop took %llu ms", (unsigned long long)(hw_now_ms() - t0));
	t0 = hw_now_ms();
	raw_pump(&r, 3000, &r.quic_closed);
	CHECK(r.quic_closed, "no CONNECTION_CLOSE in 3 s");
	CHECK(r.heard_close, "no close capsule before it");
	CHECK_EQ(r.close_code, 0);
	CHECK_STR(r.quic_reason, "server stopping");
	hw_client_event ev;
	int got;
	while ((got = hw_client_poll(c, 3000, &ev)) > 0) {
	}
	CHECK_EQ(got, HW_ERR_CLOSED);
	CHECK(hw_now_ms() - t0 < 3000, "the clients heard of it after %llu ms", (unsigned long long)(hw_now_ms() - t0));
	hw_client_free(c);
	raw_free(&r);
}

static void test_cert_rotation(void) {
	hw_server_config cfg;
	base_config(&cfg);
	cfg.log_level = HW_LOG_NONE;
	hw_server *s = server_with(&cfg);
	char json[2048];
	uint8_t h[2][32], h0[32], h1[32], h2[32];
	CHECK_EQ(json_hashes(s, h, 2, json, sizeof(json)), 1);
	memcpy(h0, h[0], 32);
	wt_opts pin0 = {.pin = h0};
	hw_client *a = wt_connect(s, &pin0);
	uint32_t sa;
	CHECK_EQ(hw_client_open(a, HW_STREAM_TCP, "127.0.0.1", g_tcp_echo_port, &sa), 0);
	echo_check(a, sa, "before");

	hw_server_wt_renew(s);
	CHECK(json_wait(s, h1, h0, 2, h), "no new certificate listed: %s", json);
	CHECK(memcmp(h[1], h0, 32) == 0, "the previous hash is listed second");
	echo_check(a, sa, "across the rotation");
	uint32_t sa2;
	CHECK_EQ(hw_client_open(a, HW_STREAM_TCP, "127.0.0.1", g_tcp_echo_port, &sa2), 0);
	echo_check(a, sa2, "a new stream");

	wt_opts pin1 = {.pin = h1};
	hw_client *b = wt_connect(s, &pin1);
	uint32_t sb;
	CHECK_EQ(hw_client_open(b, HW_STREAM_TCP, "127.0.0.1", g_tcp_echo_port, &sb), 0);
	echo_check(b, sb, "pinned to the new one");
	char err[256];
	CHECK(wt_try(s, &pin0, err, sizeof(err)) == NULL, "a new handshake still offers the old certificate");

	hw_server_wt_renew(s);
	CHECK(json_wait(s, h2, h1, 2, h), "no second rotation");
	CHECK(memcmp(h[1], h1, 32) == 0, "the previous hash is listed second");
	CHECK(memcmp(h2, h0, 32) != 0 && memcmp(h[1], h0, 32) != 0, "the oldest hash is gone");
	echo_check(a, sa, "after two rotations");
	echo_check(b, sb, "after two rotations");
	hw_client_free(a);
	hw_client_free(b);
	hw_server_free(s);
}

// A new P-256 key and a certificate for it, as PEM files at fresh temporary paths.
static void operator_pair(char cert_path[512], char key_path[512], uint8_t hash[32]) {
	uint8_t priv[HW_P256_PRIV_LEN], pub[HW_P256_PUB_LEN];
	CHECK_EQ(hw_p256_keygen(priv, pub), 0);
	hw_der cert = {0};
	int64_t now = (int64_t)time(NULL);
	CHECK_EQ(hw_cert_selfsigned(priv, pub, "wt.example", now - 3600, now + 7 * 86400, &cert), 0);
	hw_sha256(cert.der, cert.len, hash);
	uint8_t key[128];
	size_t key_len = sec1_key(priv, pub, key);
	write_pem(cert_path, 512, "CERTIFICATE", cert.der, cert.len);
	write_pem(key_path, 512, "EC PRIVATE KEY", key, key_len);
	hw_der_free(&cert);
}

// Puts from in place of to, in one step, as certbot's symlink swap or an atomic writer does.
static void file_replace(const char *from, const char *to) {
	CHECK(rename(from, to) == 0, "rename %s: %s", from, strerror(errno));
}

// Until the wall clock's second turns. The server tells files apart by stat's inode, size and
// mtime in seconds, and Windows has no inode: a key of the same size written in the second the
// last one was would look like the same file there. A real renewal comes weeks after the last.
static void second_turn(void) {
	time_t t = time(NULL);
	while (time(NULL) == t) usleep(20000);
}

// Whether a new session pinned to hash connects, and then whether every worker serves it: the
// workers get their copies by posted tasks, and each new client may land on another one.
static int pin_served(hw_server *s, const uint8_t hash[32]) {
	wt_opts w = {.pin = hash};
	char err[256];
	for (int i = 0; i < 8; i++) {
		hw_client *c = wt_try(s, &w, err, sizeof(err));
		if (!c) return 0;
		hw_client_free(c);
	}
	return 1;
}

static int pin_refused(hw_server *s, const uint8_t hash[32]) {
	wt_opts w = {.pin = hash};
	char err[256];
	for (int i = 0; i < 8; i++) {
		hw_client *c = wt_try(s, &w, err, sizeof(err));
		if (c) {
			hw_client_free(c);
			return 0;
		}
	}
	return 1;
}

// Until a new session pinned to hash connects, at most timeout_ms.
static int pin_wait(hw_server *s, const uint8_t hash[32], int timeout_ms) {
	wt_opts w = {.pin = hash};
	char err[256];
	uint64_t until = hw_now_ms() + (uint64_t)timeout_ms;
	while (hw_now_ms() < until) {
		hw_client *c = wt_try(s, &w, err, sizeof(err));
		if (c) {
			hw_client_free(c);
			usleep(100000); // the other workers' posted copies
			return 1;
		}
		usleep(100000);
	}
	return 0;
}

// The operator's files renewed in place (certbot, lego): the server reads them again within a
// couple of seconds, new sessions get the new certificate and a session from before goes on with
// the old one. A file that does not load, and a certificate whose key has not arrived yet, change
// nothing; the pair is tried again when the files change again.
static void test_operator_reload(void) {
	char cert_path[512], key_path[512], cert_new[512], key_new[512];
	uint8_t ha[32], hb[32], hc[32];
	operator_pair(cert_path, key_path, ha);
	hw_server_config cfg;
	base_config(&cfg);
	cfg.log_level = HW_LOG_NONE;
	snprintf(cfg.webtransport_cert, sizeof(cfg.webtransport_cert), "%s", cert_path);
	snprintf(cfg.webtransport_key, sizeof(cfg.webtransport_key), "%s", key_path);
	hw_server *s = server_with(&cfg);
	wt_opts pin_a = {.pin = ha};
	hw_client *a = wt_connect(s, &pin_a);
	uint32_t sa;
	CHECK_EQ(hw_client_open(a, HW_STREAM_TCP, "127.0.0.1", g_tcp_echo_port, &sa), 0);
	echo_check(a, sa, "before");

	second_turn();
	operator_pair(cert_new, key_new, hb);
	file_replace(cert_new, cert_path);
	file_replace(key_new, key_path);
	CHECK(pin_wait(s, hb, 5000), "the renewed certificate is not served");
	CHECK(pin_served(s, hb), "a worker still serves the old certificate");
	CHECK(pin_refused(s, ha), "a new session still gets the old certificate");
	echo_check(a, sa, "across the reload");
	uint32_t sa2;
	CHECK_EQ(hw_client_open(a, HW_STREAM_TCP, "127.0.0.1", g_tcp_echo_port, &sa2), 0);
	echo_check(a, sa2, "a new stream after the reload");
	char json[2048];
	uint8_t hashes[2][32];
	CHECK_EQ(json_hashes(s, hashes, 2, json, sizeof(json)), 0);

	// Not a certificate at all: B stays.
	char junk[512];
	second_turn();
	hw_test_tmp(junk, sizeof(junk), "hw-wt-junk");
	int fd = mkstemp(junk);
	CHECK(fd >= 0, "mkstemp: %s", strerror(errno));
	CHECK_EQ(write(fd, "-----BEGIN CERTIFICATE-----\nnot base64\n", 39), 39);
	close(fd);
	file_replace(junk, cert_path);
	usleep(3000000); // two looks: the change, then the read
	CHECK(pin_served(s, hb), "a file that is not a certificate replaced the one served");

	// The renewer's first half: C's certificate beside B's key. Still B, until C's key is there.
	operator_pair(cert_new, key_new, hc);
	file_replace(cert_new, cert_path);
	usleep(3000000);
	CHECK(pin_served(s, hb), "a certificate without its key replaced the one served");
	file_replace(key_new, key_path);
	CHECK(pin_wait(s, hc, 5000), "the pair was not tried again once the key arrived");
	CHECK(pin_served(s, hc), "a worker still serves B");
	CHECK(pin_refused(s, hb), "a new session still gets B");
	echo_check(a, sa, "after the second reload");
	hw_client_free(a);
	hw_server_free(s);
	unlink(cert_path);
	unlink(key_path);
}

// A host's certificate and key in one file, dir/name.pem, put in place by rename as the edge's
// exporter does.
static void host_pem(const char *dir, const char *name, uint8_t hash[32]) {
	uint8_t priv[HW_P256_PRIV_LEN], pub[HW_P256_PUB_LEN];
	CHECK_EQ(hw_p256_keygen(priv, pub), 0);
	hw_der cert = {0};
	int64_t now = (int64_t)time(NULL);
	CHECK_EQ(hw_cert_selfsigned(priv, pub, name, now - 3600, now + 7 * 86400, &cert), 0);
	hw_sha256(cert.der, cert.len, hash);
	uint8_t key[128];
	size_t key_len = sec1_key(priv, pub, key);
	char cpath[512], kpath[512], tmp[600], dst[600];
	write_pem(cpath, sizeof(cpath), "CERTIFICATE", cert.der, cert.len);
	write_pem(kpath, sizeof(kpath), "EC PRIVATE KEY", key, key_len);
	snprintf(tmp, sizeof(tmp), "%s/.%s.tmp", dir, name);
	snprintf(dst, sizeof(dst), "%s/%s.pem", dir, name);
	FILE *out = fopen(tmp, "w");
	CHECK(out != NULL, "fopen %s", tmp);
	const char *parts[2] = {cpath, kpath};
	for (int i = 0; i < 2; i++) {
		FILE *in = fopen(parts[i], "r");
		CHECK(in != NULL, "fopen %s", parts[i]);
		static char buf[8192];
		size_t n = fread(buf, 1, sizeof(buf), in);
		CHECK(n > 0 && n < sizeof(buf), "read %s", parts[i]);
		CHECK_EQ(fwrite(buf, 1, n, out), n);
		fclose(in);
		unlink(parts[i]);
	}
	fclose(out);
	file_replace(tmp, dst);
	hw_der_free(&cert);
}

// Whether a session as name for path, pinned to hash, opens; err says why not.
static int named_ok(hw_server *s, const char *name, const char *path, const uint8_t *hash, char *err, size_t cap) {
	wt_opts w = {.pin = hash, .name = name, .path = path};
	hw_client *c = wt_try(s, &w, err, cap);
	if (!c) return 0;
	hw_client_free(c);
	return 1;
}

static int named_wait(hw_server *s, const char *name, const uint8_t *hash, int timeout_ms) {
	char err[256];
	uint64_t until = hw_now_ms() + (uint64_t)timeout_ms;
	while (hw_now_ms() < until) {
		if (named_ok(s, name, "/pipe/k", hash, err, sizeof(err))) {
			usleep(100000); // the other workers' posted tables
			for (int i = 0; i < 8; i++) {
				if (!named_ok(s, name, "/pipe/k", hash, err, sizeof(err))) return 0;
			}
			return 1;
		}
		usleep(100000);
	}
	return 0;
}

// webtransport-cert-dir and webtransport-path: the certificate for the SNI a client sends, the
// operator's for any other name; sessions only on the paths the rules name; the directory read
// again as files come, change and go.
static void test_host_certificates(void) {
	char dir[512], cert_path[512], key_path[512], err[256];
	uint8_t hd[32], ha[32], ha2[32], hb[32];
	hw_test_tmp(dir, sizeof(dir), "hw-wt-hosts");
	CHECK(mkdtemp(dir) != NULL, "mkdtemp: %s", strerror(errno));
	operator_pair(cert_path, key_path, hd);
	host_pem(dir, "a.example", ha);
	// Not a certificate; names the directory never looks at.
	char junk[600];
	snprintf(junk, sizeof(junk), "%s/bad.example.pem", dir);
	FILE *f = fopen(junk, "w");
	CHECK(f != NULL, "fopen");
	fputs("-----BEGIN CERTIFICATE-----\nnot base64\n-----END CERTIFICATE-----\n", f);
	fclose(f);

	hw_server_config cfg;
	base_config(&cfg);
	cfg.log_level = HW_LOG_NONE;
	snprintf(cfg.webtransport_cert, sizeof(cfg.webtransport_cert), "%s", cert_path);
	snprintf(cfg.webtransport_key, sizeof(cfg.webtransport_key), "%s", key_path);
	snprintf(cfg.webtransport_cert_dir, sizeof(cfg.webtransport_cert_dir), "%s", dir);
	strcpy(cfg.webtransport_paths[0].path, "/pipe/k");
	strcpy(cfg.webtransport_paths[1].host, "relay.example");
	strcpy(cfg.webtransport_paths[1].path, "/");
	cfg.webtransport_path_count = 2;
	hw_server *s = server_with(&cfg);

	// The name's own certificate, whatever its case; the operator's for every other name.
	CHECK(named_ok(s, "a.example", "/pipe/k", ha, err, sizeof(err)), "a.example: %s", err);
	CHECK(named_ok(s, "A.Example", "/pipe/k", ha, err, sizeof(err)), "A.Example: %s", err);
	CHECK(!named_ok(s, "a.example", "/pipe/k", hd, err, sizeof(err)), "a.example got the default");
	CHECK(named_ok(s, "other.example", "/pipe/k", hd, err, sizeof(err)), "other.example: %s", err);
	CHECK(!named_ok(s, "other.example", "/pipe/k", ha, err, sizeof(err)), "a's certificate for another name");
	CHECK(named_ok(s, NULL, "/pipe/k", hd, err, sizeof(err)), "no SNI: %s", err);
	CHECK(named_ok(s, "bad.example", "/pipe/k", hd, err, sizeof(err)), "a file that does not load: %s", err);

	// The paths: under /pipe/k on any host, / on relay.example alone.
	CHECK(named_ok(s, "a.example", "/pipe/k/x", ha, err, sizeof(err)), "under the path: %s", err);
	CHECK(!named_ok(s, "a.example", "/pipe/kx", ha, err, sizeof(err)), "beside the path");
	CHECK(strstr(err, "404") != NULL, "a path no rule names is a 404: %s", err);
	CHECK(!named_ok(s, "a.example", "/", ha, err, sizeof(err)), "/ on a.example");
	CHECK(named_ok(s, "relay.example", "/", hd, err, sizeof(err)), "/ on relay.example: %s", err);
	CHECK(!named_ok(s, "relay.example", "/x", hd, err, sizeof(err)), "/ names / alone");

	// A new host, a renewed one, one that goes.
	second_turn();
	host_pem(dir, "b.example", hb);
	CHECK(named_wait(s, "b.example", hb, 6000), "b.example's new certificate is not served");
	host_pem(dir, "a.example", ha2);
	CHECK(named_wait(s, "a.example", ha2, 6000), "a.example's renewed certificate is not served");
	CHECK(!named_ok(s, "a.example", "/pipe/k", ha, err, sizeof(err)), "a.example's old certificate");
	char b_path[600];
	snprintf(b_path, sizeof(b_path), "%s/b.example.pem", dir);
	CHECK_EQ(unlink(b_path), 0);
	CHECK(named_wait(s, "b.example", hd, 6000), "b.example kept its certificate after its file went");
	CHECK(named_ok(s, "a.example", "/pipe/k", ha2, err, sizeof(err)), "a.example: %s", err);
	hw_server_free(s);

	// A directory that cannot be read keeps the server from starting, as a certificate would.
	snprintf(cfg.webtransport_cert_dir, sizeof(cfg.webtransport_cert_dir), "%.400s/missing", dir);
	hw_server *none = hw_server_new(&cfg);
	CHECK(none == NULL, "started without its certificate directory");
	hw_server_free(none);

	char a_path[600];
	snprintf(a_path, sizeof(a_path), "%s/a.example.pem", dir);
	unlink(a_path);
	unlink(junk);
	rmdir(dir);
	unlink(cert_path);
	unlink(key_path);
}

static void test_stats_json(void) {
	char buf[8192];
	http_get(g_server, "/stats", buf, sizeof(buf));
	CHECK(strstr(buf, "\"webTransport\":{\"sessions\":{\"total\":") != NULL, "stats: %s", buf);
	const char *body = strstr(buf, "\r\n\r\n");
	CHECK(body && hw_test_json_valid(body + 4), "not JSON: %s", buf);
	CHECK(strstr(body, "\"quic\":{\"sessionsEnded\":") != NULL, "quic: %s", body);
	hw_server_stats st = stats(g_server);
	CHECK(st.wt_sessions_total >= 4, "sessions total %llu", (unsigned long long)st.wt_sessions_total);
	// A gauge: every handshake has ended, in a session or not.
	CHECK_EQ(st.wt_handshakes, 0);
	CHECK_EQ(st.wt_sessions_active, 0);
	// Every session has ended, so each one's QUIC counters are in the sums: packets both ways,
	// some bytes, an RTT for each.
	CHECK(st.wt_quic_sessions >= 4 && st.wt_quic_sessions <= st.wt_sessions_total, "quic sessions %llu of %llu",
	      (unsigned long long)st.wt_quic_sessions, (unsigned long long)st.wt_sessions_total);
	CHECK(st.wt_quic_packets_sent > st.wt_quic_sessions && st.wt_quic_packets_received > st.wt_quic_sessions,
	      "packets %llu sent, %llu received", (unsigned long long)st.wt_quic_packets_sent,
	      (unsigned long long)st.wt_quic_packets_received);
	CHECK(st.wt_quic_bytes_sent > 0 && st.wt_quic_bytes_received > 0, "bytes");
	CHECK(st.wt_quic_srtt_us > 0, "srtt");
	CHECK(st.wt_quic_packets_lost <= st.wt_quic_packets_sent, "lost %llu", (unsigned long long)st.wt_quic_packets_lost);
	// None of them is a WebSocket.
	CHECK_EQ(st.ws_connections_total, 0);
}

// A CREDIT is taken from the session's streams only: one in a datagram, which could be lost or
// overtake the stream, is dropped and counted, and the stream stays held until one comes on its
// lane. Stream credit as an INFO with 0xE2 names it, and as the small source's end shows it.
static void test_credit_not_by_datagram(void) {
	hw_server_config cfg;
	base_config(&cfg);
	cfg.log_level = HW_LOG_NONE;
	hw_server *s = server_with(&cfg);
	raw_wt r;
	raw_open(&r, s, 1);
	uint8_t pkt[64];
	uint8_t window[4];
	hw_put_le32(window, HW_WISP_CREDIT_MIN);
	size_t n = hw_wisp_build_info(pkt, HW_WISP_MAJOR, 0);
	n += hw_wisp_build_extension(pkt + n, sizeof(pkt) - n, HW_EXT_CREDIT, window, sizeof(window));
	raw_send(&r, pkt, n);
	raw_wait_packets(&r, 2, 3000);
	CHECK(r.types[1] == HW_WISP_CONTINUE, "the handshake");
	raw_connect(&r, 0, 1, g_credit_small_port);
	uint64_t until = hw_now_ms() + 3000;
	while (r.lane_bytes[0] < HW_WISP_CREDIT_MIN && hw_now_ms() < until) raw_pump(&r, 20, NULL);
	raw_pump(&r, 300, NULL);
	CHECK_EQ(r.lane_bytes[0], HW_WISP_CREDIT_MIN);

	uint64_t dropped = stats(s).wt_dropped;
	n = hw_wisp_build_credit(pkt, 1, CREDIT_SMALL + 1);
	CHECK_EQ(hw_wt_send(r.wt, pkt, n, 1), 0); // a datagram
	raw_output(&r);
	raw_pump(&r, 300, NULL);
	CHECK_EQ(r.lane_bytes[0], HW_WISP_CREDIT_MIN);
	CHECK_EQ(stats(s).wt_dropped, dropped + 1);
	CHECK(r.last_type == HW_WISP_DATA, "no CLOSE: %u", r.last_type);

	raw_send(&r, pkt, n); // the same on the Wisp stream
	until = hw_now_ms() + 3000;
	while (r.last_type != HW_WISP_CLOSE && hw_now_ms() < until) raw_pump(&r, 20, NULL);
	CHECK_EQ(r.lane_bytes[0], CREDIT_SMALL);
	CHECK(r.last_type == HW_WISP_CLOSE && r.last_stream == 1 && r.last_reason == HW_CLOSE_VOLUNTARY, "the end");
	raw_free(&r);
	hw_server_free(s);
}

// credit_cases.h's way to connect: WebTransport, and a v2 session with two lanes, so that a held
// stream and a busy one can share one while another lane is open beside them.
static hw_client *credit_connect(hw_server *s, int v2, uint32_t window, int manual, size_t max_queue) {
	hw_client_opts o;
	hw_client_opts_defaults(&o);
	o.host = "127.0.0.1";
	o.port = hw_server_wt_port(s);
	o.webtransport = 1;
	o.v2 = v2;
	o.wt_lanes = v2 ? 2 : 0;
	o.credit_window = window;
	o.credit_manual = manual;
	if (max_queue) o.max_queue_bytes = max_queue;
	o.timeout_ms = 5000;
	char err[256];
	hw_client *c = hw_client_connect(&o, err, sizeof(err));
	CHECK(c != NULL, "connect: %s", err);
	return c;
}

int main(void) {
	start_services();
	hw_server_config cfg;
	base_config(&cfg);
	strcpy(cfg.motd, "welcome to the webtransport test server");
	strcpy(cfg.webtransport_url, "https://wt.example:4433/");
	g_server = server_with(&cfg);

	RUN(test_v1_tcp_echo);
	RUN(test_v2_handshake);
	RUN(test_udp_datagram_echo);
	RUN(test_egress_blocked);
	RUN(test_admission);
	RUN(test_certificate_json);
	RUN(test_operator_certificate);
	RUN(test_host_certificates);
	RUN(test_retry);
	RUN(test_idle_timeout);
	RUN(test_stalled_reader);
	RUN(test_wisp_stream_end);
	RUN(test_client_close_then_silent);
	RUN(test_close_unanswered);
	RUN(test_stop_closes_sessions);
	RUN(test_reset_key_file);
	RUN(test_cert_rotation);
	RUN(test_operator_reload);
	RUN(test_server_stream_opening);
	RUN(test_server_stream_info_first);
	RUN(test_client_close_answered);
	RUN(test_lane_before_info);
	RUN(test_lanes_echo);
	RUN(test_lane_backpressure);
	RUN(test_old_clients);
	RUN(test_stats_json);

	base_config(&cfg);
	cfg.stream_credit = 0;
	hw_server *off = server_with(&cfg);
	credit_env credit = {.server = g_server,
	                     .server_off = off,
	                     .echo_port = g_tcp_echo_port,
	                     .udp_echo_port = g_udp_echo_port,
	                     .open_client = credit_connect,
	                     .lanes = 1};
	credit_cases_run(&credit);
	RUN(test_credit_not_by_datagram); // after credit_cases_run, which starts its source
	hw_server_free(off);

	hw_server_stop(g_server);
	hw_server_free(g_server);
	printf("ok shutdown\n");
	return 0;
}
