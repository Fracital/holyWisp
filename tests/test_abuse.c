/*
 * End to end for what a hostile or broken client can do to the server and to its other clients:
 * a client that sends and never reads, a remote that goes away while its stream is paused, one
 * address taking every connection or every connect in progress, pages of other origins, bytes in
 * a hostname that are not a hostname's, a download past the bandwidth limit, a duplicate CONNECT.
 * A real server on loopback, driven by the client library and, where the library is too well
 * behaved, by a raw socket.
 */
#include "holywisp/client.h"
#include "holywisp/hw.h"
#include "holywisp/log.h"
#include "holywisp/net.h"
#include "holywisp/reputation.h"
#include "holywisp/server.h"
#include "holywisp/sys.h"
#include "holywisp/wisp.h"
#include "holywisp/ws.h"

#include "test.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <netinet/in.h>
#include <sys/socket.h>

static uint16_t g_echo_port;
static uint16_t g_blast_port;
static uint16_t g_reset_port;

// ---------------------------------------------------------------------------------- services

static void set_blocking(int fd) {
	int fl = fcntl(fd, F_GETFL, 0);
	fcntl(fd, F_SETFL, fl & ~O_NONBLOCK);
}

static void sleep_ms(int ms) {
	struct timespec ts = {.tv_sec = ms / 1000, .tv_nsec = (long)(ms % 1000) * 1000000L};
	nanosleep(&ts, NULL);
}

static void *echo_conn(void *arg) {
	int fd = (int)(intptr_t)arg;
	uint8_t buf[16384];
	for (;;) {
		ssize_t n = read(fd, buf, sizeof(buf));
		if (n <= 0) break;
		ssize_t off = 0;
		while (off < n) {
			ssize_t w = write(fd, buf + off, (size_t)(n - off));
			if (w <= 0) break;
			off += w;
		}
		if (off < n) break;
	}
	close(fd);
	return NULL;
}

// Sends for as long as anyone takes it.
static void *blast_conn(void *arg) {
	int fd = (int)(intptr_t)arg;
	static const uint8_t chunk[65536];
	for (;;) {
		if (send(fd, chunk, sizeof(chunk), HW_MSG_NOSIGNAL) <= 0) break;
	}
	close(fd);
	return NULL;
}

// Sends a little, waits, and resets the connection: what a remote that crashed looks like.
#define RESET_BYTES (256 * 1024)
static void *reset_conn(void *arg) {
	int fd = (int)(intptr_t)arg;
	static const uint8_t chunk[RESET_BYTES];
	ssize_t r = send(fd, chunk, sizeof(chunk), HW_MSG_NOSIGNAL);
	(void)r;
	sleep_ms(300);
	struct linger lg = {.l_onoff = 1, .l_linger = 0};
	setsockopt(fd, SOL_SOCKET, SO_LINGER, &lg, sizeof(lg));
	close(fd);
	return NULL;
}

typedef struct service {
	int lfd;
	void *(*conn)(void *);
} service;

static void *service_main(void *arg) {
	service *svc = arg;
	for (;;) {
		int fd = accept(svc->lfd, NULL, NULL);
		if (fd < 0) continue;
		set_blocking(fd);
		pthread_t th;
		pthread_attr_t attr;
		pthread_attr_init(&attr);
		pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
		pthread_create(&th, &attr, svc->conn, (void *)(intptr_t)fd);
		pthread_attr_destroy(&attr);
	}
	return NULL;
}

static uint16_t start_service(void *(*conn)(void *)) {
	static service services[8];
	static int n;
	uint16_t port = 0;
	service *svc = &services[n++];
	svc->lfd = hw_listen_tcp("127.0.0.1", 0, 0, 64, &port);
	CHECK(svc->lfd >= 0, "listen");
	set_blocking(svc->lfd); // the accept loop waits in accept(2), it does not poll
	svc->conn = conn;
	pthread_t th;
	pthread_create(&th, NULL, service_main, svc);
	pthread_detach(th);
	return port;
}

// ---------------------------------------------------------------------------------- helpers

static void base_config(hw_server_config *cfg) {
	hw_server_config_defaults(cfg);
	snprintf(cfg->host, sizeof(cfg->host), "127.0.0.1");
	cfg->port = 0;
	cfg->workers = 1;
	cfg->allow_direct_ip = 1;
	cfg->allow_loopback = 1;
	cfg->reputation_enabled = 0;
	cfg->flood.enabled = 0;
	cfg->log_level = HW_LOG_ERROR;
}

static hw_server *start(const hw_server_config *cfg) {
	hw_server *s = hw_server_new(cfg);
	CHECK(s != NULL, "server");
	CHECK_EQ(hw_server_start(s), 0);
	return s;
}

static hw_client *connect_plain(hw_server *s) {
	hw_client_opts o;
	hw_client_opts_defaults(&o);
	o.host = "127.0.0.1";
	o.port = hw_server_port(s);
	o.timeout_ms = 5000;
	char err[256];
	hw_client *c = hw_client_connect(&o, err, sizeof(err));
	CHECK(c != NULL, "connect: %s", err);
	return c;
}

// The CLOSE for a stream, skipping what else arrives. 1 with the reason, 0 when none came.
static int wait_close(hw_client *c, uint32_t sid, uint8_t *reason, size_t *data_bytes) {
	hw_client_event ev;
	for (;;) {
		int r = hw_client_poll(c, 5000, &ev);
		if (r <= 0) return 0;
		if (ev.stream_id != sid) continue;
		if (ev.type == HW_CEV_DATA && data_bytes) *data_bytes += ev.len;
		if (ev.type == HW_CEV_CLOSE) {
			*reason = ev.reason;
			return 1;
		}
	}
}

// A WebSocket upgrade over a raw socket, with `extra` header lines (each ending in CRLF) added.
// The response head lands in `head`; the socket is returned whatever the status was.
static int raw_upgrade(hw_server *s, const char *extra, char *head, size_t cap) {
	int fd = hw_connect_tcp("127.0.0.1", hw_server_port(s), 2000);
	CHECK(fd >= 0, "connect");
	char req[1024];
	int n = snprintf(req, sizeof(req),
	                 "GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
	                 "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n%s\r\n",
	                 extra);
	CHECK_EQ(send(fd, req, (size_t)n, HW_MSG_NOSIGNAL), (ssize_t)n);
	size_t got = 0;
	while (got + 1 < cap) {
		struct pollfd pfd = {.fd = fd, .events = POLLIN};
		if (poll(&pfd, 1, 5000) <= 0) break;
		ssize_t r = recv(fd, head + got, 1, 0);
		if (r <= 0) break;
		got += (size_t)r;
		if (got >= 4 && memcmp(head + got - 4, "\r\n\r\n", 4) == 0) break;
	}
	head[got] = '\0';
	return fd;
}

// One masked frame from the client side.
static size_t client_frame(uint8_t *out, uint8_t opcode, const uint8_t *payload, size_t len) {
	static const uint8_t mask[4] = {0x11, 0x22, 0x33, 0x44};
	size_t h = hw_ws_write_header(out, 1, opcode, len, mask);
	memcpy(out + h, payload, len);
	hw_ws_mask(out + h, len, mask, 0);
	return h + len;
}

static void raw_send_packet(int fd, const uint8_t *packet, size_t len) {
	uint8_t frame[HW_WS_MAX_HEADER + 512];
	CHECK(len <= 512, "packet fits");
	size_t n = client_frame(frame, HW_WS_BINARY, packet, len);
	CHECK_EQ(send(fd, frame, n, HW_MSG_NOSIGNAL), (ssize_t)n);
}

static int read_all(int fd, uint8_t *buf, size_t n, int timeout_ms) {
	size_t got = 0;
	while (got < n) {
		struct pollfd pfd = {.fd = fd, .events = POLLIN};
		if (poll(&pfd, 1, timeout_ms) <= 0) return -1;
		ssize_t r = recv(fd, buf + got, n - got, 0);
		if (r <= 0) return -1;
		got += (size_t)r;
	}
	return 0;
}

// The next Wisp packet the server sends (binary frames under 64 KiB; anything else is skipped).
// The payload length, or -1 when the socket closed or nothing came.
static int raw_read_packet(int fd, uint8_t *out, size_t cap, int timeout_ms) {
	for (;;) {
		uint8_t h[2];
		if (read_all(fd, h, 2, timeout_ms) != 0) return -1;
		size_t len = h[1] & 0x7f;
		if (len == 126) {
			uint8_t ext[2];
			if (read_all(fd, ext, 2, timeout_ms) != 0) return -1;
			len = (size_t)ext[0] << 8 | ext[1];
		} else if (len == 127) {
			return -1;
		}
		if (len > cap) return -1;
		if (read_all(fd, out, len, timeout_ms) != 0) return -1;
		if ((h[0] & 0x0f) == HW_WS_BINARY) return (int)len;
	}
}

static uint64_t active_connections(hw_server *s) {
	hw_server_stats st;
	hw_server_stats_get(s, &st);
	return st.connections_active;
}

// ---------------------------------------------------------------------------------- cases

// A client that sends and never reads. Every ping is owed a pong, so before there was a ceiling
// the server kept a copy of everything such a client sent, for as long as it sent. Now it stops
// listening to the client once the queue for it is twice the high-water mark, and after
// client-write-timeout-s without the client taking a byte, closes it.
static void test_client_that_never_reads(void) {
	hw_server_config cfg;
	base_config(&cfg);
	cfg.ws_write_high_water = 64 * 1024;
	cfg.socket_buffer_size = 64 * 1024;
	cfg.client_write_timeout_s = 1;
	hw_server *s = start(&cfg);
	char head[512];
	int fd = raw_upgrade(s, "", head, sizeof(head));
	CHECK(strncmp(head, "HTTP/1.1 101", 12) == 0, "status: %.20s", head);
	hw_set_nonblock(fd);

	static uint8_t pings[64 * 1024];
	size_t filled = 0;
	uint8_t payload[125];
	memset(payload, 'p', sizeof(payload));
	while (filled + HW_WS_MAX_HEADER + sizeof(payload) <= sizeof(pings)) {
		filled += client_frame(pings + filled, HW_WS_PING, payload, sizeof(payload));
	}
	const size_t limit = 64u * 1024 * 1024;
	size_t sent = 0, off = 0;
	uint64_t last_progress = hw_now_ms();
	while (sent < limit && hw_now_ms() - last_progress < 700) {
		ssize_t n = send(fd, pings + off, filled - off, HW_MSG_NOSIGNAL);
		if (n > 0) {
			sent += (size_t)n;
			off = (off + (size_t)n) % filled;
			last_progress = hw_now_ms();
			continue;
		}
		if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) break;
		sleep_ms(10);
	}
	CHECK(sent < limit, "the server took %zu bytes from a client that reads nothing", sent);
	CHECK_EQ(active_connections(s), 1);

	// Nothing is read here, so nothing leaves the server's queue: the sweep closes the client.
	uint64_t deadline = hw_now_ms() + 8000;
	while (active_connections(s) != 0 && hw_now_ms() < deadline) sleep_ms(50);
	CHECK_EQ(active_connections(s), 0);
	close(fd);

	// A client that does read is not touched by any of this.
	hw_client *c = connect_plain(s);
	uint32_t sid;
	CHECK_EQ(hw_client_open(c, HW_STREAM_TCP, "127.0.0.1", g_echo_port, &sid), 0);
	CHECK_EQ(hw_client_send(c, sid, "hello", 5), 0);
	uint8_t buf[8];
	CHECK_EQ(hw_client_read_exact(c, sid, buf, 5, 5000), 5);
	sleep_ms(2500); // idle, but with an empty queue: longer than the timeout and still there
	CHECK_EQ(hw_client_send(c, sid, "again", 5), 0);
	CHECK_EQ(hw_client_read_exact(c, sid, buf, 5, 5000), 5);
	hw_client_free(c);
	hw_server_free(s);
}

// Process CPU time in milliseconds, or -1 where clock() does not measure that (it is wall time on
// Windows): a sleep that costs CPU time means the clock cannot be used for this.
static long cpu_ms(void) {
	return (long)(clock() * 1000 / CLOCKS_PER_SEC);
}

static int cpu_clock_works(void) {
	long before = cpu_ms();
	sleep_ms(120);
	return cpu_ms() - before < 60;
}

// The remote resets its connection while the stream may not read (the client is not taking what
// is queued). The event loop reports a dead socket for as long as it is watched, and nothing the
// paused stream did made it stop: a worker spun at full speed until the client came back, and one
// client could do that to every worker. The stream now leaves the loop until it may read again.
static void test_remote_resets_while_paused(void) {
	hw_server_config cfg;
	base_config(&cfg);
	cfg.ws_write_high_water = 4096;
	cfg.socket_buffer_size = 8192;
	hw_server *s = start(&cfg);
	hw_client *c = connect_plain(s);
	int small = 4096;
	setsockopt(hw_client_fd(c), SOL_SOCKET, SO_RCVBUF, &small, sizeof(small));
	uint32_t sid;
	CHECK_EQ(hw_client_open(c, HW_STREAM_TCP, "127.0.0.1", g_reset_port, &sid), 0);

	// Not reading: the server's queue for this client passes the mark, the stream pauses, and
	// 300 ms in the remote resets.
	int measure = cpu_clock_works();
	sleep_ms(500);
	long before = cpu_ms();
	sleep_ms(600);
	long spent = cpu_ms() - before;
	if (measure) CHECK(spent < 300, "the server used %ld ms of CPU in 600 ms of waiting", spent);

	// Reading again: the stream comes back, finds its remote gone, and says so.
	uint8_t reason = 0;
	size_t got = 0;
	CHECK(wait_close(c, sid, &reason, &got), "the stream was closed once the client read again");
	CHECK(got <= RESET_BYTES, "%zu bytes", got);
	// And the connection is as good as before.
	uint32_t sid2;
	CHECK_EQ(hw_client_open(c, HW_STREAM_TCP, "127.0.0.1", g_echo_port, &sid2), 0);
	CHECK_EQ(hw_client_send(c, sid2, "hello", 5), 0);
	uint8_t buf[8];
	CHECK_EQ(hw_client_read_exact(c, sid2, buf, 5, 5000), 5);
	hw_client_free(c);
	hw_server_free(s);
}

// allow-origin: a browser says which page opened the socket. Pages that are not listed are
// refused; a client that sends no Origin is not a browser and is let through.
static void test_origin_allowlist(void) {
	hw_server_config cfg;
	base_config(&cfg);
	snprintf(cfg.allow_origins[0], sizeof(cfg.allow_origins[0]), "https://app.example");
	snprintf(cfg.allow_origins[1], sizeof(cfg.allow_origins[1]), "http://localhost:8080");
	cfg.allow_origin_count = 2;
	hw_server *s = start(&cfg);
	char head[512];
	static const struct {
		const char *header;
		const char *status;
	} cases[] = {
	    {"", "HTTP/1.1 101"},
	    {"Origin: https://app.example\r\n", "HTTP/1.1 101"},
	    {"Origin: HTTPS://APP.EXAMPLE\r\n", "HTTP/1.1 101"},
	    {"Origin: http://localhost:8080\r\n", "HTTP/1.1 101"},
	    {"Origin: https://evil.example\r\n", "HTTP/1.1 403"},
	    {"Origin: https://app.example.evil.example\r\n", "HTTP/1.1 403"},
	    {"Origin: http://app.example\r\n", "HTTP/1.1 403"},
	    {"Origin: null\r\n", "HTTP/1.1 403"},
	};
	for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		int fd = raw_upgrade(s, cases[i].header, head, sizeof(head));
		CHECK(strncmp(head, cases[i].status, 12) == 0, "%s -> %.20s", cases[i].header, head);
		close(fd);
	}
	hw_server_free(s);

	// With no list, any page may connect.
	base_config(&cfg);
	s = start(&cfg);
	int fd = raw_upgrade(s, "Origin: https://evil.example\r\n", head, sizeof(head));
	CHECK(strncmp(head, "HTTP/1.1 101", 12) == 0, "status: %.20s", head);
	close(fd);
	hw_server_free(s);
}

// Who the client is, when a proxy says so. The per-IP connection window (one per address here) is
// what shows which address the server settled on.
static void test_forwarded_address(void) {
	hw_server_config cfg;
	base_config(&cfg);
	cfg.parse_real_ip = 1;
	CHECK_EQ(hw_cidr_parse("127.0.0.1", &cfg.trusted_proxies[0]), 0);
	cfg.trusted_proxy_count = 1;
	cfg.connections_limit_per_ip = 1;
	cfg.connection_window_s = 60;
	hw_server *s = start(&cfg);
	char head[512];
	int a = raw_upgrade(s, "X-Forwarded-For: 203.0.113.1\r\n", head, sizeof(head));
	CHECK(strncmp(head, "HTTP/1.1 101", 12) == 0, "first address: %.20s", head);
	int b = raw_upgrade(s, "X-Forwarded-For: 203.0.113.1\r\n", head, sizeof(head));
	CHECK(strncmp(head, "HTTP/1.1 429", 12) == 0, "same address again: %.20s", head);
	int c = raw_upgrade(s, "X-Forwarded-For: 203.0.113.2\r\n", head, sizeof(head));
	CHECK(strncmp(head, "HTTP/1.1 101", 12) == 0, "another address: %.20s", head);
	// The header on a line of its own counts like the same list: the right-most entry is the one
	// the proxy wrote, and a client that sends its own line first does not get to pick.
	int d = raw_upgrade(s, "X-Forwarded-For: 198.51.100.7\r\nX-Forwarded-For: 203.0.113.1\r\n", head, sizeof(head));
	CHECK(strncmp(head, "HTTP/1.1 429", 12) == 0, "two lines: %.20s", head);

	// A list too long to keep whole has lost its end, which is the part the proxy wrote. Reading
	// what is left would take the client's word for its address: the request is refused.
	char extra[700] = "X-Forwarded-For: ";
	size_t n = strlen(extra);
	while (n < 600) n += (size_t)snprintf(extra + n, sizeof(extra) - n, "198.51.100.9, ");
	snprintf(extra + n, sizeof(extra) - n, "203.0.113.3\r\n");
	int e = raw_upgrade(s, extra, head, sizeof(head));
	CHECK(strncmp(head, "HTTP/1.1 400", 12) == 0, "cut list: %.20s", head);
	close(a);
	close(b);
	close(c);
	close(d);
	close(e);
	hw_server_free(s);

	// With a secret, the proxy's address is not enough: without it the headers say nothing and
	// the client is the peer.
	snprintf(cfg.trusted_proxy_secret, sizeof(cfg.trusted_proxy_secret), "s3cret-of-this-start");
	s = start(&cfg);
	a = raw_upgrade(s, "X-Forwarded-For: 203.0.113.1\r\n", head, sizeof(head));
	CHECK(strncmp(head, "HTTP/1.1 101", 12) == 0, "no secret, the peer: %.20s", head);
	b = raw_upgrade(s, "X-Forwarded-For: 203.0.113.2\r\n", head, sizeof(head));
	CHECK(strncmp(head, "HTTP/1.1 429", 12) == 0, "no secret, the peer again: %.20s", head);
	c = raw_upgrade(s, "X-Forwarded-For: 203.0.113.2\r\nX-HolyWisp-Proxy-Secret: wrong\r\n", head, sizeof(head));
	CHECK(strncmp(head, "HTTP/1.1 429", 12) == 0, "wrong secret: %.20s", head);
	d = raw_upgrade(s, "X-Forwarded-For: 203.0.113.2\r\nX-HolyWisp-Proxy-Secret: s3cret-of-this-start\r\n", head,
	                sizeof(head));
	CHECK(strncmp(head, "HTTP/1.1 101", 12) == 0, "with the secret: %.20s", head);
	close(a);
	close(b);
	close(c);
	close(d);
	hw_server_free(s);
}

// One address may hold max-concurrent-connections-per-ip connections and no more, whatever is
// left of the server-wide cap; a slot comes back when a connection closes.
static void test_connections_per_ip(void) {
	hw_server_config cfg;
	base_config(&cfg);
	cfg.flood.enabled = 1;
	cfg.flood.max_concurrent_connections = 100;
	cfg.flood.max_concurrent_connections_per_ip = 2;
	hw_server *s = start(&cfg);
	hw_client *a = connect_plain(s);
	hw_client *b = connect_plain(s);
	char head[512];
	int fd = raw_upgrade(s, "", head, sizeof(head));
	CHECK(strncmp(head, "HTTP/1.1 429", 12) == 0, "status: %.20s", head);
	CHECK(strstr(head, "\r\nRetry-After: ") != NULL, "head: %s", head);
	close(fd);
	hw_client_free(a);
	uint64_t deadline = hw_now_ms() + 5000;
	while (active_connections(s) > 1 && hw_now_ms() < deadline) sleep_ms(10);
	hw_client *c = connect_plain(s);
	hw_client_free(b);
	hw_client_free(c);
	hw_server_free(s);
}

// A TCP port whose connects never finish: a listener that never accepts, with its accept queue
// filled from here. Returns 0 where the kernel refuses instead of dropping (the case is skipped).
#define BLACKHOLE_FDS 66
static uint16_t start_blackhole(int fds[BLACKHOLE_FDS]) {
	for (int i = 0; i < BLACKHOLE_FDS; i++) fds[i] = -1;
	uint16_t port = 0;
	fds[0] = hw_listen_tcp("127.0.0.1", 0, 0, 0, &port);
	CHECK(fds[0] >= 0, "listen");
	struct sockaddr_in sin = {.sin_family = AF_INET, .sin_port = htons(port)};
	sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	for (int i = 1; i < BLACKHOLE_FDS; i++) {
		fds[i] = hw_socket_nb(AF_INET, SOCK_STREAM, 0);
		CHECK(fds[i] >= 0, "socket");
		if (connect(fds[i], (struct sockaddr *)&sin, sizeof(sin)) != 0 && errno != EINPROGRESS) return 0;
		struct pollfd pfd = {.fd = fds[i], .events = POLLOUT};
		int err = 0;
		socklen_t el = sizeof(err);
		if (poll(&pfd, 1, 300) <= 0) return port; // hangs: the queue is full
		if (getsockopt(fds[i], SOL_SOCKET, SO_ERROR, &err, &el) != 0 || err != 0) return 0;
	}
	return 0;
}

// The connects in progress are a server-wide pool, and one client with slow destinations could
// hold all of it: nobody else could open a TCP stream, and each of them was counted a violation
// for trying. A client address now has a share of its own, and running into the server-wide cap
// is nobody's violation.
static void test_in_flight_syns_per_ip(void) {
	int hole[BLACKHOLE_FDS];
	uint16_t port = start_blackhole(hole);
	if (port != 0) {
		hw_server_config cfg;
		base_config(&cfg);
		cfg.connect_timeout_ms = 3000;
		cfg.flood.enabled = 1;
		cfg.flood.syn_signature_enabled = 0;
		cfg.flood.max_in_flight_syns_per_ip = 2;
		cfg.flood.ws_close_after_violations = 0;
		hw_server *s = start(&cfg);
		hw_client *c = connect_plain(s);
		uint32_t held[2], third;
		CHECK_EQ(hw_client_open(c, HW_STREAM_TCP, "127.0.0.1", port, &held[0]), 0);
		CHECK_EQ(hw_client_open(c, HW_STREAM_TCP, "127.0.0.1", port, &held[1]), 0);
		CHECK_EQ(hw_client_open(c, HW_STREAM_TCP, "127.0.0.1", g_echo_port, &third), 0);
		uint8_t reason = 0;
		CHECK(wait_close(c, third, &reason, NULL), "the third connect was answered");
		CHECK_EQ(reason, HW_CLOSE_THROTTLED);
		hw_server_stats st;
		hw_server_stats_get(s, &st);
		CHECK_EQ(st.throttled_syns, 1);
		// A connect that ends gives its slot back.
		CHECK_EQ(hw_client_close_stream(c, held[0], HW_CLOSE_VOLUNTARY), 0);
		uint32_t sid;
		uint8_t buf[8];
		uint64_t deadline = hw_now_ms() + 5000;
		int echoed = 0;
		while (!echoed && hw_now_ms() < deadline) {
			CHECK_EQ(hw_client_open(c, HW_STREAM_TCP, "127.0.0.1", g_echo_port, &sid), 0);
			CHECK_EQ(hw_client_send(c, sid, "hello", 5), 0);
			echoed = hw_client_read_exact(c, sid, buf, 5, 500) == 5;
		}
		CHECK(echoed, "a stream opens once a slot is free");
		hw_client_free(c);
		hw_server_free(s);
	} else {
		CHECK(1, "this kernel refuses where a blackhole is wanted");
	}
	for (int i = 0; i < BLACKHOLE_FDS; i++) {
		if (hole[i] >= 0) close(hole[i]);
	}
}

// bandwidth-limit-kbps counts both directions. A download used to be free: the pause stopped only
// the client's own reads, and bytes that arrived during it were not charged.
static void test_bandwidth_limits_downloads(void) {
	hw_server_config cfg;
	base_config(&cfg);
	cfg.bandwidth_limit_kbps = 800; // 100 kB/s, with one second of burst
	hw_server *s = start(&cfg);
	hw_client *c = connect_plain(s);
	uint32_t sid;
	CHECK_EQ(hw_client_open(c, HW_STREAM_TCP, "127.0.0.1", g_blast_port, &sid), 0);
	size_t got = 0;
	uint64_t end = hw_now_ms() + 1500;
	while (hw_now_ms() < end) {
		hw_client_event ev;
		int r = hw_client_poll(c, 100, &ev);
		CHECK(r >= 0, "connection alive");
		if (r == 1 && ev.type == HW_CEV_DATA) got += ev.len;
		CHECK(r != 1 || ev.type != HW_CEV_CLOSE, "the stream was paused, not closed");
	}
	// The burst, 1.5 s at the rate, and what one pass over the remote can read before the charge
	// for it lands: a few megabytes at the very most. Unlimited, loopback moves hundreds.
	CHECK(got > 0, "something arrived");
	CHECK(got < 8u * 1024 * 1024, "%zu bytes in 1.5 s under a 100 kB/s limit", got);
	hw_client_free(c);
	hw_server_free(s);
}

// idle-timeout-s closes a client that has no streams and has said nothing for that long, and
// leaves one with a stream alone however quiet it is.
static void test_idle_timeout(void) {
	hw_server_config cfg;
	base_config(&cfg);
	cfg.idle_timeout_s = 1;
	cfg.client_write_timeout_s = 0;
	hw_server *s = start(&cfg);
	hw_client *idle = connect_plain(s);
	hw_client *busy = connect_plain(s);
	uint32_t sid;
	CHECK_EQ(hw_client_open(busy, HW_STREAM_TCP, "127.0.0.1", g_echo_port, &sid), 0);
	hw_client_event ev;
	int r = 0;
	uint64_t deadline = hw_now_ms() + 6000;
	while (r >= 0 && hw_now_ms() < deadline) r = hw_client_poll(idle, 500, &ev);
	CHECK(r < 0, "the idle client was closed");
	CHECK_EQ(hw_client_send(busy, sid, "hello", 5), 0);
	uint8_t buf[8];
	CHECK_EQ(hw_client_read_exact(busy, sid, buf, 5, 5000), 5);
	hw_client_free(idle);
	hw_client_free(busy);
	hw_server_free(s);
}

// A destination is made of the bytes hostnames and address literals are made of. Anything else is
// 0x41 before it is looked up, logged, or put into an upstream proxy's request line.
static void test_host_bytes(void) {
	hw_server_config cfg;
	base_config(&cfg);
	hw_server *s = start(&cfg);
	hw_client *c = connect_plain(s);
	static const char *const bad[] = {
	    "exa mple.com",
	    "example.com\r\nX-Injected: 1",
	    "example.com\t",
	    "exa/mple.com",
	    "user@example.com",
	    "ex\x7f"
	    "ample.com",
	    "ex\xc3\xa4"
	    "mple.com",
	    "example.com?x",
	};
	for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
		uint32_t sid;
		uint8_t reason = 0;
		CHECK_EQ(hw_client_open(c, HW_STREAM_TCP, bad[i], 80, &sid), 0);
		CHECK(wait_close(c, sid, &reason, NULL), "closed: %s", bad[i]);
		CHECK(reason == HW_CLOSE_INVALID_INFO, "%s: reason 0x%02x", bad[i], reason);
	}
	// What a name may hold still goes through.
	uint32_t sid;
	CHECK_EQ(hw_client_open(c, HW_STREAM_TCP, "127.0.0.1", g_echo_port, &sid), 0);
	CHECK_EQ(hw_client_send(c, sid, "hello", 5), 0);
	uint8_t buf[8];
	CHECK_EQ(hw_client_read_exact(c, sid, buf, 5, 5000), 5);
	hw_client_free(c);
	hw_server_free(s);
}

// Two things a well-behaved client never sends. A terminal stream asked of a server that has no
// Twisp is refused and costs the client nothing (it used to cost 40 points of reputation, which a
// page could spend for its visitors). A CONNECT for a stream id that is already open closes that
// stream: the CLOSE it earns names the id, and the server must agree with what it just said.
static void test_raw_connects(void) {
	hw_server_config cfg;
	base_config(&cfg);
	cfg.reputation_enabled = 1;
	cfg.reputation.store_path[0] = '\0';
	hw_server *s = start(&cfg);
	char head[512];
	int fd = raw_upgrade(s, "", head, sizeof(head));
	CHECK(strncmp(head, "HTTP/1.1 101", 12) == 0, "status: %.20s", head);
	uint8_t in[256], out[300];
	hw_wisp_packet p;
	CHECK(raw_read_packet(fd, in, sizeof(in), 5000) > 0, "the opening CONTINUE");

	size_t n = hw_wisp_build_connect(out, sizeof(out), 7, HW_STREAM_TERM, 1, "sh", 2);
	raw_send_packet(fd, out, n);
	int len = raw_read_packet(fd, in, sizeof(in), 5000);
	CHECK(len > 0 && hw_wisp_parse(in, (size_t)len, &p) == 0, "an answer");
	CHECK(p.type == HW_WISP_CLOSE && p.stream_id == 7 && p.payload[0] == HW_CLOSE_BLOCKED, "the terminal was refused");
	CHECK_EQ(hw_reputation_source_score(hw_server_reputation(s), "127.0.0.1"), 0);

	n = hw_wisp_build_connect(out, sizeof(out), 9, HW_STREAM_TCP, g_echo_port, "127.0.0.1", 9);
	raw_send_packet(fd, out, n);
	hw_server_stats st;
	uint64_t deadline = hw_now_ms() + 5000;
	do {
		sleep_ms(10);
		hw_server_stats_get(s, &st);
	} while (st.streams_active != 1 && hw_now_ms() < deadline);
	CHECK_EQ(st.streams_active, 1);
	raw_send_packet(fd, out, n); // the same id again
	len = raw_read_packet(fd, in, sizeof(in), 5000);
	CHECK(len > 0 && hw_wisp_parse(in, (size_t)len, &p) == 0, "an answer");
	CHECK(p.type == HW_WISP_CLOSE && p.stream_id == 9 && p.payload[0] == HW_CLOSE_INVALID_INFO,
	      "the duplicate was refused");
	hw_server_stats_get(s, &st);
	CHECK_EQ(st.streams_active, 0);
	close(fd);
	hw_server_free(s);
}

// Passwords: an empty one is not accepted into a config, and with hashed passwords in use a name
// that does not exist is turned away like a wrong password (after the same work, off the loop).
static void test_passwords(void) {
	hw_server_config cfg;
	base_config(&cfg);
	CHECK(hw_server_config_add_user(&cfg, "alice", "") != 0, "an empty password was accepted");
	CHECK_EQ(cfg.password_user_count, 0);
	if (!hw_sys_has_crypt()) return;
	char hash[128];
	CHECK_EQ(hw_sys_crypt("hunter2", "$6$holywispsalt$", hash, sizeof(hash)), 0);
	CHECK_EQ(hw_server_config_add_user(&cfg, "alice", hash), 0);
	CHECK_EQ(hw_server_config_add_user(&cfg, "bob", "plain"), 0);
	cfg.password_required = 1;
	hw_server *s = start(&cfg);
	hw_client_opts o;
	hw_client_opts_defaults(&o);
	o.host = "127.0.0.1";
	o.port = hw_server_port(s);
	o.v2 = 1;
	o.timeout_ms = 5000;
	char err[256];
	const struct {
		const char *user;
		const char *pass;
		int ok;
	} cases[] = {
	    {"alice", "hunter2", 1}, {"alice", "hunter3", 0}, {"alice", "", 0}, {"mallory", "hunter2", 0},
	    {"bob", "plain", 1},     {"bob", "plain2", 0},    {"bob", hash, 0}, {"alice", hash, 0},
	};
	for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		o.user = cases[i].user;
		o.pass = cases[i].pass;
		hw_client *c = hw_client_connect(&o, err, sizeof(err));
		CHECK((c != NULL) == cases[i].ok, "%s / %s", cases[i].user, cases[i].pass);
		if (c) hw_client_free(c);
	}
	// A client that leaves while its password is being hashed is not a problem for anyone.
	for (int i = 0; i < 20; i++) {
		char head[512];
		int fd = raw_upgrade(s, "Sec-WebSocket-Protocol: wisp-v2\r\n", head, sizeof(head));
		CHECK(strncmp(head, "HTTP/1.1 101", 12) == 0, "status: %.20s", head);
		uint8_t info[128];
		size_t n = hw_wisp_build_info(info, HW_WISP_MAJOR, 0);
		// The user name's length, the name, and the password is the rest.
		static const uint8_t meta[13] = {5, 'a', 'l', 'i', 'c', 'e', 'h', 'u', 'n', 't', 'e', 'r', '3'};
		n += hw_wisp_build_extension(info + n, sizeof(info) - n, HW_EXT_PASSWORD, meta, sizeof(meta));
		raw_send_packet(fd, info, n);
		close(fd);
	}
	o.user = "alice";
	o.pass = "hunter2";
	hw_client *c = hw_client_connect(&o, err, sizeof(err));
	CHECK(c != NULL, "still serving: %s", err);
	hw_client_free(c);
	hw_server_free(s);
}

int main(void) {
	g_echo_port = start_service(echo_conn);
	g_blast_port = start_service(blast_conn);
	g_reset_port = start_service(reset_conn);

	RUN(test_client_that_never_reads);
	RUN(test_remote_resets_while_paused);
	RUN(test_origin_allowlist);
	RUN(test_forwarded_address);
	RUN(test_connections_per_ip);
	RUN(test_in_flight_syns_per_ip);
	RUN(test_bandwidth_limits_downloads);
	RUN(test_idle_timeout);
	RUN(test_host_bytes);
	RUN(test_raw_connects);
	RUN(test_passwords);
	printf("ok all abuse cases\n");
	return 0;
}
