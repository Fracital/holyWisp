/*
 * End to end for the data path under pressure, the four classes of bug the wispurr relay needed
 * patches for in production: DATA that arrives while a CONNECT is still in flight, egress DATA
 * frames that must fit the negotiated message size, a client that reads slower than its remotes
 * send (connection-level backpressure, never a close), and a client that spends its whole CONTINUE
 * window into a remote that does not drain (the window must be sized so this never trips the
 * 0x49 backstop). A real server, real helper services, the real client library.
 */
#include "holywisp/client.h"
#include "holywisp/hw.h"
#include "holywisp/log.h"
#include "holywisp/net.h"
#include "holywisp/server.h"
#include "holywisp/wisp.h"

#include "test.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <netinet/in.h>
#include <sys/socket.h>

static uint16_t g_echo_port;
static uint16_t g_blast_port;

#define BLAST_BYTES  (2u * 1024 * 1024)
#define BLAST_SEED   77u
#define BLAST_SNDBUF (64 * 1024)

static _Atomic int g_blast_done; // blast connections that wrote every byte

// ---------------------------------------------------------------------------------- helpers

static void fill_pattern(uint8_t *buf, size_t n, uint32_t seed) {
	uint32_t x = seed * 2654435761u + 1;
	for (size_t i = 0; i < n; i++) {
		x ^= x << 13;
		x ^= x >> 17;
		x ^= x << 5;
		buf[i] = (uint8_t)x;
	}
}

static int write_full(int fd, const uint8_t *buf, size_t n) {
	size_t off = 0;
	while (off < n) {
		ssize_t w = write(fd, buf + off, n - off);
		if (w <= 0) return -1;
		off += (size_t)w;
	}
	return 0;
}

// Whether a socket from accept(2) has its listener's O_NONBLOCK depends on the kernel (Linux: no;
// the BSDs and Windows: yes). A sink the test reads with read_full has to block either way.
static void set_blocking(int fd) {
	fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) & ~O_NONBLOCK);
}

static int read_full(int fd, uint8_t *buf, size_t n) {
	size_t got = 0;
	while (got < n) {
		ssize_t r = read(fd, buf + got, n - got);
		if (r <= 0) return -1;
		got += (size_t)r;
	}
	return 0;
}

static void spawn_detached(void *(*fn)(void *), int fd) {
	pthread_t th;
	pthread_attr_t attr;
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	pthread_create(&th, &attr, fn, (void *)(intptr_t)fd);
	pthread_attr_destroy(&attr);
}

static void *accept_loop(int lfd, void *(*handler)(void *)) {
	for (;;) {
		int fd = accept(lfd, NULL, NULL);
		if (fd < 0) {
			if (errno == EINTR) continue;
			return NULL;
		}
		spawn_detached(handler, fd);
	}
}

// TCP echo service.
static void *echo_conn(void *arg) {
	int fd = (int)(intptr_t)arg;
	uint8_t buf[16384];
	for (;;) {
		ssize_t n = read(fd, buf, sizeof(buf));
		if (n <= 0 || write_full(fd, buf, (size_t)n) != 0) break;
	}
	close(fd);
	return NULL;
}

static void *echo_main(void *arg) {
	return accept_loop((int)(intptr_t)arg, echo_conn);
}

// Blast service: a fast origin. Writes BLAST_BYTES of a fixed pattern as quickly as the peer takes
// them, then closes. The send buffer is pinned small so the kernel cannot absorb the whole payload
// on the origin's behalf: when the relay stops reading, the origin's write(2) has to block.
static void *blast_conn(void *arg) {
	int fd = (int)(intptr_t)arg;
	int sz = BLAST_SNDBUF;
	setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sz, sizeof(sz));
	uint8_t *data = malloc(BLAST_BYTES);
	fill_pattern(data, BLAST_BYTES, BLAST_SEED);
	if (write_full(fd, data, BLAST_BYTES) == 0) atomic_fetch_add(&g_blast_done, 1);
	free(data);
	close(fd);
	return NULL;
}

static void *blast_main(void *arg) {
	return accept_loop((int)(intptr_t)arg, blast_conn);
}

static void start_service(void *(*fn)(void *), uint16_t *port) {
	int lfd = hw_listen_tcp("127.0.0.1", 0, 0, 64, port);
	CHECK(lfd >= 0, "listen: %s", strerror(errno));
	fcntl(lfd, F_SETFL, fcntl(lfd, F_GETFL, 0) & ~O_NONBLOCK); // the helpers block in accept(2)
	pthread_t th;
	pthread_create(&th, NULL, fn, (void *)(intptr_t)lfd);
	pthread_detach(th);
}

static void base_config(hw_server_config *cfg) {
	hw_server_config_defaults(cfg);
	snprintf(cfg->host, sizeof(cfg->host), "127.0.0.1");
	cfg->port = 0;
	cfg->workers = 1;
	cfg->allow_direct_ip = 1;
	cfg->allow_loopback = 1;
	cfg->buffer_remaining = 64;
	cfg->max_message_size = 64 * 1024 + HW_WISP_HEADER_LEN; // keeps the 64-packet window uncapped
	cfg->reputation_enabled = 0;
	cfg->log_level = HW_LOG_ERROR;
}

static hw_server *start_server(const hw_server_config *cfg) {
	hw_server *s = hw_server_new(cfg);
	CHECK(s != NULL, "server: %s", strerror(errno));
	CHECK_EQ(hw_server_start(s), 0);
	return s;
}

static hw_client *connect_plain(hw_server *s, size_t max_message) {
	hw_client_opts o;
	hw_client_opts_defaults(&o);
	o.host = "127.0.0.1";
	o.port = hw_server_port(s);
	o.timeout_ms = 5000;
	o.max_message = max_message;
	char err[256];
	hw_client *c = hw_client_connect(&o, err, sizeof(err));
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

static int echo_once(hw_client *c, uint32_t sid, const char *msg) {
	if (hw_client_send(c, sid, msg, strlen(msg)) != 0) return 0;
	uint8_t buf[64];
	long n = hw_client_read_exact(c, sid, buf, strlen(msg), 5000);
	return n == (long)strlen(msg) && memcmp(buf, msg, strlen(msg)) == 0;
}

// ---------------------------------------------------------------------------------- cases

// wispurr 0001: DATA sent right behind the CONNECT, before the remote has accepted, is queued and
// written in order once the socket is up. The client sends CONNECT and the whole burst in one go,
// so the server sees the DATA while the connect is still in flight.
static void test_data_before_connect_completes(void) {
	hw_server_config cfg;
	base_config(&cfg);
	hw_server *s = start_server(&cfg);
	hw_client *c = connect_plain(s, 0);
	enum {
		N = 48
	};
	uint8_t *data = malloc(N * 4096);
	fill_pattern(data, N * 4096, 3);
	uint32_t sid;
	CHECK_EQ(hw_client_open(c, HW_STREAM_TCP, "127.0.0.1", g_echo_port, &sid), 0);
	size_t total = 0;
	for (int i = 0; i < N; i++) {
		size_t len = 1 + (size_t)(i * 97) % 4000; // uneven packet sizes so a reorder shows
		CHECK_EQ(hw_client_send(c, sid, data + total, len), 0);
		total += len;
	}
	uint8_t *back = malloc(total);
	CHECK_EQ(hw_client_read_exact(c, sid, back, total, 5000), (long)total);
	CHECK(memcmp(data, back, total) == 0, "burst behind CONNECT intact and in order");
	free(data);
	free(back);
	hw_client_free(c);
	hw_server_free(s);
}

// wispurr 0002: a 64 KiB read from the remote must not become one 64 KiB DATA frame when the
// negotiated message size is smaller. The client is told the same limit and fails the socket on
// an oversize frame, exactly as a strict peer would.
static void test_egress_frames_within_max_message(void) {
	enum {
		LIMIT = 16 * 1024 + HW_WISP_HEADER_LEN,
		CHUNK = 8 * 1024,
		N = 32
	};
	hw_server_config cfg;
	base_config(&cfg);
	cfg.max_message_size = LIMIT;
	hw_server *s = start_server(&cfg);
	hw_client *c = connect_plain(s, LIMIT);
	uint32_t sid;
	CHECK_EQ(hw_client_open(c, HW_STREAM_TCP, "127.0.0.1", g_echo_port, &sid), 0);
	uint8_t *data = malloc((size_t)N * CHUNK);
	fill_pattern(data, (size_t)N * CHUNK, 11);
	for (int i = 0; i < N; i++) CHECK_EQ(hw_client_send(c, sid, data + (size_t)i * CHUNK, CHUNK), 0);
	uint8_t *back = malloc((size_t)N * CHUNK);
	long got = hw_client_read_exact(c, sid, back, (size_t)N * CHUNK, 5000);
	CHECK(got == (long)N * CHUNK, "echo of %d bytes through %d-byte frames: got %ld", N * CHUNK, LIMIT, got);
	CHECK(memcmp(data, back, (size_t)N * CHUNK) == 0, "split frames reassemble in order");
	free(data);
	free(back);
	hw_client_free(c);
	hw_server_free(s);
}

// wispurr 0003: four fast origins into a client that does not read. The server's queue toward the
// client passes the high-water mark, every stream stops reading its origin (the origins' writes
// block), nothing is closed, and once the client reads again every byte arrives in order.
static void test_slow_client_backpressure(void) {
	enum {
		N = 4
	};
	hw_server_config cfg;
	base_config(&cfg);
	cfg.ws_write_high_water = 256 * 1024;
	cfg.socket_buffer_size = 64 * 1024;
	hw_server *s = start_server(&cfg);
	hw_client *c = connect_plain(s, 0);
	int rcv = 64 * 1024; // keep the kernel from hiding a slow reader behind a big receive buffer
	setsockopt(hw_client_fd(c), SOL_SOCKET, SO_RCVBUF, &rcv, sizeof(rcv));
	atomic_store(&g_blast_done, 0);
	uint32_t sids[N];
	for (int i = 0; i < N; i++) CHECK_EQ(hw_client_open(c, HW_STREAM_TCP, "127.0.0.1", g_blast_port, &sids[i]), 0);

	// Do not read. The origins cannot have finished: the relay must have stopped reading them.
	usleep(400 * 1000);
	int done = atomic_load(&g_blast_done);
	CHECK(done < N, "origins blocked on a slow client: %d of %d finished", done, N);

	uint8_t *expect = malloc(BLAST_BYTES);
	fill_pattern(expect, BLAST_BYTES, BLAST_SEED);
	uint8_t *back[N];
	size_t got[N] = {0};
	int closed[N] = {0};
	for (int i = 0; i < N; i++) back[i] = malloc(BLAST_BYTES);
	int remaining = N;
	while (remaining > 0) {
		hw_client_event ev;
		int r = hw_client_poll(c, 10000, &ev);
		CHECK(r > 0, "poll while draining: %d (connection must stay up)", r);
		int idx = -1;
		for (int i = 0; i < N; i++) {
			if (sids[i] == ev.stream_id) idx = i;
		}
		CHECK(idx >= 0, "event for unknown stream %u", ev.stream_id);
		if (ev.type == HW_CEV_DATA) {
			CHECK(got[idx] + ev.len <= BLAST_BYTES, "stream %d overflow", idx);
			memcpy(back[idx] + got[idx], ev.data, ev.len);
			got[idx] += ev.len;
		} else if (ev.type == HW_CEV_CLOSE) {
			CHECK_EQ(ev.reason, HW_CLOSE_VOLUNTARY);
			CHECK_EQ(got[idx], BLAST_BYTES);
			closed[idx] = 1;
			remaining--;
		}
	}
	for (int i = 0; i < N; i++) {
		CHECK(closed[i] && memcmp(back[i], expect, BLAST_BYTES) == 0, "stream %d intact after backpressure", i);
		free(back[i]);
	}
	free(expect);
	CHECK_EQ(atomic_load(&g_blast_done), N);
	// The connection is still healthy and reads resumed: a fresh stream works.
	uint32_t sid;
	CHECK_EQ(hw_client_open(c, HW_STREAM_TCP, "127.0.0.1", g_echo_port, &sid), 0);
	CHECK(echo_once(c, sid, "still here"), "echo after backpressure");
	hw_client_free(c);
	hw_server_free(s);
}

// wispurr 0004: the window the server advertises must be small enough that a client spending all
// of it with maximum-size packets into a remote that is not reading fits in the stream queue. The
// client is only ever slowed by the held-back CONTINUE, never closed with 0x49.
static void test_ingress_window_stalled_upstream(void) {
	enum {
		PKT = 64 * 1024,
		QUEUE = 1024 * 1024,
		WINDOW = QUEUE / PKT // 16: the queue in max-size packets
	};
	hw_server_config cfg;
	base_config(&cfg);
	cfg.max_message_size = PKT + HW_WISP_HEADER_LEN;
	cfg.stream_queue_max = QUEUE;
	cfg.socket_buffer_size = 64 * 1024;
	hw_server *s = start_server(&cfg);

	uint16_t port = 0;
	int lfd = hw_listen_tcp("127.0.0.1", 0, 0, 4, &port);
	CHECK(lfd >= 0, "sink listen");
	int rcv = 64 * 1024; // inherited by the accepted socket: the kernel holds far less than a window
	setsockopt(lfd, SOL_SOCKET, SO_RCVBUF, &rcv, sizeof(rcv));

	hw_client *c = connect_plain(s, 0);
	CHECK_EQ(hw_client_buffer_size(c), WINDOW);
	uint32_t sid;
	CHECK_EQ(hw_client_open(c, HW_STREAM_TCP, "127.0.0.1", port, &sid), 0);
	struct pollfd pfd = {.fd = lfd, .events = POLLIN};
	CHECK_EQ(poll(&pfd, 1, 5000), 1);
	int sink = accept(lfd, NULL, NULL);
	CHECK(sink >= 0, "accept");
	set_blocking(sink);

	// Spend the whole window into a sink that reads nothing.
	uint8_t *data = malloc((size_t)WINDOW * PKT);
	fill_pattern(data, (size_t)WINDOW * PKT, 5);
	for (int i = 0; i < WINDOW; i++) CHECK_EQ(hw_client_send(c, sid, data + (size_t)i * PKT, PKT), 0);
	hw_client_event ev;
	int r = hw_client_poll(c, 300, &ev);
	CHECK(r == 0, "nothing from the server while the remote is stalled: got %d (type %d reason %u)", r, ev.type,
	      ev.reason);

	// The remote drains: every byte in order, then the held CONTINUE hands the window back.
	uint8_t *back = malloc((size_t)WINDOW * PKT);
	CHECK_EQ(read_full(sink, back, (size_t)WINDOW * PKT), 0);
	CHECK(memcmp(data, back, (size_t)WINDOW * PKT) == 0, "queued window intact");
	CHECK_EQ(wait_event(c, sid, HW_CEV_CONTINUE, &ev, 5000), 1);
	CHECK_EQ(ev.buffer_remaining, WINDOW);
	CHECK_EQ(hw_client_send(c, sid, data, 100), 0);
	CHECK_EQ(read_full(sink, back, 100), 0);
	CHECK(memcmp(data, back, 100) == 0, "stream still relays after the stall");
	free(data);
	free(back);
	close(sink);
	close(lfd);
	hw_client_free(c);
	hw_server_free(s);
}

// A sender thread for the connection-budget test: hw_client_send blocks once the server stops
// reading, which is exactly what the test wants to observe, so it cannot run on the test thread.
static struct {
	hw_client *c;
	uint32_t *sids;
	int streams;
	int window;
	size_t pkt;
	uint8_t *data;
	_Atomic int sent; // packets handed to hw_client_send that returned
} g_sender;

static void *sender_main(void *arg) {
	for (int k = 0; k < g_sender.window; k++) {
		for (int i = 0; i < g_sender.streams; i++) {
			const uint8_t *p = g_sender.data + ((size_t)i * g_sender.window + k) * g_sender.pkt;
			if (hw_client_send(g_sender.c, g_sender.sids[i], p, g_sender.pkt) != 0) return NULL;
			atomic_fetch_add(&g_sender.sent, 1);
		}
	}
	return NULL;
}

static struct {
	uint8_t *buf;
	size_t len;
	int fd;
	int ok;
} g_drain[4];

static void *drain_main(void *arg) {
	int i = (int)(intptr_t)arg;
	g_drain[i].ok = read_full(g_drain[i].fd, g_drain[i].buf, g_drain[i].len) == 0;
	return NULL;
}

// Several streams, each inside its own window, into remotes that read nothing. Their queues add
// up past conn-queue-max, so the server stops reading the client (its sends block) and closes
// nothing. Once the remotes drain, reads resume and every byte is there, in order, per stream.
static void test_conn_queue_pauses_reads(void) {
	enum {
		PKT = 64 * 1024,
		QUEUE = 1024 * 1024,
		WINDOW = QUEUE / PKT, // 16
		STREAMS = 3
	};
	hw_server_config cfg;
	base_config(&cfg);
	cfg.max_message_size = PKT + HW_WISP_HEADER_LEN;
	cfg.stream_queue_max = QUEUE;
	cfg.conn_queue_max = 2 * QUEUE; // three full windows do not fit
	cfg.socket_buffer_size = 64 * 1024;
	hw_server *s = start_server(&cfg);

	uint16_t port = 0;
	int lfd = hw_listen_tcp("127.0.0.1", 0, 0, 4, &port);
	CHECK(lfd >= 0, "sink listen");
	int small = 64 * 1024;
	setsockopt(lfd, SOL_SOCKET, SO_RCVBUF, &small, sizeof(small));

	hw_client *c = connect_plain(s, 0);
	setsockopt(hw_client_fd(c), SOL_SOCKET, SO_SNDBUF, &small, sizeof(small));
	CHECK_EQ(hw_client_buffer_size(c), WINDOW);
	uint32_t sids[STREAMS];
	int sinks[STREAMS];
	for (int i = 0; i < STREAMS; i++) {
		CHECK_EQ(hw_client_open(c, HW_STREAM_TCP, "127.0.0.1", port, &sids[i]), 0);
		struct pollfd pfd = {.fd = lfd, .events = POLLIN};
		CHECK_EQ(poll(&pfd, 1, 5000), 1);
		sinks[i] = accept(lfd, NULL, NULL);
		CHECK(sinks[i] >= 0, "accept %d", i);
		set_blocking(sinks[i]);
	}

	const size_t per_stream = (size_t)WINDOW * PKT;
	uint8_t *data = malloc(per_stream * STREAMS);
	fill_pattern(data, per_stream * STREAMS, 9);
	g_sender.c = c;
	g_sender.sids = sids;
	g_sender.streams = STREAMS;
	g_sender.window = WINDOW;
	g_sender.pkt = PKT;
	g_sender.data = data;
	atomic_store(&g_sender.sent, 0);
	pthread_t sender;
	CHECK_EQ(pthread_create(&sender, NULL, sender_main, NULL), 0);

	// The budget is 2 MiB of 3 MiB: the server must have stopped reading before the sender is done.
	usleep(500 * 1000);
	int sent = atomic_load(&g_sender.sent);
	CHECK(sent < WINDOW * STREAMS, "client blocked by the paused server: %d of %d packets sent", sent,
	      WINDOW * STREAMS);

	// Drain all sinks at once (draining one alone cannot free enough to resume the client).
	pthread_t drains[STREAMS];
	for (int i = 0; i < STREAMS; i++) {
		g_drain[i].fd = sinks[i];
		g_drain[i].buf = malloc(per_stream);
		g_drain[i].len = per_stream;
		CHECK_EQ(pthread_create(&drains[i], NULL, drain_main, (void *)(intptr_t)i), 0);
	}
	for (int i = 0; i < STREAMS; i++) pthread_join(drains[i], NULL);
	pthread_join(sender, NULL);
	CHECK_EQ(atomic_load(&g_sender.sent), WINDOW * STREAMS);
	for (int i = 0; i < STREAMS; i++) {
		CHECK(g_drain[i].ok, "sink %d drained", i);
		CHECK(memcmp(data + per_stream * (size_t)i, g_drain[i].buf, per_stream) == 0, "stream %d intact", i);
		free(g_drain[i].buf);
	}
	// Nothing was closed and the windows come back: every stream gets its CONTINUE (in whatever
	// order the remotes drained) and still relays.
	int continued = 0;
	uint64_t deadline = hw_now_ms() + 5000;
	while (continued < STREAMS && hw_now_ms() < deadline) {
		hw_client_event ev;
		int r = hw_client_poll(c, 200, &ev);
		CHECK(r >= 0, "poll: %d", r);
		if (r <= 0) continue;
		CHECK(ev.type != HW_CEV_CLOSE, "unexpected CLOSE on stream %u (reason %u)", ev.stream_id, ev.reason);
		if (ev.type != HW_CEV_CONTINUE) continue;
		CHECK_EQ(ev.buffer_remaining, WINDOW);
		continued++;
	}
	CHECK_EQ(continued, STREAMS);
	CHECK_EQ(hw_client_send(c, sids[0], data, 100), 0);
	uint8_t back[100];
	CHECK_EQ(read_full(sinks[0], back, sizeof(back)), 0);
	CHECK(memcmp(data, back, sizeof(back)) == 0, "relays after the pause");
	free(data);
	for (int i = 0; i < STREAMS; i++) close(sinks[i]);
	close(lfd);
	hw_client_free(c);
	hw_server_free(s);
}

int main(void) {
	hw_log_set_level(HW_LOG_ERROR);
	start_service(echo_main, &g_echo_port);
	start_service(blast_main, &g_blast_port);
	RUN(test_data_before_connect_completes);
	RUN(test_egress_frames_within_max_message);
	RUN(test_slow_client_backpressure);
	RUN(test_ingress_window_stalled_upstream);
	RUN(test_conn_queue_pauses_reads);
	return 0;
}
