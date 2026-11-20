/*
 * tests/ext_cases.h - holyWisp's private INFO extensions end to end (docs/extensions.md), the same
 * cases over both transports: included by test_e2e.c (WebSocket) and test_e2e_wt.c
 * (WebTransport), each with its own way to make a server and a client. Stream credit (0xE2) has
 * its own file, credit_cases.h.
 */
#ifndef HOLYWISP_TESTS_EXT_CASES_H
#define HOLYWISP_TESTS_EXT_CASES_H

#include "holywisp/client.h"
#include "holywisp/hw.h"
#include "holywisp/net.h"
#include "holywisp/server.h"
#include "holywisp/wisp.h"

#include "test.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>

typedef struct ext_env {
	void (*config)(hw_server_config *cfg);                // the transport's base config
	hw_server *(*start)(const hw_server_config *cfg);     // a started server
	void (*client_opts)(hw_server *s, hw_client_opts *o); // a v2 client of s on the transport
	uint16_t echo_port;                                   // TCP echo
} ext_env;

static const ext_env *g_ext;

static hw_client *ext_connect(const hw_client_opts *o) {
	char err[256];
	hw_client *c = hw_client_connect(o, err, sizeof(err));
	CHECK(c != NULL, "connect: %s", err);
	return c;
}

static void ext_echo(hw_client *c, uint32_t sid, const char *what) {
	size_t n = strlen(what);
	uint8_t back[64];
	CHECK_EQ(hw_client_send(c, sid, what, n), 0);
	CHECK_EQ(hw_client_read_exact(c, sid, back, n, 5000), (long long)n);
	CHECK(memcmp(back, what, n) == 0, "echo of %s", what);
}

// ---------------------------------------------------------------------------------- stream limit

// The server's INFO says how many streams the connection may have open (0xE3), so a client keeps
// under it instead of finding it by being refused 0x49. The client library refuses the one past it
// without sending anything, and a stream it closed makes room at once. One lane: across lanes a
// CONNECT may overtake the CLOSE that made room for it, which the extension does not promise
// against.
static void limit_offered(void) {
	const ext_env *e = g_ext;
	hw_server_config cfg;
	e->config(&cfg);
	cfg.max_streams_per_conn = 3;
	hw_server *s = e->start(&cfg);
	hw_client_opts o;
	e->client_opts(s, &o);
	o.wt_lanes = 1;
	hw_client *c = ext_connect(&o);
	CHECK_EQ(hw_client_max_streams(c), 3);
	uint32_t sid[3], extra;
	for (int i = 0; i < 3; i++) {
		CHECK_EQ(hw_client_open(c, HW_STREAM_TCP, "127.0.0.1", e->echo_port, &sid[i]), 0);
		ext_echo(c, sid[i], "within");
	}
	CHECK_EQ(hw_client_open(c, HW_STREAM_TCP, "127.0.0.1", e->echo_port, &extra), HW_ERR_TOOBIG);
	CHECK_EQ(hw_client_close_stream(c, sid[1], HW_CLOSE_VOLUNTARY), 0);
	for (int round = 0; round < 8; round++) { // close one, open one, never refused
		CHECK_EQ(hw_client_open(c, HW_STREAM_TCP, "127.0.0.1", e->echo_port, &extra), 0);
		ext_echo(c, extra, "room");
		CHECK_EQ(hw_client_close_stream(c, extra, HW_CLOSE_VOLUNTARY), 0);
	}
	hw_client_free(c);

	// A v1 client hears no limit, and the server refuses past it as it always did.
	e->client_opts(s, &o);
	o.v2 = 0;
	o.wt_lanes = 0;
	c = ext_connect(&o);
	CHECK_EQ(hw_client_max_streams(c), 0);
	for (int i = 0; i < 3; i++) CHECK_EQ(hw_client_open(c, HW_STREAM_TCP, "127.0.0.1", e->echo_port, &sid[i]), 0);
	CHECK_EQ(hw_client_open(c, HW_STREAM_TCP, "127.0.0.1", e->echo_port, &extra), 0);
	hw_client_event ev;
	for (;;) {
		CHECK_EQ(hw_client_poll(c, 5000, &ev), 1);
		if (ev.stream_id == extra && ev.type == HW_CEV_CLOSE) break;
	}
	CHECK_EQ(ev.reason, HW_CLOSE_THROTTLED);
	hw_client_free(c);
	hw_server_free(s);
}

// max-streams-per-conn 0 is no limit, and the INFO says 0: the client counts nothing.
static void limit_none(void) {
	const ext_env *e = g_ext;
	hw_server_config cfg;
	e->config(&cfg);
	cfg.max_streams_per_conn = 0;
	hw_server *s = e->start(&cfg);
	hw_client_opts o;
	e->client_opts(s, &o);
	hw_client *c = ext_connect(&o);
	CHECK_EQ(hw_client_max_streams(c), 0);
	uint32_t sid;
	for (int i = 0; i < 5; i++) CHECK_EQ(hw_client_open(c, HW_STREAM_TCP, "127.0.0.1", e->echo_port, &sid), 0);
	ext_echo(c, sid, "unlimited");
	hw_client_free(c);
	hw_server_free(s);
}

// ---------------------------------------------------------------------------------- upload credit

// The bytes the upload cases send: position i of a stream's.
static uint8_t up_byte(size_t i) {
	return (uint8_t)(i * 13 % 253);
}

// Events of stream sid until none has come for quiet_ms: how many CONTINUEs and whether it closed.
static int up_quiet(hw_client *c, uint32_t sid, int quiet_ms, int *closed) {
	hw_client_event ev;
	int continues = 0;
	*closed = 0;
	for (;;) {
		int r = hw_client_poll(c, quiet_ms, &ev);
		CHECK(r >= 0, "poll %d", r);
		if (r == 0) return continues;
		if (ev.stream_id != sid) continue;
		if (ev.type == HW_CEV_CONTINUE) continues++;
		if (ev.type == HW_CEV_CLOSE) *closed = 1;
	}
}

// A client that names 0xE4 is told the window (upload-window within stream-queue-max: here the
// 8 MiB of ws-write-high-water), and its uploads go on byte grants alone: 32 MiB through an echo
// in 1 MiB packets, four times the window, with no CONTINUE for the stream. Over WebTransport the
// stream rides lane 1, and its grants with it.
static void upload_credit_echo(void) {
	const ext_env *e = g_ext;
	hw_server_config cfg;
	e->config(&cfg);
	hw_server *s = e->start(&cfg);
	hw_client_opts o;
	e->client_opts(s, &o);
	o.upload_credit = 1;
	hw_client *c = ext_connect(&o);
	CHECK_EQ(hw_client_upload_window(c), 8u * 1024 * 1024);
	uint32_t first, sid;
	CHECK_EQ(hw_client_open(c, HW_STREAM_TCP, "127.0.0.1", e->echo_port, &first), 0);
	CHECK_EQ(hw_client_open(c, HW_STREAM_TCP, "127.0.0.1", e->echo_port, &sid), 0);
	static uint8_t chunk[1024 * 1024], back[1024 * 1024];
	size_t off = 0;
	for (int i = 0; i < 32; i++) {
		for (size_t k = 0; k < sizeof(chunk); k++) chunk[k] = up_byte(off + k);
		CHECK_EQ(hw_client_send(c, sid, chunk, sizeof(chunk)), 0);
		CHECK_EQ(hw_client_read_exact(c, sid, back, sizeof(back), 5000), (long long)sizeof(back));
		CHECK(memcmp(chunk, back, sizeof(chunk)) == 0, "echo %d", i);
		off += sizeof(chunk);
	}
	int closed;
	CHECK_EQ(up_quiet(c, sid, 200, &closed), 0);
	CHECK(!closed, "the stream closed");
	ext_echo(c, first, "beside it");
	hw_client_free(c);
	hw_server_free(s);
}

typedef struct up_sink {
	int fd;
	_Atomic size_t got;
} up_sink;

static void *up_sink_drain(void *arg) {
	up_sink *k = arg;
	uint8_t buf[65536];
	for (;;) {
		ssize_t n = recv(k->fd, buf, sizeof(buf), 0);
		if (n < 0 && errno == EINTR) continue;
		if (n == 0 || (n < 0 && errno == ECONNRESET)) break;  // the stream's end; the case counts the bytes
		CHECK(n > 0, "the sink's recv: %s", strerror(errno)); // a sink that quit would stall the upload
		size_t at = atomic_load(&k->got);
		for (ssize_t i = 0; i < n; i++) CHECK(buf[i] == up_byte(at + (size_t)i), "byte %zu", at + (size_t)i);
		atomic_fetch_add(&k->got, (size_t)n);
	}
	return NULL;
}

// The bound that makes early grants safe: a remote that takes nothing holds the client to what
// reached the kernel plus a budget (and the one packet it may start inside its credit), so the
// client is slowed and never closed 0x49, though stream-queue-max is here only 2 MiB. Then the
// remote reads, the grants come, and the rest goes through in order.
static void upload_credit_stalled_remote(void) {
	const ext_env *e = g_ext;
	hw_server_config cfg;
	e->config(&cfg);
	cfg.stream_queue_max = 2u * 1024 * 1024;
	cfg.max_message_size = 64 * 1024 + HW_WISP_HEADER_LEN;
	cfg.socket_buffer_size = 64 * 1024;
	hw_server *s = e->start(&cfg);
	uint16_t port;
	int lfd = hw_listen_tcp("127.0.0.1", 0, 0, 4, &port);
	CHECK(lfd >= 0, "listen");
	int small = 4096;
	setsockopt(lfd, SOL_SOCKET, SO_RCVBUF, &small, sizeof(small));
	hw_client_opts o;
	e->client_opts(s, &o);
	o.upload_credit = 1;
	o.timeout_ms = 500;
	hw_client *c = ext_connect(&o);
	uint32_t window = hw_client_upload_window(c);
	CHECK(window == 2u * 1024 * 1024 - 64 * 1024 - 4, "window %u", window);
	uint32_t sid;
	CHECK_EQ(hw_client_open(c, HW_STREAM_TCP, "127.0.0.1", port, &sid), 0);
	struct pollfd pfd = {.fd = lfd, .events = POLLIN};
	CHECK_EQ(poll(&pfd, 1, 5000), 1);
	up_sink sink = {.fd = accept(lfd, NULL, NULL)};
	CHECK(sink.fd >= 0, "accept");
	// The drain blocks in recv. Whether accept(2) passes on the listener's O_NONBLOCK depends on the
	// kernel (Linux: no; macOS and Windows: yes), and a sink whose recv says EAGAIN has quit.
	fcntl(sink.fd, F_SETFL, fcntl(sink.fd, F_GETFL, 0) & ~O_NONBLOCK);

	static uint8_t chunk[64 * 1024];
	size_t sent = 0;
	int r;
	for (;;) {
		for (size_t k = 0; k < sizeof(chunk); k++) chunk[k] = up_byte(sent + k);
		r = hw_client_send(c, sid, chunk, sizeof(chunk));
		if (r != 0) break;
		sent += sizeof(chunk);
		CHECK(sent < 64u * 1024 * 1024, "the credit never ran out");
	}
	CHECK_EQ(r, HW_ERR_TIMEOUT);
	CHECK(sent >= window, "sent %zu of a window of %u", sent, window);
	int closed;
	up_quiet(c, sid, 300, &closed);
	CHECK(!closed, "closed inside its credit");

	pthread_t th;
	CHECK_EQ(pthread_create(&th, NULL, up_sink_drain, &sink), 0);
	size_t want = sent + 8u * 1024 * 1024;
	int waits = 0;
	while (sent < want) {
		for (size_t k = 0; k < sizeof(chunk); k++) chunk[k] = up_byte(sent + k);
		r = hw_client_send(c, sid, chunk, sizeof(chunk));
		if (r == HW_ERR_TIMEOUT) { // the client's own 500 ms, while the remote catches up
			CHECK(++waits < 20, "no grant for 10 s: %zu of %zu bytes at the remote", atomic_load(&sink.got), sent);
			continue;
		}
		CHECK_EQ(r, 0);
		waits = 0;
		sent += sizeof(chunk);
	}
	// A CLOSE from the client drops what is still queued toward the remote: wait for all of it,
	// in the client's calls, which are where a WebTransport client sends what it holds.
	for (int i = 0; i < 500 && atomic_load(&sink.got) < sent; i++) {
		hw_client_event ev;
		CHECK(hw_client_poll(c, 10, &ev) == 0, "an event while draining");
	}
	CHECK_EQ(atomic_load(&sink.got), sent);
	CHECK_EQ(hw_client_close_stream(c, sid, HW_CLOSE_VOLUNTARY), 0);
	pthread_join(th, NULL);
	close(sink.fd);
	close(lfd);
	hw_client_free(c);
	hw_server_free(s);
}

// Without both INFOs naming it there is no upload credit, and CONTINUE paces the stream as ever: a
// v2 client that does not ask, a v1 client, and a client asking a server with upload-credit off.
static void upload_credit_not_negotiated(void) {
	const ext_env *e = g_ext;
	hw_server_config cfg;
	e->config(&cfg);
	hw_server *on = e->start(&cfg);
	cfg.upload_credit = 0;
	hw_server *off = e->start(&cfg);
	struct {
		hw_server *s;
		int v2, ask;
	} cases[3] = {{on, 1, 0}, {on, 0, 1}, {off, 1, 1}};
	static uint8_t chunk[256 * 1024], back[256 * 1024];
	memset(chunk, 0x5a, sizeof(chunk));
	for (int i = 0; i < 3; i++) {
		hw_client_opts o;
		e->client_opts(cases[i].s, &o);
		o.v2 = cases[i].v2;
		if (!o.v2) o.wt_lanes = 0;
		o.upload_credit = cases[i].ask;
		hw_client *c = ext_connect(&o);
		CHECK_EQ(hw_client_upload_window(c), 0);
		uint32_t sid;
		CHECK_EQ(hw_client_open(c, HW_STREAM_TCP, "127.0.0.1", e->echo_port, &sid), 0);
		for (int k = 0; k < 40; k++) { // 40 packets, past the window of 16
			CHECK_EQ(hw_client_send(c, sid, chunk, sizeof(chunk)), 0);
			CHECK_EQ(hw_client_read_exact(c, sid, back, sizeof(back), 5000), (long long)sizeof(back));
		}
		int closed;
		CHECK(up_quiet(c, sid, 200, &closed) > 0, "case %d: CONTINUE paces it", i);
		hw_client_free(c);
	}
	hw_server_free(on);
	hw_server_free(off);
}

static void ext_cases_run(const ext_env *e) {
	g_ext = e;
	RUN(limit_offered);
	RUN(limit_none);
	RUN(upload_credit_echo);
	RUN(upload_credit_stalled_remote);
	RUN(upload_credit_not_negotiated);
}

#endif
