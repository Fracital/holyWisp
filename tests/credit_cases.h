/*
 * tests/credit_cases.h - stream credit end to end, the same cases over both transports: included
 * by test_e2e.c (WebSocket) and test_e2e_wt.c (WebTransport, the held and the busy stream on one
 * lane of several), each with its own way to connect. The services it needs are its own: a remote
 * that sends without end, and two that send a fixed number of bytes and close.
 */
#ifndef HOLYWISP_TESTS_CREDIT_CASES_H
#define HOLYWISP_TESTS_CREDIT_CASES_H

#include "holywisp/client.h"
#include "holywisp/hw.h"
#include "holywisp/net.h"
#include "holywisp/server.h"
#include "holywisp/sys.h"
#include "holywisp/wisp.h"

#include "test.h"

#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <unistd.h>

#include <sys/socket.h>

#define CREDIT_SMALL (40 * 1000)       // what the small source sends before it closes
#define CREDIT_LARGE (8 * 1024 * 1024) // ... and the large one

typedef struct credit_env {
	hw_server *server;     // stream-credit on, as by default
	hw_server *server_off; // stream-credit off
	uint16_t echo_port;    // TCP echo
	uint16_t udp_echo_port;
	// A client of s: v2 unless v2 is 0, naming stream credit with window (0: not), granting by
	// itself unless manual, with max_queue (0: the default).
	hw_client *(*open_client)(hw_server *s, int v2, uint32_t window, int manual, size_t max_queue);
	int lanes; // the transport has lanes: put the held stream and the busy one on the same lane
} credit_env;

static const credit_env *g_credit;
static uint16_t g_credit_blast_port, g_credit_small_port, g_credit_large_port;

// The byte at offset i of what a source sends.
static uint8_t credit_byte(size_t i) {
	return (uint8_t)(i % 251);
}

// n bytes of stream sid that the source sent from offset off.
static void credit_check_bytes(uint32_t sid, const uint8_t *p, size_t n, size_t off) {
	size_t i = 0;
	while (i < n && p[i] == credit_byte(off + i)) i++;
	CHECK(i == n, "stream %u byte %zu: %u", sid, off + i, i < n ? p[i] : 0);
}

typedef struct credit_service {
	int lfd;
	size_t bytes; // 0: without end
} credit_service;

typedef struct credit_conn {
	int fd;
	size_t bytes;
} credit_conn;

static void *credit_conn_main(void *arg) {
	credit_conn *cc = arg;
	uint8_t buf[65536];
	size_t off = 0;
	for (;;) {
		size_t n = sizeof(buf);
		if (cc->bytes && cc->bytes - off < n) n = cc->bytes - off;
		if (n == 0) break;
		for (size_t i = 0; i < n; i++) buf[i] = credit_byte(off + i);
		ssize_t w = send(cc->fd, buf, n, HW_MSG_NOSIGNAL);
		if (w <= 0) break;
		off += (size_t)w;
	}
	close(cc->fd);
	free(cc);
	return NULL;
}

static void *credit_accept_main(void *arg) {
	const credit_service *svc = arg;
	for (;;) {
		struct pollfd pfd = {.fd = svc->lfd, .events = POLLIN};
		if (poll(&pfd, 1, -1) < 0) continue;
		int fd = accept(svc->lfd, NULL, NULL);
		if (fd < 0) continue;
		int fl = fcntl(fd, F_GETFL, 0);
		fcntl(fd, F_SETFL, fl & ~O_NONBLOCK);
		credit_conn *cc = malloc(sizeof(*cc));
		CHECK(cc != NULL, "malloc");
		cc->fd = fd;
		cc->bytes = svc->bytes;
		pthread_t th;
		pthread_attr_t attr;
		pthread_attr_init(&attr);
		pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
		pthread_create(&th, &attr, credit_conn_main, cc);
		pthread_attr_destroy(&attr);
	}
	return NULL;
}

static uint16_t credit_service_start(size_t bytes) {
	static credit_service services[3];
	static int n;
	credit_service *svc = &services[n++];
	uint16_t port = 0;
	svc->lfd = hw_listen_tcp("127.0.0.1", 0, 0, 64, &port);
	CHECK(svc->lfd >= 0, "listen");
	svc->bytes = bytes;
	pthread_t th;
	pthread_create(&th, NULL, credit_accept_main, svc);
	pthread_detach(th);
	return port;
}

// Take every event until none has come for quiet_ms: the DATA bytes of stream sid (checked as the
// source sends them, from offset base), and whether (and why) it closed. Events of other streams
// are taken and dropped.
static size_t credit_drain(hw_client *c, uint32_t sid, size_t base, int quiet_ms, int *closed, uint8_t *reason) {
	size_t got = 0;
	hw_client_event ev;
	*closed = 0;
	for (;;) {
		int r = hw_client_poll(c, quiet_ms, &ev);
		CHECK(r >= 0, "poll %d", r);
		if (r == 0) return got;
		if (ev.stream_id != sid) continue;
		if (ev.type == HW_CEV_DATA) {
			credit_check_bytes(sid, ev.data, ev.len, base + got);
			got += ev.len;
		}
		if (ev.type == HW_CEV_CLOSE) {
			*closed = 1;
			if (reason) *reason = ev.reason;
			return got;
		}
	}
}

// One stream that nobody reads and one that is busy, on the same connection and lane: the unread
// one is sent exactly its window and stops there, and the busy one goes on as if it were alone.
// Without credit the unread one's remote filled the client's queue (and over WebTransport its
// lane's), which failed the busy one. A grant lets exactly that much more through; a repeated or a
// lower one, or one where it cannot apply, does nothing.
static void credit_holds_one_stream(void) {
	const credit_env *e = g_credit;
	hw_client *c = e->open_client(e->server, 1, 65536, 1, 4 * 1024 * 1024);
	CHECK_EQ(hw_client_credit_window(c), 65536);
	uint32_t held, busy, other = 0;
	CHECK_EQ(hw_client_open(c, HW_STREAM_TCP, "127.0.0.1", g_credit_blast_port, &held), 0);
	if (e->lanes) {
		// Lane by lane, fewest open first: held on 0, other on 1, busy on 0 again.
		CHECK(hw_client_lanes(c) >= 2, "lanes: %d", hw_client_lanes(c));
		CHECK_EQ(hw_client_open(c, HW_STREAM_TCP, "127.0.0.1", e->echo_port, &other), 0);
	}
	CHECK_EQ(hw_client_open(c, HW_STREAM_TCP, "127.0.0.1", e->echo_port, &busy), 0);
	CHECK_EQ(hw_client_stream_lane(c, held), hw_client_stream_lane(c, busy));
	CHECK_EQ(hw_client_credit(c, busy, UINT64_MAX / 2), 0);

	static uint8_t chunk[65536], back[65536];
	for (int i = 0; i < 256; i++) { // 16 MiB each way through the busy stream
		for (size_t k = 0; k < sizeof(chunk); k++) chunk[k] = (uint8_t)(k * 7 + (size_t)i);
		CHECK_EQ(hw_client_send(c, busy, chunk, sizeof(chunk)), 0);
		CHECK_EQ(hw_client_read_exact(c, busy, back, sizeof(back), 5000), (long long)sizeof(back));
		CHECK(memcmp(chunk, back, sizeof(chunk)) == 0, "echo %d", i);
	}
	int closed;
	size_t got = credit_drain(c, held, 0, 300, &closed, NULL);
	CHECK_EQ(got, 65536);
	CHECK(!closed, "the held stream closed");

	CHECK_EQ(hw_client_credit(c, held, 65536 + 100000), 0);
	CHECK_EQ(hw_client_credit(c, held, 65536 + 50000), 0); // one sent earlier that arrives later
	got += credit_drain(c, held, got, 300, &closed, NULL);
	CHECK_EQ(got, 65536 + 100000);
	CHECK(!closed, "the held stream closed");
	CHECK_EQ(hw_client_credit(c, held, 65536 + 100000), 0); // again
	CHECK_EQ(hw_client_credit(c, held, 0), 0);
	CHECK_EQ(hw_client_credit(c, 0, UINT64_MAX), 0);    // stream 0
	CHECK_EQ(hw_client_credit(c, 9999, UINT64_MAX), 0); // a stream that is not open
	CHECK_EQ(credit_drain(c, held, got, 300, &closed, NULL), 0);
	CHECK(!closed, "the held stream closed");

	// A UDP stream is never counted: more than a window comes back without a grant, and a CREDIT
	// for it changes nothing.
	uint32_t udp;
	CHECK_EQ(hw_client_open(c, HW_STREAM_UDP, "127.0.0.1", e->udp_echo_port, &udp), 0);
	CHECK_EQ(hw_client_credit(c, udp, 1), 0);
	size_t udp_back = 0;
	for (int i = 0; i < 80; i++) { // 80000 bytes
		CHECK_EQ(hw_client_send(c, udp, chunk, 1000), 0);
		CHECK_EQ(hw_client_read_exact(c, udp, back, 1000, 5000), 1000);
		udp_back += 1000;
	}
	CHECK(udp_back > 65536, "udp %zu", udp_back);

	// The connection is as good as before, and the held stream still holds.
	CHECK_EQ(hw_client_send(c, busy, "again", 5), 0);
	CHECK_EQ(hw_client_read_exact(c, busy, back, 5, 5000), 5);
	CHECK_EQ(credit_drain(c, held, got, 100, &closed, NULL), 0);
	if (other) CHECK_EQ(hw_client_close_stream(c, other, HW_CLOSE_VOLUNTARY), 0);
	hw_client_free(c);
}

// The server learns of the remote's end by reading, so a stream at its limit sends its CLOSE only
// once a grant lets it read again: here even when the grant is exactly what the remote sent, the
// end waits for the next one. A window under the smallest is the smallest.
static void credit_eof_after_grant(void) {
	const credit_env *e = g_credit;
	hw_client *c = e->open_client(e->server, 1, 1000, 1, 0);
	CHECK_EQ(hw_client_credit_window(c), HW_WISP_CREDIT_MIN);
	uint32_t sid;
	CHECK_EQ(hw_client_open(c, HW_STREAM_TCP, "127.0.0.1", g_credit_small_port, &sid), 0);
	int closed;
	uint8_t reason = 0;
	size_t got = credit_drain(c, sid, 0, 500, &closed, NULL);
	CHECK_EQ(got, HW_WISP_CREDIT_MIN);
	CHECK(!closed, "closed before its bytes were granted");

	CHECK_EQ(hw_client_credit(c, sid, CREDIT_SMALL), 0);
	got += credit_drain(c, sid, got, 300, &closed, NULL);
	CHECK_EQ(got, CREDIT_SMALL);
	CHECK(!closed, "closed at its limit before a grant");

	CHECK_EQ(hw_client_credit(c, sid, CREDIT_SMALL + 1), 0);
	CHECK_EQ(credit_drain(c, sid, got, 2000, &closed, &reason), 0);
	CHECK(closed, "no CLOSE after the grant");
	CHECK_EQ(reason, HW_CLOSE_VOLUNTARY);
	hw_client_free(c);
}

// The library's own grants: a window past what its caller took, once half a window is taken,
// whether the caller takes by polling (two streams at once) or by reading one stream.
static void credit_auto_grants(void) {
	const credit_env *e = g_credit;
	hw_client *c = e->open_client(e->server, 1, 65536, 0, 0);
	CHECK_EQ(hw_client_credit_window(c), 65536);
	uint32_t sid[2];
	size_t got[2] = {0, 0};
	int closed[2] = {0, 0};
	for (int k = 0; k < 2; k++) {
		CHECK_EQ(hw_client_open(c, HW_STREAM_TCP, "127.0.0.1", g_credit_large_port, &sid[k]), 0);
	}
	uint64_t until = hw_now_ms() + 20000;
	while ((!closed[0] || !closed[1]) && hw_now_ms() < until) {
		hw_client_event ev;
		int r = hw_client_poll(c, 1000, &ev);
		CHECK(r > 0, "poll %d", r);
		int k = ev.stream_id == sid[0] ? 0 : 1;
		CHECK(ev.stream_id == sid[k], "stream %u", ev.stream_id);
		if (ev.type == HW_CEV_DATA) {
			credit_check_bytes(sid[k], ev.data, ev.len, got[k]);
			got[k] += ev.len;
		} else if (ev.type == HW_CEV_CLOSE) {
			CHECK_EQ(ev.reason, HW_CLOSE_VOLUNTARY);
			closed[k] = 1;
		}
	}
	CHECK(got[0] == CREDIT_LARGE && got[1] == CREDIT_LARGE, "%zu and %zu bytes", got[0], got[1]);

	static uint8_t buf[CREDIT_LARGE];
	uint32_t one;
	CHECK_EQ(hw_client_open(c, HW_STREAM_TCP, "127.0.0.1", g_credit_large_port, &one), 0);
	CHECK_EQ(hw_client_read_exact(c, one, buf, sizeof(buf), 20000), (long long)sizeof(buf));
	credit_check_bytes(one, buf, sizeof(buf), 0);
	hw_client_event ev;
	CHECK_EQ(hw_client_poll(c, 5000, &ev), 1);
	CHECK(ev.stream_id == one && ev.type == HW_CEV_CLOSE && ev.reason == HW_CLOSE_VOLUNTARY, "the end");
	hw_client_free(c);
}

// Without both INFOs naming it there is no stream credit, and a stream the client grants nothing
// still gets everything: a v2 client that does not ask, a v1 client (no INFO), and a client that
// asks a server with stream-credit off (which leaves 0xE2 out of its INFO, so the client does not
// name it).
static void credit_not_negotiated(void) {
	const credit_env *e = g_credit;
	struct {
		hw_server *s;
		int v2;
		uint32_t window;
	} cases[3] = {{e->server, 1, 0}, {e->server, 0, 65536}, {e->server_off, 1, 65536}};
	for (int i = 0; i < 3; i++) {
		hw_client *c = e->open_client(cases[i].s, cases[i].v2, cases[i].window, 1, 0);
		CHECK_EQ(hw_client_is_v2(c), cases[i].v2);
		CHECK_EQ(hw_client_credit_window(c), 0);
		uint32_t sid;
		CHECK_EQ(hw_client_open(c, HW_STREAM_TCP, "127.0.0.1", g_credit_large_port, &sid), 0);
		CHECK_EQ(hw_client_credit(c, sid, 1), HW_ERR_INVALID);
		int closed;
		uint8_t reason = 0;
		CHECK_EQ(credit_drain(c, sid, 0, 2000, &closed, &reason), CREDIT_LARGE);
		CHECK(closed && reason == HW_CLOSE_VOLUNTARY, "case %d: the end (%d, 0x%02x)", i, closed, reason);
		hw_client_free(c);
	}
}

static void credit_cases_run(const credit_env *e) {
	g_credit = e;
	if (!g_credit_blast_port) {
		g_credit_blast_port = credit_service_start(0);
		g_credit_small_port = credit_service_start(CREDIT_SMALL);
		g_credit_large_port = credit_service_start(CREDIT_LARGE);
	}
	RUN(credit_holds_one_stream);
	RUN(credit_eof_after_grant);
	RUN(credit_auto_grants);
	RUN(credit_not_negotiated);
}

#endif
