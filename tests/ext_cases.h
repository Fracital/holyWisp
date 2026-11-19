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
#include "holywisp/server.h"
#include "holywisp/wisp.h"

#include "test.h"

#include <stdint.h>
#include <string.h>

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

static void ext_cases_run(const ext_env *e) {
	g_ext = e;
	RUN(limit_offered);
	RUN(limit_none);
}

#endif
