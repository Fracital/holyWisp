/*
 * End to end: a real server on an ephemeral port, real echo services, the real client library.
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
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>

// ---------------------------------------------------------------------------------- echo services

static uint16_t g_tcp_echo_port;
static uint16_t g_udp_echo_port;

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

static void *tcp_echo_main(void *arg) {
	int lfd = (int)(intptr_t)arg;
	for (;;) {
		struct pollfd pfd = {.fd = lfd, .events = POLLIN};
		if (poll(&pfd, 1, -1) < 0) continue;
		struct sockaddr_storage ss;
		socklen_t sl = sizeof(ss);
		int fd = accept(lfd, (struct sockaddr *)&ss, &sl);
		if (fd < 0) continue;
		int fl = fcntl(fd, F_GETFL, 0);
		fcntl(fd, F_SETFL, fl & ~O_NONBLOCK);
		pthread_t th;
		pthread_attr_t attr;
		pthread_attr_init(&attr);
		pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
		pthread_create(&th, &attr, tcp_echo_conn, (void *)(intptr_t)fd);
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

static void start_echo_services(void) {
	int lfd = hw_listen_tcp("0.0.0.0", 0, 0, 128, &g_tcp_echo_port);
	CHECK(lfd >= 0, "tcp echo listen: %s", strerror(errno));
	pthread_t th;
	pthread_create(&th, NULL, tcp_echo_main, (void *)(intptr_t)lfd);
	pthread_detach(th);

	int ufd = socket(AF_INET, SOCK_DGRAM, 0);
	CHECK(ufd >= 0, "udp socket: %s", strerror(errno));
	struct sockaddr_in sin = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK), .sin_port = 0};
	CHECK_EQ(bind(ufd, (struct sockaddr *)&sin, sizeof(sin)), 0);
	socklen_t sl = sizeof(sin);
	getsockname(ufd, (struct sockaddr *)&sin, &sl);
	g_udp_echo_port = ntohs(sin.sin_port);
	pthread_create(&th, NULL, udp_echo_main, (void *)(intptr_t)ufd);
	pthread_detach(th);
}

// A port nothing listens on: bind, note the port, close.
static uint16_t closed_port(void) {
	uint16_t port = 0;
	int fd = hw_listen_tcp("127.0.0.1", 0, 0, 1, &port);
	CHECK(fd >= 0, "bind");
	close(fd);
	return port;
}

// ---------------------------------------------------------------------------------- helpers

static hw_server *g_server;

static hw_client *connect_to(hw_server *s, int v2, const char *user, const char *pass, int confirm) {
	hw_client_opts o;
	hw_client_opts_defaults(&o);
	o.host = "127.0.0.1";
	o.port = hw_server_port(s);
	o.v2 = v2;
	o.user = user;
	o.pass = pass;
	o.stream_confirm = confirm;
	o.timeout_ms = 5000;
	char err[256];
	hw_client *c = hw_client_connect(&o, err, sizeof(err));
	CHECK(c != NULL, "connect: %s", err);
	return c;
}

// Wait for the next event on a given stream, queuing the rest.
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

static void wait_streams_idle(hw_server *s) {
	for (int i = 0; i < 200; i++) {
		hw_server_stats st;
		hw_server_stats_get(s, &st);
		if (st.streams_active == 0) return;
		usleep(10000);
	}
	hw_server_stats st;
	hw_server_stats_get(s, &st);
	CHECK(st.streams_active == 0, "streams still active: %llu", (unsigned long long)st.streams_active);
}

// ---------------------------------------------------------------------------------- cases

static void test_v1_tcp_echo_small(void) {
	hw_client *c = connect_to(g_server, 0, NULL, NULL, 0);
	CHECK(!hw_client_is_v2(c), "v1");
	CHECK_EQ(hw_client_buffer_size(c), 16);
	uint32_t sid;
	CHECK_EQ(hw_client_open(c, HW_STREAM_TCP, "127.0.0.1", g_tcp_echo_port, &sid), 0);
	CHECK_EQ(hw_client_send(c, sid, "hello wisp", 10), 0);
	uint8_t buf[10];
	CHECK_EQ(hw_client_read_exact(c, sid, buf, 10, 5000), 10);
	CHECK(memcmp(buf, "hello wisp", 10) == 0, "echo");
	CHECK_EQ(hw_client_close_stream(c, sid, HW_CLOSE_VOLUNTARY), 0);
	hw_client_free(c);
	wait_streams_idle(g_server);
}

static void test_v1_tcp_echo_large(void) {
	hw_client *c = connect_to(g_server, 0, NULL, NULL, 0);
	uint32_t sid;
	CHECK_EQ(hw_client_open(c, HW_STREAM_TCP, "127.0.0.1", g_tcp_echo_port, &sid), 0);
	const size_t total = 6 * 1024 * 1024;
	const size_t chunk = 16 * 1024;
	uint8_t *data = malloc(total);
	uint8_t *back = malloc(total);
	fill_pattern(data, total, 42);
	size_t sent = 0, got = 0;
	int continues = 0;
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
			} else if (ev.type == HW_CEV_CONTINUE) {
				continues++;
			} else {
				CHECK(0, "unexpected event %d on stream %u (reason %u)", ev.type, ev.stream_id, ev.reason);
			}
			if (sent < total || got >= total) break;
		}
		CHECK(r >= 0, "poll: %d", r);
		if (r == 0 && sent >= total) CHECK(0, "timed out with %zu/%zu bytes", got, total);
	}
	CHECK(memcmp(data, back, total) == 0, "6 MiB round trip intact");
	// 384 packets of 16 KiB through a 16-packet window: at least 20 CONTINUEs.
	CHECK(continues >= 20, "flow control exercised: %d CONTINUEs", continues);
	free(data);
	free(back);
	hw_client_free(c);
	wait_streams_idle(g_server);
}

static void test_udp_echo(void) {
	hw_client *c = connect_to(g_server, 0, NULL, NULL, 0);
	uint32_t sid;
	CHECK_EQ(hw_client_open(c, HW_STREAM_UDP, "127.0.0.1", g_udp_echo_port, &sid), 0);
	uint8_t dgram[1200];
	fill_pattern(dgram, sizeof(dgram), 7);
	for (int i = 0; i < 3; i++) CHECK_EQ(hw_client_send(c, sid, dgram, sizeof(dgram)), 0);
	for (int i = 0; i < 3; i++) {
		hw_client_event ev;
		CHECK_EQ(wait_event(c, sid, HW_CEV_DATA, &ev, 5000), 1);
		CHECK_EQ(ev.len, sizeof(dgram));
		CHECK(memcmp(ev.data, dgram, sizeof(dgram)) == 0, "datagram %d intact", i);
	}
	hw_client_free(c);
	wait_streams_idle(g_server);
}

static void test_many_streams_interleaved(void) {
	enum {
		N = 32,
		PER = 64 * 1024,
		CHUNK = 4096
	};
	hw_client *c = connect_to(g_server, 0, NULL, NULL, 0);
	uint32_t sids[N];
	uint8_t *data[N];
	size_t got[N] = {0};
	uint8_t *back = malloc((size_t)N * PER);
	for (int i = 0; i < N; i++) {
		CHECK_EQ(hw_client_open(c, HW_STREAM_TCP, "127.0.0.1", g_tcp_echo_port, &sids[i]), 0);
		data[i] = malloc(PER);
		fill_pattern(data[i], PER, (uint32_t)i + 100);
	}
	size_t sent = 0;
	size_t total_got = 0;
	while (total_got < (size_t)N * PER) {
		if (sent < PER) {
			for (int i = 0; i < N; i++) CHECK_EQ(hw_client_send(c, sids[i], data[i] + sent, CHUNK), 0);
			sent += CHUNK;
		}
		hw_client_event ev;
		int r;
		while ((r = hw_client_poll(c, sent < PER ? 0 : 5000, &ev)) > 0) {
			if (ev.type != HW_CEV_DATA) continue;
			int idx = -1;
			for (int i = 0; i < N; i++) {
				if (sids[i] == ev.stream_id) idx = i;
			}
			CHECK(idx >= 0, "unknown stream %u", ev.stream_id);
			CHECK(got[idx] + ev.len <= PER, "stream %d overflow", idx);
			memcpy(back + (size_t)idx * PER + got[idx], ev.data, ev.len);
			got[idx] += ev.len;
			total_got += ev.len;
			if (sent < PER || total_got >= (size_t)N * PER) break;
		}
		CHECK(r >= 0, "poll");
		if (r == 0 && sent >= PER) CHECK(0, "timeout: %zu of %zu", total_got, (size_t)N * PER);
	}
	for (int i = 0; i < N; i++) {
		CHECK(memcmp(data[i], back + (size_t)i * PER, PER) == 0, "stream %d intact", i);
		free(data[i]);
	}
	free(back);
	hw_server_stats st;
	hw_server_stats_get(g_server, &st);
	CHECK(st.streams_active >= N, "streams open: %llu", (unsigned long long)st.streams_active);
	hw_client_free(c);
	wait_streams_idle(g_server);
}

static void test_remote_eof_closes_stream(void) {
	// A stream to the TCP echo server: when we half-close nothing happens (echo waits), so use
	// a listener that accepts and closes immediately.
	uint16_t port = 0;
	int lfd = hw_listen_tcp("127.0.0.1", 0, 0, 4, &port);
	hw_client *c = connect_to(g_server, 0, NULL, NULL, 0);
	uint32_t sid;
	CHECK_EQ(hw_client_open(c, HW_STREAM_TCP, "127.0.0.1", port, &sid), 0);
	struct pollfd pfd = {.fd = lfd, .events = POLLIN};
	CHECK_EQ(poll(&pfd, 1, 5000), 1);
	int afd = accept(lfd, NULL, NULL);
	CHECK(afd >= 0, "accept");
	CHECK_EQ(write(afd, "bye", 3), 3);
	close(afd);
	uint8_t buf[3];
	CHECK_EQ(hw_client_read_exact(c, sid, buf, 3, 5000), 3);
	hw_client_event ev;
	CHECK_EQ(wait_event(c, sid, HW_CEV_CLOSE, &ev, 5000), 1);
	CHECK_EQ(ev.reason, HW_CLOSE_VOLUNTARY);
	close(lfd);
	hw_client_free(c);
}

static void test_connection_refused(void) {
	hw_client *c = connect_to(g_server, 0, NULL, NULL, 0);
	uint32_t sid;
	CHECK_EQ(hw_client_open(c, HW_STREAM_TCP, "127.0.0.1", closed_port(), &sid), 0);
	hw_client_event ev;
	CHECK_EQ(wait_event(c, sid, HW_CEV_CLOSE, &ev, 5000), 1);
	CHECK_EQ(ev.reason, HW_CLOSE_REFUSED);
	hw_client_free(c);
}

static void test_hostname_resolution(void) {
	// "localhost" goes through the resolver thread pool; the echo server listens on 0.0.0.0,
	// so a ::1 attempt fails and the server must fall back to 127.0.0.1.
	hw_client *c = connect_to(g_server, 0, NULL, NULL, 0);
	uint32_t sid;
	CHECK_EQ(hw_client_open(c, HW_STREAM_TCP, "localhost", g_tcp_echo_port, &sid), 0);
	CHECK_EQ(hw_client_send(c, sid, "named", 5), 0);
	uint8_t buf[5];
	CHECK_EQ(hw_client_read_exact(c, sid, buf, 5, 5000), 5);
	CHECK(memcmp(buf, "named", 5) == 0, "echo via hostname");
	CHECK_EQ(hw_client_open(c, HW_STREAM_TCP, "does-not-exist.invalid", 80, &sid), 0);
	hw_client_event ev;
	CHECK_EQ(wait_event(c, sid, HW_CEV_CLOSE, &ev, 10000), 1);
	CHECK_EQ(ev.reason, HW_CLOSE_UNREACHABLE);
	hw_client_free(c);
	wait_streams_idle(g_server);
}

static void test_invalid_connect(void) {
	hw_client *c = connect_to(g_server, 0, NULL, NULL, 0);
	uint32_t sid;
	// Port 0 is invalid.
	CHECK_EQ(hw_client_open(c, HW_STREAM_TCP, "127.0.0.1", 0, &sid), 0);
	hw_client_event ev;
	CHECK_EQ(wait_event(c, sid, HW_CEV_CLOSE, &ev, 5000), 1);
	CHECK_EQ(ev.reason, HW_CLOSE_INVALID_INFO);
	// Unknown stream type.
	CHECK_EQ(hw_client_open(c, 0x7f, "127.0.0.1", 80, &sid), 0);
	CHECK_EQ(wait_event(c, sid, HW_CEV_CLOSE, &ev, 5000), 1);
	CHECK_EQ(ev.reason, HW_CLOSE_INVALID_INFO);
	// Malformed literal.
	CHECK_EQ(hw_client_open(c, HW_STREAM_TCP, "300.1.1.1", 80, &sid), 0);
	CHECK_EQ(wait_event(c, sid, HW_CEV_CLOSE, &ev, 5000), 1);
	CHECK_EQ(ev.reason, HW_CLOSE_INVALID_INFO);
	hw_client_free(c);
}

static void test_egress_blocked(void) {
	hw_server_config cfg;
	hw_server_config_defaults(&cfg);
	strcpy(cfg.host, "127.0.0.1");
	cfg.port = 0;
	cfg.workers = 1;
	cfg.allow_direct_ip = 1;
	cfg.allow_loopback = 0;
	cfg.log_level = HW_LOG_NONE;
	hw_server *s = hw_server_new(&cfg);
	CHECK(s != NULL, "server");
	CHECK_EQ(hw_server_start(s), 0);
	hw_client *c = connect_to(s, 0, NULL, NULL, 0);
	uint32_t sid;
	hw_client_event ev;
	CHECK_EQ(hw_client_open(c, HW_STREAM_TCP, "127.0.0.1", g_tcp_echo_port, &sid), 0);
	CHECK_EQ(wait_event(c, sid, HW_CEV_CLOSE, &ev, 5000), 1);
	CHECK_EQ(ev.reason, HW_CLOSE_BLOCKED);
	CHECK_EQ(hw_client_open(c, HW_STREAM_TCP, "10.1.2.3", 80, &sid), 0);
	CHECK_EQ(wait_event(c, sid, HW_CEV_CLOSE, &ev, 5000), 1);
	CHECK_EQ(ev.reason, HW_CLOSE_BLOCKED);
	CHECK_EQ(hw_client_open(c, HW_STREAM_TCP, "localhost", g_tcp_echo_port, &sid), 0);
	CHECK_EQ(wait_event(c, sid, HW_CEV_CLOSE, &ev, 5000), 1);
	CHECK_EQ(ev.reason, HW_CLOSE_BLOCKED);
	hw_client_free(c);

	// Direct IPs off entirely.
	hw_server_free(s);
	cfg.allow_direct_ip = 0;
	cfg.allow_loopback = 1;
	s = hw_server_new(&cfg);
	CHECK_EQ(hw_server_start(s), 0);
	c = connect_to(s, 0, NULL, NULL, 0);
	CHECK_EQ(hw_client_open(c, HW_STREAM_TCP, "127.0.0.1", g_tcp_echo_port, &sid), 0);
	CHECK_EQ(wait_event(c, sid, HW_CEV_CLOSE, &ev, 5000), 1);
	CHECK_EQ(ev.reason, HW_CLOSE_BLOCKED);
	CHECK_EQ(hw_client_open(c, HW_STREAM_UDP, "127.0.0.1", g_udp_echo_port, &sid), 0);
	CHECK_EQ(wait_event(c, sid, HW_CEV_CLOSE, &ev, 5000), 1);
	CHECK_EQ(ev.reason, HW_CLOSE_BLOCKED);
	hw_client_free(c);
	hw_server_free(s);
}

static void test_v2_handshake_and_confirm(void) {
	hw_client *c = connect_to(g_server, 1, NULL, NULL, 1);
	CHECK(hw_client_is_v2(c), "v2 negotiated");
	CHECK_STR(hw_client_motd(c), "welcome to the test server");
	CHECK(hw_client_server_has_udp(c), "udp advertised");
	CHECK_EQ(hw_client_buffer_size(c), 16);
	uint32_t sid;
	CHECK_EQ(hw_client_open(c, HW_STREAM_TCP, "127.0.0.1", g_tcp_echo_port, &sid), 0);
	hw_client_event ev;
	CHECK_EQ(wait_event(c, sid, 0, &ev, 5000), 1);
	CHECK_EQ(ev.type, HW_CEV_CONTINUE); // stream confirm: the first thing we hear is CONTINUE
	CHECK_EQ(ev.buffer_remaining, 16);
	CHECK_EQ(hw_client_send(c, sid, "v2", 2), 0);
	uint8_t buf[2];
	CHECK_EQ(hw_client_read_exact(c, sid, buf, 2, 5000), 2);
	CHECK(memcmp(buf, "v2", 2) == 0, "echo over v2");
	hw_client_free(c);
	wait_streams_idle(g_server);
}

static void test_v2_password_auth(void) {
	hw_server_config cfg;
	hw_server_config_defaults(&cfg);
	strcpy(cfg.host, "127.0.0.1");
	cfg.port = 0;
	cfg.workers = 1;
	cfg.allow_direct_ip = 1;
	cfg.allow_loopback = 1;
	cfg.password_required = 1;
	cfg.log_level = HW_LOG_NONE;
	CHECK_EQ(hw_server_config_add_user(&cfg, "alice", "s3cret"), 0);
	hw_server *s = hw_server_new(&cfg);
	CHECK(s != NULL, "server");
	CHECK_EQ(hw_server_start(s), 0);

	hw_client_opts o;
	hw_client_opts_defaults(&o);
	o.host = "127.0.0.1";
	o.port = hw_server_port(s);
	o.timeout_ms = 5000;
	char err[256];
	// v1 is refused outright when auth is required.
	CHECK(hw_client_connect(&o, err, sizeof(err)) == NULL, "v1 rejected");
	// v2 without credentials.
	o.v2 = 1;
	CHECK(hw_client_connect(&o, err, sizeof(err)) == NULL, "no creds rejected");
	CHECK(strstr(err, "authentication required") != NULL, "reason: %s", err);
	// Wrong password.
	o.user = "alice";
	o.pass = "wrong";
	CHECK(hw_client_connect(&o, err, sizeof(err)) == NULL, "bad password rejected");
	CHECK(strstr(err, "bad password") != NULL, "reason: %s", err);
	// Unknown user.
	o.user = "bob";
	o.pass = "s3cret";
	CHECK(hw_client_connect(&o, err, sizeof(err)) == NULL, "unknown user rejected");
	// Right credentials.
	o.user = "alice";
	o.pass = "s3cret";
	hw_client *c = hw_client_connect(&o, err, sizeof(err));
	CHECK(c != NULL, "auth ok: %s", err);
	uint32_t sid;
	CHECK_EQ(hw_client_open(c, HW_STREAM_TCP, "127.0.0.1", g_tcp_echo_port, &sid), 0);
	CHECK_EQ(hw_client_send(c, sid, "auth", 4), 0);
	uint8_t buf[4];
	CHECK_EQ(hw_client_read_exact(c, sid, buf, 4, 5000), 4);
	hw_client_free(c);
	hw_server_free(s);
}

static void test_plain_http(void) {
	int fd = hw_connect_tcp("127.0.0.1", hw_server_port(g_server), 2000);
	CHECK(fd >= 0, "connect");
	const char *req = "GET /health HTTP/1.1\r\nHost: x\r\n\r\n";
	CHECK_EQ(write(fd, req, strlen(req)), (ssize_t)strlen(req));
	char buf[1024];
	size_t n = 0;
	for (;;) {
		ssize_t r = read(fd, buf + n, sizeof(buf) - 1 - n);
		if (r <= 0) break;
		n += (size_t)r;
	}
	buf[n] = '\0';
	CHECK(strncmp(buf, "HTTP/1.1 200 OK", 15) == 0, "status: %.20s", buf);
	CHECK(strstr(buf, "{\"status\":\"ok\"}") != NULL, "body: %s", buf);
	close(fd);

	fd = hw_connect_tcp("127.0.0.1", hw_server_port(g_server), 2000);
	const char *bad = "garbage\r\n\r\n";
	CHECK_EQ(write(fd, bad, strlen(bad)), (ssize_t)strlen(bad));
	n = 0;
	for (;;) {
		ssize_t r = read(fd, buf + n, sizeof(buf) - 1 - n);
		if (r <= 0) break;
		n += (size_t)r;
	}
	buf[n] = '\0';
	CHECK(strncmp(buf, "HTTP/1.1 400", 12) == 0, "status: %.20s", buf);
	close(fd);
}

static void test_connection_counts(void) {
	hw_server_stats before, after;
	hw_server_stats_get(g_server, &before);
	hw_client *a = connect_to(g_server, 0, NULL, NULL, 0);
	hw_client *b = connect_to(g_server, 1, NULL, NULL, 0);
	hw_server_stats_get(g_server, &after);
	CHECK_EQ(after.connections_active, before.connections_active + 2);
	CHECK_EQ(after.connections_total, before.connections_total + 2);
	hw_client_free(a);
	hw_client_free(b);
	for (int i = 0; i < 200; i++) {
		hw_server_stats_get(g_server, &after);
		if (after.connections_active == before.connections_active) break;
		usleep(10000);
	}
	CHECK_EQ(after.connections_active, before.connections_active);
	CHECK(after.bytes_in > 0 && after.bytes_out > 0, "byte counters moved");
}

int main(void) {
	start_echo_services();
	hw_server_config cfg;
	hw_server_config_defaults(&cfg);
	strcpy(cfg.host, "127.0.0.1");
	cfg.port = 0;
	cfg.workers = 2;
	cfg.allow_direct_ip = 1;
	cfg.allow_loopback = 1;
	cfg.buffer_remaining = 16;
	strcpy(cfg.motd, "welcome to the test server");
	cfg.log_level = HW_LOG_WARN;
	g_server = hw_server_new(&cfg);
	CHECK(g_server != NULL, "server: %s", strerror(errno));
	CHECK_EQ(hw_server_start(g_server), 0);
	CHECK(hw_server_port(g_server) != 0, "ephemeral port");

	RUN(test_v1_tcp_echo_small);
	RUN(test_v1_tcp_echo_large);
	RUN(test_udp_echo);
	RUN(test_many_streams_interleaved);
	RUN(test_remote_eof_closes_stream);
	RUN(test_connection_refused);
	RUN(test_hostname_resolution);
	RUN(test_invalid_connect);
	RUN(test_egress_blocked);
	RUN(test_v2_handshake_and_confirm);
	RUN(test_v2_password_auth);
	RUN(test_plain_http);
	RUN(test_connection_counts);

	hw_server_stop(g_server);
	hw_server_free(g_server);
	printf("ok shutdown\n");
	return 0;
}
