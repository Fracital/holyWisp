/*
 * End to end for the security features: host/port filters, per-source connect throttle, the
 * concurrent-connection cap, crypt(3) password auth, reputation accrual, upstream SOCKS5 and HTTP
 * CONNECT proxies, and a Twisp terminal stream. A real server, real helper services, the real
 * client library.
 */
#include "holywisp/client.h"
#include "holywisp/hw.h"
#include "holywisp/log.h"
#include "holywisp/net.h"
#include "holywisp/reputation.h"
#include "holywisp/server.h"
#include "holywisp/wisp.h"

#include "test.h"

#include <crypt.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>

static uint16_t g_echo_port;

// ---------------------------------------------------------------------------------- helpers

static void set_blocking(int fd) {
	int fl = fcntl(fd, F_GETFL, 0);
	fcntl(fd, F_SETFL, fl & ~O_NONBLOCK);
}

// Read exactly n bytes or fail: loopback sends can split, so fixed-size proxy reads must loop.
static int read_full(int fd, void *buf, size_t n) {
	size_t got = 0;
	while (got < n) {
		ssize_t r = read(fd, (char *)buf + got, n - got);
		if (r <= 0) return -1;
		got += (size_t)r;
	}
	return 0;
}

static int read_line(int fd, char *buf, size_t cap) {
	size_t n = 0;
	while (n + 1 < cap) {
		char ch;
		ssize_t r = read(fd, &ch, 1);
		if (r <= 0) return -1;
		buf[n++] = ch;
		if (ch == '\n') break;
	}
	buf[n] = '\0';
	return (int)n;
}

static void splice_pair(int a, int b) {
	struct pollfd pfds[2] = {{.fd = a, .events = POLLIN}, {.fd = b, .events = POLLIN}};
	uint8_t buf[16384];
	for (;;) {
		if (poll(pfds, 2, 5000) <= 0) break;
		for (int i = 0; i < 2; i++) {
			if (!(pfds[i].revents & POLLIN)) continue;
			int from = i == 0 ? a : b, to = i == 0 ? b : a;
			ssize_t r = read(from, buf, sizeof(buf));
			if (r <= 0) return;
			ssize_t off = 0;
			while (off < r) {
				ssize_t w = write(to, buf + off, (size_t)(r - off));
				if (w <= 0) return;
				off += w;
			}
		}
	}
}

// TCP echo service.
static void *echo_conn(void *arg) {
	int fd = (int)(intptr_t)arg;
	uint8_t buf[16384];
	for (;;) {
		ssize_t n = read(fd, buf, sizeof(buf));
		if (n <= 0) break;
		ssize_t off = 0;
		while (off < n) {
			ssize_t w = write(fd, buf + off, (size_t)(n - off));
			if (w <= 0) {
				close(fd);
				return NULL;
			}
			off += w;
		}
	}
	close(fd);
	return NULL;
}

static void *echo_main(void *arg) {
	int lfd = (int)(intptr_t)arg;
	for (;;) {
		int fd = accept(lfd, NULL, NULL);
		if (fd < 0) continue;
		set_blocking(fd);
		pthread_t th;
		pthread_attr_t attr;
		pthread_attr_init(&attr);
		pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
		pthread_create(&th, &attr, echo_conn, (void *)(intptr_t)fd);
		pthread_attr_destroy(&attr);
	}
	return NULL;
}

static uint16_t start_listener(void (*fn)(void), int *out_fd) {
	(void)fn;
	uint16_t port = 0;
	int fd = hw_listen_tcp("127.0.0.1", 0, 0, 64, &port);
	CHECK(fd >= 0, "listen");
	*out_fd = fd;
	return port;
}

// Minimal HTTP CONNECT proxy: read the request head, reply 200, splice to the target.
static void *http_proxy_main(void *arg) {
	int lfd = (int)(intptr_t)arg;
	for (;;) {
		int fd = accept(lfd, NULL, NULL);
		if (fd < 0) {
			if (errno == EINVAL || errno == EBADF) return NULL; // listener shut down
			continue;
		}
		set_blocking(fd);
		char line[512], first[512] = "";
		int got_first = 0;
		while (read_line(fd, line, sizeof(line)) > 0) {
			if (!got_first) {
				snprintf(first, sizeof(first), "%s", line);
				got_first = 1;
			}
			if (!strcmp(line, "\r\n") || !strcmp(line, "\n")) break;
		}
		char method[16], target[256];
		if (sscanf(first, "%15s %255s", method, target) != 2 || strcmp(method, "CONNECT") != 0) {
			close(fd);
			continue;
		}
		char host[256];
		int port = 0;
		char *colon = strrchr(target, ':');
		if (colon) {
			*colon = '\0';
			port = (int)strtol(colon + 1, NULL, 10);
		}
		snprintf(host, sizeof(host), "%s", target);
		int up = hw_connect_tcp(host, (uint16_t)port, 2000);
		if (up < 0) {
			const char *resp = "HTTP/1.1 502 Bad Gateway\r\n\r\n";
			ssize_t r = write(fd, resp, strlen(resp));
			(void)r;
			close(fd);
			continue;
		}
		const char *ok = "HTTP/1.1 200 Connection Established\r\n\r\n";
		ssize_t r = write(fd, ok, strlen(ok));
		(void)r;
		splice_pair(fd, up);
		close(fd);
		close(up);
	}
	return NULL;
}

// Minimal SOCKS5 proxy: no-auth greeting, CONNECT to an IPv4/IPv6 literal, splice.
static void *socks5_proxy_main(void *arg) {
	int lfd = (int)(intptr_t)arg;
	for (;;) {
		int fd = accept(lfd, NULL, NULL);
		if (fd < 0) {
			if (errno == EINVAL || errno == EBADF) return NULL; // listener shut down
			continue;
		}
		set_blocking(fd);
		uint8_t greet[2];
		if (read_full(fd, greet, 2) != 0 || greet[0] != 5) {
			close(fd);
			continue;
		}
		uint8_t nmethods = greet[1];
		uint8_t methods[255];
		if (read_full(fd, methods, nmethods) != 0) {
			close(fd);
			continue;
		}
		uint8_t choose[2] = {5, 0}; // no auth
		ssize_t r = write(fd, choose, 2);
		(void)r;
		uint8_t req[4];
		if (read_full(fd, req, 4) != 0 || req[1] != 1) {
			close(fd);
			continue;
		}
		char host[128];
		uint16_t port = 0;
		if (req[3] == 1) {
			uint8_t a[4], p[2];
			if (read_full(fd, a, 4) != 0 || read_full(fd, p, 2) != 0) {
				close(fd);
				continue;
			}
			snprintf(host, sizeof(host), "%u.%u.%u.%u", a[0], a[1], a[2], a[3]);
			port = (uint16_t)(p[0] << 8 | p[1]);
		} else if (req[3] == 4) {
			uint8_t a[16], p[2];
			if (read_full(fd, a, 16) != 0 || read_full(fd, p, 2) != 0) {
				close(fd);
				continue;
			}
			inet_ntop(AF_INET6, a, host, sizeof(host));
			port = (uint16_t)(p[0] << 8 | p[1]);
		} else {
			close(fd);
			continue;
		}
		int up = hw_connect_tcp(host, port, 2000);
		uint8_t reply[10] = {5, up < 0 ? 5 : 0, 0, 1, 0, 0, 0, 0, 0, 0};
		r = write(fd, reply, sizeof(reply));
		(void)r;
		if (up < 0) {
			close(fd);
			continue;
		}
		splice_pair(fd, up);
		close(fd);
		close(up);
	}
	return NULL;
}

static void spawn(void *(*fn)(void *), int fd) {
	pthread_t th;
	pthread_create(&th, NULL, fn, (void *)(intptr_t)fd);
	pthread_detach(th);
}

static void base_config(hw_server_config *cfg) {
	hw_server_config_defaults(cfg);
	snprintf(cfg->host, sizeof(cfg->host), "127.0.0.1");
	cfg->port = 0;
	cfg->workers = 1;
	cfg->allow_direct_ip = 1;
	cfg->allow_loopback = 1;
	cfg->buffer_remaining = 16;
	cfg->reputation_enabled = 0; // most cases do not want reputation side effects
	cfg->log_level = HW_LOG_ERROR;
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

static int wait_close(hw_client *c, uint32_t sid, uint8_t *reason) {
	hw_client_event ev;
	for (int i = 0; i < 200; i++) {
		int r = hw_client_poll(c, 5000, &ev);
		if (r <= 0) return 0;
		if (ev.stream_id == sid && ev.type == HW_CEV_CLOSE) {
			*reason = ev.reason;
			return 1;
		}
	}
	return 0;
}

static int echo_once(hw_client *c, uint32_t sid, const char *msg) {
	if (hw_client_send(c, sid, msg, strlen(msg)) != 0) return 0;
	uint8_t buf[64];
	long n = hw_client_read_exact(c, sid, buf, strlen(msg), 5000);
	return n == (long)strlen(msg) && memcmp(buf, msg, strlen(msg)) == 0;
}

// ---------------------------------------------------------------------------------- cases

static void test_port_filter(void) {
	hw_server_config cfg;
	base_config(&cfg);
	char spec[16];
	snprintf(spec, sizeof(spec), "%u", g_echo_port);
	CHECK_EQ(hw_portset_add(&cfg.block_ports, spec), 0);
	hw_server *s = hw_server_new(&cfg);
	CHECK(s != NULL, "server");
	hw_server_start(s);
	hw_client *c = connect_plain(s);
	uint32_t sid;
	CHECK_EQ(hw_client_open(c, HW_STREAM_TCP, "127.0.0.1", g_echo_port, &sid), 0);
	uint8_t reason = 0;
	CHECK(wait_close(c, sid, &reason), "got close");
	CHECK_EQ(reason, HW_CLOSE_BLOCKED);
	hw_client_free(c);
	hw_server_free(s);
}

static void test_host_filter(void) {
	hw_server_config cfg;
	base_config(&cfg);
	CHECK_EQ(hw_hostlist_add(&cfg.block_hosts, "127.0.0.1"), 0);
	hw_server *s = hw_server_new(&cfg);
	hw_server_start(s);
	hw_client *c = connect_plain(s);
	uint32_t sid;
	CHECK_EQ(hw_client_open(c, HW_STREAM_TCP, "127.0.0.1", g_echo_port, &sid), 0);
	uint8_t reason = 0;
	CHECK(wait_close(c, sid, &reason), "got close");
	CHECK_EQ(reason, HW_CLOSE_BLOCKED);
	hw_client_free(c);
	hw_server_free(s);
}

static void test_per_source_throttle(void) {
	hw_server_config cfg;
	base_config(&cfg);
	cfg.flood.enabled = 1;
	cfg.flood.max_connects_per_source_per_second = 2;
	cfg.flood.ws_close_after_violations = 0; // don't drop the WS, just throttle the stream
	cfg.flood.max_connects_per_dest_per_second = 0;
	cfg.flood.max_connects_per_dest_per_minute = 0;
	cfg.flood.syn_signature_enabled = 0;
	hw_server *s = hw_server_new(&cfg);
	hw_server_start(s);
	hw_client *c = connect_plain(s);
	// First two CONNECTs pass; the third trips the per-source rate.
	int throttled = 0;
	for (int i = 0; i < 3; i++) {
		uint32_t sid;
		CHECK_EQ(hw_client_open(c, HW_STREAM_TCP, "127.0.0.1", g_echo_port, &sid), 0);
		if (i == 2) {
			uint8_t reason = 0;
			CHECK(wait_close(c, sid, &reason), "third closes");
			throttled = reason == HW_CLOSE_THROTTLED;
		}
	}
	CHECK(throttled, "third CONNECT throttled");
	hw_server_stats st;
	hw_server_stats_get(s, &st);
	CHECK(st.throttled_source >= 1, "stat recorded");
	hw_client_free(c);
	hw_server_free(s);
}

static void test_concurrent_cap(void) {
	hw_server_config cfg;
	base_config(&cfg);
	cfg.flood.enabled = 1;
	cfg.flood.max_concurrent_connections = 1;
	hw_server *s = hw_server_new(&cfg);
	hw_server_start(s);
	hw_client *a = connect_plain(s);
	// The second upgrade is refused at capacity: the client sees the connection fail.
	hw_client_opts o;
	hw_client_opts_defaults(&o);
	o.host = "127.0.0.1";
	o.port = hw_server_port(s);
	o.timeout_ms = 2000;
	char err[256];
	hw_client *b = hw_client_connect(&o, err, sizeof(err));
	CHECK(b == NULL, "second client refused at capacity");
	hw_client_free(a);
	// With the first gone, a new client gets the slot.
	hw_client *c = hw_client_connect(&o, err, sizeof(err));
	CHECK(c != NULL, "slot freed: %s", err);
	hw_client_free(c);
	hw_server_free(s);
}

static void test_password_crypt(void) {
	hw_server_config cfg;
	base_config(&cfg);
	cfg.password_required = 1;
	// A real crypt(3) SHA-512 hash of "hunter2".
	struct crypt_data data;
	memset(&data, 0, sizeof(data));
	const char *hash = crypt_r("hunter2", "$6$holywispsalt$", &data);
	CHECK(hash && hash[0] == '$', "made a hash");
	CHECK_EQ(hw_server_config_add_user(&cfg, "alice", hash), 0);
	hw_server *s = hw_server_new(&cfg);
	CHECK(s != NULL, "server");
	hw_server_start(s);

	hw_client_opts o;
	hw_client_opts_defaults(&o);
	o.host = "127.0.0.1";
	o.port = hw_server_port(s);
	o.v2 = 1;
	o.timeout_ms = 5000;
	char err[256];

	o.user = "alice";
	o.pass = "wrong";
	CHECK(hw_client_connect(&o, err, sizeof(err)) == NULL, "wrong password rejected");

	o.pass = "hunter2";
	hw_client *c = hw_client_connect(&o, err, sizeof(err));
	CHECK(c != NULL, "hashed password accepted: %s", err);
	uint32_t sid;
	CHECK_EQ(hw_client_open(c, HW_STREAM_TCP, "127.0.0.1", g_echo_port, &sid), 0);
	CHECK(echo_once(c, sid, "hashed"), "echo after auth");
	hw_client_free(c);
	hw_server_free(s);
}

static void test_reputation_accrual(void) {
	hw_server_config cfg;
	base_config(&cfg);
	cfg.reputation_enabled = 1;
	cfg.reputation.store_path[0] = '\0'; // memory only
	cfg.password_required = 1;
	cfg.password_user_count = 0;
	CHECK_EQ(hw_server_config_add_user(&cfg, "bob", "pw"), 0);
	hw_server *s = hw_server_new(&cfg);
	hw_server_start(s);

	hw_client_opts o;
	hw_client_opts_defaults(&o);
	o.host = "127.0.0.1";
	o.port = hw_server_port(s);
	o.v2 = 1;
	o.user = "bob";
	o.pass = "nope";
	o.timeout_ms = 2000;
	char err[256];
	for (int i = 0; i < 3; i++) {
		hw_client *c = hw_client_connect(&o, err, sizeof(err));
		if (c) hw_client_free(c);
	}
	// Auth failures raised the client's reputation score.
	hw_reputation *rep = hw_server_reputation(s);
	CHECK(rep != NULL, "reputation live");
	CHECK(hw_reputation_source_score(rep, "127.0.0.1") > 0, "score accrued from auth failures");
	hw_server_stats st;
	hw_server_stats_get(s, &st);
	CHECK(st.auth_failures >= 3, "auth failures counted");
	hw_server_free(s);
}

static void proxy_echo_case(const char *scheme, void *(*proxy_fn)(void *)) {
	int pfd;
	uint16_t pport = start_listener(NULL, &pfd);
	spawn(proxy_fn, pfd);

	hw_server_config cfg;
	base_config(&cfg);
	snprintf(cfg.proxy, sizeof(cfg.proxy), "%s://127.0.0.1:%u", scheme, pport);
	hw_server *s = hw_server_new(&cfg);
	CHECK(s != NULL, "%s: server", scheme);
	hw_server_start(s);
	hw_client *c = connect_plain(s);
	uint32_t sid;
	CHECK_EQ(hw_client_open(c, HW_STREAM_TCP, "127.0.0.1", g_echo_port, &sid), 0);
	CHECK(echo_once(c, sid, "through-the-proxy"), "%s: echo via proxy", scheme);
	hw_client_free(c);
	hw_server_free(s);
	shutdown(pfd, SHUT_RDWR); // wake the proxy thread's blocked accept(2) so it exits
	close(pfd);
}

static void test_http_proxy(void) {
	proxy_echo_case("http", http_proxy_main);
}

static void test_socks5_proxy(void) {
	proxy_echo_case("socks5", socks5_proxy_main);
}

static void test_twisp(void) {
	hw_server_config cfg;
	base_config(&cfg);
	cfg.enable_twisp = 1;
	CHECK_EQ(hw_server_config_add_user(&cfg, "op", "pw"), 0);
	hw_server *s = hw_server_new(&cfg);
	CHECK(s != NULL, "server");
	hw_server_start(s);

	// Without auth the terminal stream is refused.
	hw_client *plain = connect_plain(s);
	uint32_t sid;
	CHECK_EQ(hw_client_open(plain, HW_STREAM_TERM, "cat", 0, &sid), 0);
	uint8_t reason = 0;
	CHECK(wait_close(plain, sid, &reason), "term refused without auth");
	CHECK_EQ(reason, HW_CLOSE_BLOCKED);
	hw_client_free(plain);

	// Authenticated: run `cat` on a PTY and read an echoed line back.
	hw_client_opts o;
	hw_client_opts_defaults(&o);
	o.host = "127.0.0.1";
	o.port = hw_server_port(s);
	o.v2 = 1;
	o.user = "op";
	o.pass = "pw";
	o.timeout_ms = 5000;
	char err[256];
	hw_client *c = hw_client_connect(&o, err, sizeof(err));
	CHECK(c != NULL, "auth: %s", err);
	CHECK_EQ(hw_client_open(c, HW_STREAM_TERM, "cat", 0, &sid), 0);
	CHECK_EQ(hw_client_send(c, sid, "ping\n", 5), 0);
	// A PTY in cooked mode echoes the input and `cat` writes it again; either way "ping" arrives.
	uint8_t buf[256];
	int found = 0;
	for (int i = 0; i < 50 && !found; i++) {
		hw_client_event ev;
		int r = hw_client_poll(c, 5000, &ev);
		if (r <= 0) break;
		if (ev.type == HW_CEV_DATA && ev.stream_id == sid) {
			if (ev.len <= sizeof(buf) && memmem(ev.data, ev.len, "ping", 4)) found = 1;
		} else if (ev.type == HW_CEV_CLOSE) {
			break;
		}
	}
	CHECK(found, "terminal echoed input");
	hw_client_close_stream(c, sid, HW_CLOSE_VOLUNTARY);
	hw_client_free(c);
	hw_server_free(s);
}

int main(void) {
	int echo_fd;
	g_echo_port = start_listener(NULL, &echo_fd);
	spawn(echo_main, echo_fd);

	RUN(test_port_filter);
	RUN(test_host_filter);
	RUN(test_per_source_throttle);
	RUN(test_concurrent_cap);
	RUN(test_password_crypt);
	RUN(test_reputation_accrual);
	RUN(test_http_proxy);
	RUN(test_socks5_proxy);
	RUN(test_twisp);
	printf("ok all security cases\n");
	return 0;
}
