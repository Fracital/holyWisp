/*
 * End to end for the security features: host/port filters, per-source connect throttle, the
 * concurrent-connection cap, crypt(3) password auth, reputation accrual, upstream SOCKS5 and HTTP
 * CONNECT proxies, and a Twisp terminal stream. A real server, real helper services, the real
 * client library.
 */
#include "holywisp/client.h"
#include "holywisp/filter.h"
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
#include <netdb.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>

static uint16_t g_echo_port;
static uint16_t g_udp_echo_port;

// What the toy SOCKS5 proxy last saw in a CONNECT request, and how many it has handled. The edge
// deployments put a classifying SOCKS5 router upstream that needs the hostname (ATYP 3), so the
// address type the server sends is part of the contract.
static _Atomic int g_socks5_requests;
static _Atomic int g_socks5_atyp;
static char g_socks5_host[256];
static _Atomic int g_socks5_reply_delay_ms; // sleep before the CONNECT reply (a slow upstream dial)

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

static uint16_t start_udp_echo(void) {
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	CHECK(fd >= 0, "udp socket: %s", strerror(errno));
	struct sockaddr_in sin = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK), .sin_port = 0};
	CHECK_EQ(bind(fd, (struct sockaddr *)&sin, sizeof(sin)), 0);
	socklen_t sl = sizeof(sin);
	getsockname(fd, (struct sockaddr *)&sin, &sl);
	pthread_t th;
	pthread_create(&th, NULL, udp_echo_main, (void *)(intptr_t)fd);
	pthread_detach(th);
	return ntohs(sin.sin_port);
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
// Each accepted connection is handled on its own detached thread (accept_loop below), so a slow
// handshake never blocks the next connection. That keeps the proxy e2e tests from serializing
// retries behind a straggler under CPU contention.
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
			if (errno == EINVAL || errno == EBADF) return NULL; // listener shut down
			continue;
		}
		spawn_detached(handler, fd);
	}
}

static void *http_proxy_conn(void *arg) {
	int fd = (int)(intptr_t)arg;
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
		return NULL;
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
		return NULL;
	}
	const char *ok = "HTTP/1.1 200 Connection Established\r\n\r\n";
	ssize_t r = write(fd, ok, strlen(ok));
	(void)r;
	splice_pair(fd, up);
	close(fd);
	close(up);
	return NULL;
}

static void *http_proxy_main(void *arg) {
	return accept_loop((int)(intptr_t)arg, http_proxy_conn);
}

// Minimal SOCKS5 proxy: no-auth greeting, CONNECT to an IPv4/IPv6 literal, splice.
static void *socks5_proxy_conn(void *arg) {
	int fd = (int)(intptr_t)arg;
	set_blocking(fd);
	uint8_t greet[2];
	if (read_full(fd, greet, 2) != 0 || greet[0] != 5) {
		close(fd);
		return NULL;
	}
	uint8_t nmethods = greet[1];
	uint8_t methods[255];
	if (read_full(fd, methods, nmethods) != 0) {
		close(fd);
		return NULL;
	}
	uint8_t choose[2] = {5, 0}; // no auth
	ssize_t r = write(fd, choose, 2);
	(void)r;
	uint8_t req[4];
	if (read_full(fd, req, 4) != 0 || req[1] != 1) {
		close(fd);
		return NULL;
	}
	char host[256];
	uint16_t port = 0;
	uint8_t p[2];
	if (req[3] == 1) {
		uint8_t a[4];
		if (read_full(fd, a, 4) != 0 || read_full(fd, p, 2) != 0) {
			close(fd);
			return NULL;
		}
		snprintf(host, sizeof(host), "%u.%u.%u.%u", a[0], a[1], a[2], a[3]);
	} else if (req[3] == 4) {
		uint8_t a[16];
		if (read_full(fd, a, 16) != 0 || read_full(fd, p, 2) != 0) {
			close(fd);
			return NULL;
		}
		inet_ntop(AF_INET6, a, host, sizeof(host));
	} else if (req[3] == 3) {
		uint8_t len;
		if (read_full(fd, &len, 1) != 0 || read_full(fd, host, len) != 0 || read_full(fd, p, 2) != 0) {
			close(fd);
			return NULL;
		}
		host[len] = '\0';
	} else {
		close(fd);
		return NULL;
	}
	port = (uint16_t)(p[0] << 8 | p[1]);
	atomic_store(&g_socks5_atyp, req[3]);
	snprintf(g_socks5_host, sizeof(g_socks5_host), "%s", host);
	atomic_fetch_add(&g_socks5_requests, 1);
	int delay = atomic_load(&g_socks5_reply_delay_ms);
	if (delay > 0) usleep((useconds_t)delay * 1000);
	// A hostname is resolved here, by the proxy, the way a socks5h proxy does.
	int up = -1;
	struct addrinfo hints = {.ai_socktype = SOCK_STREAM}, *res = NULL;
	char service[8];
	snprintf(service, sizeof(service), "%u", port);
	if (getaddrinfo(host, service, &hints, &res) == 0) {
		for (struct addrinfo *ai = res; ai && up < 0; ai = ai->ai_next) {
			char ip[HW_IP_STR_LEN];
			hw_addr_ip_str(ai->ai_addr, ip, sizeof(ip));
			up = hw_connect_tcp(ip, port, 2000);
		}
		freeaddrinfo(res);
	}
	uint8_t reply[10] = {5, up < 0 ? 5 : 0, 0, 1, 0, 0, 0, 0, 0, 0};
	r = write(fd, reply, sizeof(reply));
	(void)r;
	if (up < 0) {
		close(fd);
		return NULL;
	}
	splice_pair(fd, up);
	close(fd);
	close(up);
	return NULL;
}

static void *socks5_proxy_main(void *arg) {
	return accept_loop((int)(intptr_t)arg, socks5_proxy_conn);
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

static int echo_once_t(hw_client *c, uint32_t sid, const char *msg, int timeout_ms) {
	if (hw_client_send(c, sid, msg, strlen(msg)) != 0) return 0;
	uint8_t buf[64];
	long n = hw_client_read_exact(c, sid, buf, strlen(msg), timeout_ms);
	return n == (long)strlen(msg) && memcmp(buf, msg, strlen(msg)) == 0;
}

static int echo_once(hw_client *c, uint32_t sid, const char *msg) {
	return echo_once_t(c, sid, msg, 10000);
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
	// The in-process toy proxy and echo run on their own threads; under heavy CPU contention the
	// proxy's handshake reply can lag a single relay attempt. Retry the whole connection a few
	// times (each on a fresh server connection) before failing, so the suite is not scheduling
	// sensitive. The server relays correctly; this only absorbs thread starvation in the harness.
	int ok = 0;
	for (int attempt = 0; attempt < 4 && !ok; attempt++) {
		hw_client *c = connect_plain(s);
		uint32_t sid;
		if (hw_client_open(c, HW_STREAM_TCP, "127.0.0.1", g_echo_port, &sid) == 0 &&
		    echo_once_t(c, sid, "through-the-proxy", 4000)) {
			ok = 1;
		}
		hw_client_free(c);
	}
	CHECK(ok, "%s: echo via proxy", scheme);
	hw_server_free(s);
	shutdown(pfd, SHUT_RDWR); // wake the proxy thread's blocked accept(2) so it exits
	close(pfd);
}

static void test_http_proxy(void) {
	proxy_echo_case("http", http_proxy_main);
}

static void test_socks5_proxy(void) {
	proxy_echo_case("socks5", socks5_proxy_main);
	CHECK_EQ(atomic_load(&g_socks5_atyp), 1); // a literal IP goes as ATYP 1, never as a domain
}

// The upstream SOCKS5 router classifies destinations by name, so a hostname must reach it as an
// ATYP 3 domain, unresolved, and `socks5h://` (what the wispurr deployments use) must be accepted.
// A literal IP still goes as ATYP 1, and the egress policy still runs on what the name resolves
// to locally: a blocked destination never reaches the proxy at all.
static void test_socks5_proxy_hostname(void) {
	int pfd;
	uint16_t pport = start_listener(NULL, &pfd);
	spawn(socks5_proxy_main, pfd);

	hw_server_config cfg;
	base_config(&cfg);
	snprintf(cfg.proxy, sizeof(cfg.proxy), "socks5h://127.0.0.1:%u", pport);
	hw_server *s = hw_server_new(&cfg);
	CHECK(s != NULL, "server with socks5h://");
	hw_server_start(s);
	hw_client *c = connect_plain(s);
	uint32_t sid;
	CHECK_EQ(hw_client_open(c, HW_STREAM_TCP, "localhost", g_echo_port, &sid), 0);
	CHECK(echo_once(c, sid, "by-name-through-the-proxy"), "echo via proxy by hostname");
	CHECK_EQ(atomic_load(&g_socks5_atyp), 3);
	CHECK_STR(g_socks5_host, "localhost");
	hw_client_free(c);
	hw_server_free(s);

	// Egress policy still applies before the proxy sees anything.
	int before = atomic_load(&g_socks5_requests);
	cfg.allow_loopback = 0;
	s = hw_server_new(&cfg);
	CHECK(s != NULL, "server");
	hw_server_start(s);
	c = connect_plain(s);
	CHECK_EQ(hw_client_open(c, HW_STREAM_TCP, "localhost", g_echo_port, &sid), 0);
	uint8_t reason = 0;
	CHECK_EQ(wait_close(c, sid, &reason), 1);
	CHECK_EQ(reason, HW_CLOSE_BLOCKED);
	CHECK_EQ(atomic_load(&g_socks5_requests), before);
	hw_client_free(c);
	hw_server_free(s);
	shutdown(pfd, SHUT_RDWR);
	close(pfd);
}

// wispurr 0001: DATA that arrives while the upstream dial is still in flight. The proxy sits on
// its CONNECT reply, so the burst lands on a stream whose socket is not writable yet; all of it
// must be queued and written in order once the tunnel is up.
static void test_data_queued_during_proxy_connect(void) {
	int pfd;
	uint16_t pport = start_listener(NULL, &pfd);
	spawn(socks5_proxy_main, pfd);

	hw_server_config cfg;
	base_config(&cfg);
	cfg.buffer_remaining = 64;
	snprintf(cfg.proxy, sizeof(cfg.proxy), "socks5://127.0.0.1:%u", pport);
	hw_server *s = hw_server_new(&cfg);
	CHECK(s != NULL, "server");
	hw_server_start(s);
	atomic_store(&g_socks5_reply_delay_ms, 300);
	hw_client *c = connect_plain(s);
	uint32_t sid;
	CHECK_EQ(hw_client_open(c, HW_STREAM_TCP, "127.0.0.1", g_echo_port, &sid), 0);
	enum {
		N = 40
	};
	uint8_t data[N * 1500];
	for (size_t i = 0; i < sizeof(data); i++) data[i] = (uint8_t)(i * 31 + 7);
	size_t total = 0;
	for (int i = 0; i < N; i++) {
		size_t len = 1 + (size_t)(i * 53) % 1400;
		CHECK_EQ(hw_client_send(c, sid, data + total, len), 0);
		total += len;
	}
	uint8_t back[sizeof(data)];
	CHECK_EQ(hw_client_read_exact(c, sid, back, total, 10000), (long)total);
	CHECK(memcmp(data, back, total) == 0, "burst during the proxy handshake intact and in order");
	atomic_store(&g_socks5_reply_delay_ms, 0);
	hw_client_free(c);
	hw_server_free(s);
	shutdown(pfd, SHUT_RDWR);
	close(pfd);
}

// With a proxy configured, UDP is refused by default (the proxy cannot carry it) and relayed
// directly when the operator asks for it with proxy-udp = direct.
static void test_udp_with_proxy(void) {
	int pfd;
	uint16_t pport = start_listener(NULL, &pfd);
	spawn(socks5_proxy_main, pfd);

	hw_server_config cfg;
	base_config(&cfg);
	snprintf(cfg.proxy, sizeof(cfg.proxy), "socks5://127.0.0.1:%u", pport);
	hw_server *s = hw_server_new(&cfg);
	CHECK(s != NULL, "server");
	hw_server_start(s);
	hw_client *c = connect_plain(s);
	uint32_t sid;
	CHECK_EQ(hw_client_open(c, HW_STREAM_UDP, "127.0.0.1", g_udp_echo_port, &sid), 0);
	uint8_t reason = 0;
	CHECK_EQ(wait_close(c, sid, &reason), 1);
	CHECK_EQ(reason, HW_CLOSE_BLOCKED);
	hw_client_free(c);
	hw_server_free(s);

	cfg.proxy_udp_direct = 1;
	s = hw_server_new(&cfg);
	CHECK(s != NULL, "server with proxy-udp = direct");
	hw_server_start(s);
	c = connect_plain(s);
	CHECK_EQ(hw_client_open(c, HW_STREAM_UDP, "127.0.0.1", g_udp_echo_port, &sid), 0);
	const char dgram[] = "datagram around the proxy";
	CHECK_EQ(hw_client_send(c, sid, dgram, sizeof(dgram)), 0);
	hw_client_event ev;
	int got = 0;
	for (int i = 0; i < 20 && !got; i++) {
		int r = hw_client_poll(c, 5000, &ev);
		CHECK(r > 0, "poll: %d", r);
		if (ev.stream_id == sid && ev.type == HW_CEV_DATA) {
			CHECK_EQ(ev.len, sizeof(dgram));
			CHECK(memcmp(ev.data, dgram, sizeof(dgram)) == 0, "datagram intact");
			got = 1;
		}
	}
	CHECK(got, "udp echo direct while tcp goes through the proxy");
	hw_client_free(c);
	hw_server_free(s);
	shutdown(pfd, SHUT_RDWR);
	close(pfd);
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
	g_udp_echo_port = start_udp_echo();

	RUN(test_port_filter);
	RUN(test_host_filter);
	RUN(test_per_source_throttle);
	RUN(test_concurrent_cap);
	RUN(test_password_crypt);
	RUN(test_reputation_accrual);
	RUN(test_http_proxy);
	RUN(test_socks5_proxy);
	RUN(test_socks5_proxy_hostname);
	RUN(test_data_queued_during_proxy_connect);
	RUN(test_udp_with_proxy);
	RUN(test_twisp);
	printf("ok all security cases\n");
	return 0;
}
