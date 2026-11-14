/*
 * UDP on WARP (udp-warp-marks, udp-warp-state): the state file as the server tracks it, and what a
 * UDP stream gets from it end to end. TCP dialled by the server itself (tcp-warp) the same way,
 * where what a missing state means is tcp-warp-fallback's, not "unmarked".
 *
 * Marking a socket takes CAP_NET_ADMIN, which a test does not have, so the server it starts has
 * marking off (warp_on 0: the startup probe got EPERM) and these cases switch it on by hand, as if
 * the probe had passed. A stream then really calls hw_sys_set_mark: as root the mark takes (and
 * with no policy route for it the datagram still reaches loopback); otherwise it is refused, and
 * that is the "cannot mark" path, which follows udp-warp-fallback like "no healthy tunnel" does.
 */
#include "holywisp/client.h"
#include "holywisp/hw.h"
#include "holywisp/log.h"
#include "holywisp/server.h"
#include "holywisp/sys.h"
#include "holywisp/wisp.h"

#include "server/internal.h"
#include "test.h"

#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <utime.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>

static uint16_t g_udp_echo_port;
static uint16_t g_tcp_echo_port;
static char g_state[256];
static int g_can_mark; // this process may mark sockets: the server's marks take

static void *udp_echo_main(void *arg) {
	int fd = (int)(intptr_t)arg;
	uint8_t buf[2048];
	for (;;) {
		struct sockaddr_storage ss;
		socklen_t sl = sizeof(ss);
		ssize_t n = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr *)&ss, &sl);
		if (n < 0) continue;
		sendto(fd, buf, (size_t)n, 0, (struct sockaddr *)&ss, sl);
	}
	return NULL;
}

static void start_udp_echo(void) {
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	CHECK(fd >= 0, "udp socket: %s", strerror(errno));
	struct sockaddr_in sin = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK), .sin_port = 0};
	CHECK_EQ(bind(fd, (struct sockaddr *)&sin, sizeof(sin)), 0);
	socklen_t sl = sizeof(sin);
	getsockname(fd, (struct sockaddr *)&sin, &sl);
	g_udp_echo_port = ntohs(sin.sin_port);
	pthread_t th;
	pthread_create(&th, NULL, udp_echo_main, (void *)(intptr_t)fd);
	pthread_detach(th);
}

static void *tcp_echo_conn(void *arg) {
	int fd = (int)(intptr_t)arg;
	char buf[4096];
	ssize_t n;
	while ((n = read(fd, buf, sizeof(buf))) > 0) {
		if (write(fd, buf, (size_t)n) != n) break;
	}
	close(fd);
	return NULL;
}

static void *tcp_echo_main(void *arg) {
	int lfd = (int)(intptr_t)arg;
	for (;;) {
		int fd = accept(lfd, NULL, NULL);
		if (fd < 0) continue;
		pthread_t th;
		pthread_create(&th, NULL, tcp_echo_conn, (void *)(intptr_t)fd);
		pthread_detach(th);
	}
	return NULL;
}

static void start_tcp_echo(void) {
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	CHECK(fd >= 0, "tcp socket: %s", strerror(errno));
	struct sockaddr_in sin = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK), .sin_port = 0};
	CHECK_EQ(bind(fd, (struct sockaddr *)&sin, sizeof(sin)), 0);
	CHECK_EQ(listen(fd, 64), 0);
	socklen_t sl = sizeof(sin);
	getsockname(fd, (struct sockaddr *)&sin, &sl);
	g_tcp_echo_port = ntohs(sin.sin_port);
	pthread_t th;
	pthread_create(&th, NULL, tcp_echo_main, (void *)(intptr_t)fd);
	pthread_detach(th);
}

// The state file, replaced the way the router replaces it: written aside, then renamed over.
static void write_state(const char *json) {
	char tmp[300];
	snprintf(tmp, sizeof(tmp), "%s.tmp", g_state);
	FILE *f = fopen(tmp, "w");
	CHECK(f != NULL, "fopen %s: %s", tmp, strerror(errno));
	fputs(json, f);
	fclose(f);
	CHECK_EQ(rename(tmp, g_state), 0);
}

static void age_state(int seconds) {
	struct utimbuf t;
	t.actime = t.modtime = time(NULL) - seconds;
	CHECK_EQ(utime(g_state, &t), 0);
}

static void base_config(hw_server_config *cfg, int fallback_direct) {
	hw_server_config_defaults(cfg);
	snprintf(cfg->host, sizeof(cfg->host), "127.0.0.1");
	cfg->port = 0;
	cfg->workers = 2;
	cfg->allow_direct_ip = 1;
	cfg->allow_loopback = 1;
	cfg->reputation_enabled = 0;
	cfg->flood.enabled = 0;
	cfg->log_level = HW_LOG_NONE;
	CHECK_EQ(hw_warp_marks_parse("0x7701,0x7702,0x7703,0x7704", cfg->udp_warp_marks, HW_WARP_MAX_TUNNELS), 4);
	cfg->udp_warp_mark_count = 4;
	snprintf(cfg->udp_warp_state, sizeof(cfg->udp_warp_state), "%s", g_state);
	cfg->udp_warp_fallback_direct = fallback_direct;
}

// A server whose marking is on, as if it had CAP_NET_ADMIN, with the state file read once.
static hw_server *warp_server(int fallback_direct) {
	hw_server_config cfg;
	base_config(&cfg, fallback_direct);
	hw_server *s = hw_server_new(&cfg);
	CHECK(s != NULL, "server");
	CHECK_EQ(s->warp_on, g_can_mark); // the startup probe says what this process may do
	s->warp_on = 1;
	server_warp_refresh(s, 0);
	return s;
}

// Every worker holds the same view: NULL, or n4/n6 tunnels.
static void check_workers(hw_server *s, int present, int n4, int n6) {
	for (int i = 0; i < s->nworkers; i++) {
		const hw_warp_state *w = s->workers[i].warp;
		CHECK(present ? w != NULL : w == NULL, "worker %d: state %s", i, w ? "present" : "absent");
		if (present && w) {
			CHECK_EQ(w->n4, n4);
			CHECK_EQ(w->n6, n6);
		}
	}
}

static const char *const STATE_TWO =
    "{\"v4\": [{\"name\": \"warp0\", \"mark\": 30465}, {\"name\": \"warp1\", \"mark\": 30466},"
    " {\"name\": \"rogue\", \"mark\": 1}], \"v6\": [{\"name\": \"warp0\", \"mark\": 30465}]}";

static void test_unprivileged_start(void) {
	// Without the capability the server still starts, with marking off: its UDP is as it was.
	hw_server_config cfg;
	base_config(&cfg, 0);
	hw_server *s = hw_server_new(&cfg);
	CHECK(s != NULL, "a server with udp-warp-marks and no capability starts");
	CHECK_EQ(s->warp_on, g_can_mark);
	hw_server_free(s);

	// Half the pair is a config error, wherever it runs.
	base_config(&cfg, 0);
	cfg.udp_warp_state[0] = '\0';
	char err[256];
	CHECK_EQ(hw_server_config_validate(&cfg, err, sizeof(err)), -1);
	base_config(&cfg, 0);
	cfg.udp_warp_mark_count = 0;
	CHECK_EQ(hw_server_config_validate(&cfg, err, sizeof(err)), -1);
}

static void test_state_tracking(void) {
	unlink(g_state);
	hw_server *s = warp_server(0);
	check_workers(s, 0, 0, 0); // missing: unmarked

	write_state(STATE_TWO);
	server_warp_refresh(s, 0);
	check_workers(s, 1, 2, 1); // the rogue mark is not one of udp-warp-marks

	// A rewrite within the same second is still seen: it is another file.
	write_state("{\"v4\": [{\"name\": \"warp3\", \"mark\": 30468}]}");
	server_warp_refresh(s, 0);
	check_workers(s, 1, 1, 0);
	CHECK_STR(s->workers[0].warp->v4[0].name, "warp3");

	// Not rewritten for longer than the max age: the router is not running. Unmarked.
	age_state(61);
	server_warp_refresh(s, 0);
	check_workers(s, 0, 0, 0);
	s->cfg.udp_warp_state_max_age_s = 0; // never too old
	server_warp_refresh(s, 0);
	check_workers(s, 1, 1, 0);
	s->cfg.udp_warp_state_max_age_s = 60;

	// Malformed: unmarked, never half read.
	write_state("{\"v4\": [{\"name\": \"warp0\", \"mark\": 30465}");
	server_warp_refresh(s, 0);
	check_workers(s, 0, 0, 0);

	write_state(STATE_TWO);
	server_warp_refresh(s, 0);
	check_workers(s, 1, 2, 1);
	unlink(g_state);
	server_warp_refresh(s, 0);
	check_workers(s, 0, 0, 0);
	hw_server_free(s);
}

// One stream of this type to its echo service, by literal IP. 1 when the bytes came back, 0 when
// the stream was closed (its reason in *reason).
static int roundtrip(hw_server *s, uint8_t type, uint8_t *reason) {
	hw_client_opts o;
	hw_client_opts_defaults(&o);
	o.host = "127.0.0.1";
	o.port = hw_server_port(s);
	o.timeout_ms = 5000;
	char err[256];
	hw_client *c = hw_client_connect(&o, err, sizeof(err));
	CHECK(c != NULL, "connect: %s", err);
	if (!c) return 0;
	uint32_t sid;
	CHECK_EQ(hw_client_open(c, type, "127.0.0.1", type == HW_STREAM_UDP ? g_udp_echo_port : g_tcp_echo_port, &sid), 0);
	CHECK_EQ(hw_client_send(c, sid, "ping", 4), 0);
	int got = 0;
	*reason = 0;
	uint64_t deadline = hw_now_ms() + 5000;
	while (hw_now_ms() < deadline) {
		hw_client_event ev;
		int r = hw_client_poll(c, 200, &ev);
		if (r < 0) break;
		if (r == 0 || ev.stream_id != sid) continue;
		if (ev.type == HW_CEV_DATA) {
			got = ev.len == 4 && memcmp(ev.data, "ping", 4) == 0;
			break;
		}
		if (ev.type == HW_CEV_CLOSE) {
			*reason = ev.reason;
			break;
		}
	}
	hw_client_free(c);
	return got;
}

static int udp_roundtrip(hw_server *s, uint8_t *reason) {
	return roundtrip(s, HW_STREAM_UDP, reason);
}

static void stats(hw_server *s, hw_server_stats *st) {
	// The stream's counters are bumped on its worker; give them a moment to show.
	usleep(20000);
	hw_server_stats_get(s, st);
}

static void test_udp_streams(void) {
	uint8_t reason;
	hw_server_stats st;

	// No state file: unmarked, whatever the fallback says.
	unlink(g_state);
	hw_server *s = warp_server(0);
	CHECK_EQ(hw_server_start(s), 0);
	CHECK_EQ(udp_roundtrip(s, &reason), 1);
	stats(s, &st);
	CHECK_EQ(st.udp_warp_direct, 1);
	CHECK_EQ(st.udp_warp_marked + st.udp_warp_refused, 0);
	hw_server_free(s);

	// A stale one: the same.
	write_state(STATE_TWO);
	age_state(120);
	s = warp_server(0);
	CHECK_EQ(hw_server_start(s), 0);
	CHECK_EQ(udp_roundtrip(s, &reason), 1);
	stats(s, &st);
	CHECK_EQ(st.udp_warp_direct, 1);
	hw_server_free(s);

	// A healthy IPv4 tunnel and fallback refuse: marked where the mark takes, refused where it
	// cannot be set.
	write_state(STATE_TWO);
	s = warp_server(0);
	CHECK_EQ(hw_server_start(s), 0);
	int ok = udp_roundtrip(s, &reason);
	stats(s, &st);
	if (g_can_mark) {
		CHECK_EQ(ok, 1);
		CHECK_EQ(st.udp_warp_marked, 1);
	} else {
		CHECK_EQ(ok, 0);
		CHECK_EQ(reason, HW_CLOSE_UNREACHABLE);
		CHECK_EQ(st.udp_warp_refused, 1);
	}
	hw_server_free(s);

	// The same with fallback direct: it goes out, marked or not.
	s = warp_server(1);
	CHECK_EQ(hw_server_start(s), 0);
	CHECK_EQ(udp_roundtrip(s, &reason), 1);
	stats(s, &st);
	CHECK_EQ(g_can_mark ? st.udp_warp_marked : st.udp_warp_direct, 1);
	hw_server_free(s);

	// Tunnels only for IPv6 and an IPv4 destination: no tunnel for its family, whatever this
	// process may do. Refuse refuses it; direct sends it unmarked.
	write_state("{\"v4\": [], \"v6\": [{\"name\": \"warp0\", \"mark\": 30465}]}");
	s = warp_server(0);
	CHECK_EQ(hw_server_start(s), 0);
	CHECK_EQ(udp_roundtrip(s, &reason), 0);
	CHECK_EQ(reason, HW_CLOSE_UNREACHABLE);
	stats(s, &st);
	CHECK_EQ(st.udp_warp_refused, 1);
	hw_server_free(s);
	s = warp_server(1);
	CHECK_EQ(hw_server_start(s), 0);
	CHECK_EQ(udp_roundtrip(s, &reason), 1);
	stats(s, &st);
	CHECK_EQ(st.udp_warp_direct, 1);
	CHECK_EQ(st.udp_warp_refused, 0);
	hw_server_free(s);
	unlink(g_state);
}

// A server whose TCP is dialled here and marked (tcp-warp), with marking on as in warp_server.
static hw_server *tcp_warp_server(int fallback_direct) {
	hw_server_config cfg;
	base_config(&cfg, 0);
	cfg.tcp_warp = 1;
	cfg.tcp_warp_fallback_direct = fallback_direct;
	hw_server *s = hw_server_new(&cfg);
	CHECK(s != NULL, "server");
	s->warp_on = 1;
	server_warp_refresh(s, 0);
	return s;
}

static void test_tcp_streams(void) {
	uint8_t reason;
	hw_server_stats st;

	// No state: the router is not there to say which tunnel, so the fallback decides. Refuse is
	// 0x42; direct sends it unmarked. UDP on the same server stays unmarked whatever TCP does.
	unlink(g_state);
	hw_server *s = tcp_warp_server(0);
	CHECK_EQ(hw_server_start(s), 0);
	CHECK_EQ(roundtrip(s, HW_STREAM_TCP, &reason), 0);
	CHECK_EQ(reason, HW_CLOSE_UNREACHABLE);
	CHECK_EQ(udp_roundtrip(s, &reason), 1);
	stats(s, &st);
	CHECK_EQ(st.tcp_warp_refused, 1);
	CHECK_EQ(st.tcp_warp_marked + st.tcp_warp_direct, 0);
	CHECK_EQ(st.syn_signatures, 0); // no SYN went out: nothing for the signature
	CHECK_EQ(st.udp_warp_direct, 1);
	hw_server_free(s);
	s = tcp_warp_server(1);
	CHECK_EQ(hw_server_start(s), 0);
	CHECK_EQ(roundtrip(s, HW_STREAM_TCP, &reason), 1);
	stats(s, &st);
	CHECK_EQ(st.tcp_warp_direct, 1);
	hw_server_free(s);

	// A stale state is no state.
	write_state(STATE_TWO);
	age_state(120);
	s = tcp_warp_server(0);
	CHECK_EQ(hw_server_start(s), 0);
	CHECK_EQ(roundtrip(s, HW_STREAM_TCP, &reason), 0);
	CHECK_EQ(reason, HW_CLOSE_UNREACHABLE);
	hw_server_free(s);

	// A healthy IPv4 tunnel: marked where the mark takes; where it cannot be set, the fallback.
	write_state(STATE_TWO);
	s = tcp_warp_server(0);
	CHECK_EQ(hw_server_start(s), 0);
	int ok = roundtrip(s, HW_STREAM_TCP, &reason);
	stats(s, &st);
	if (g_can_mark) {
		CHECK_EQ(ok, 1);
		CHECK_EQ(st.tcp_warp_marked, 1);
	} else {
		CHECK_EQ(ok, 0);
		CHECK_EQ(reason, HW_CLOSE_UNREACHABLE);
		CHECK_EQ(st.tcp_warp_refused, 1);
	}
	hw_server_free(s);

	// Tunnels for IPv6 only and an IPv4 destination.
	write_state("{\"v4\": [], \"v6\": [{\"name\": \"warp0\", \"mark\": 30465}]}");
	s = tcp_warp_server(0);
	CHECK_EQ(hw_server_start(s), 0);
	CHECK_EQ(roundtrip(s, HW_STREAM_TCP, &reason), 0);
	CHECK_EQ(reason, HW_CLOSE_UNREACHABLE);
	hw_server_free(s);
	unlink(g_state);

	// The config: tcp-warp takes its tunnels from udp-warp, and with a proxy it needs
	// proxy-only-to, or there would be no TCP dialled here to mark.
	hw_server_config cfg;
	char err[256];
	base_config(&cfg, 0);
	cfg.tcp_warp = 1;
	CHECK_EQ(hw_server_config_validate(&cfg, err, sizeof(err)), 0);
	cfg.udp_warp_mark_count = 0;
	cfg.udp_warp_state[0] = '\0';
	CHECK_EQ(hw_server_config_validate(&cfg, err, sizeof(err)), -1);
	base_config(&cfg, 0);
	cfg.tcp_warp = 1;
	snprintf(cfg.proxy, sizeof(cfg.proxy), "socks5h://127.0.0.1:1081");
	CHECK_EQ(hw_server_config_validate(&cfg, err, sizeof(err)), -1);
	CHECK_EQ(hw_cidr_parse("192.0.2.1", &cfg.proxy_only_to[0]), 0);
	cfg.proxy_only_to_count = 1;
	CHECK_EQ(hw_server_config_validate(&cfg, err, sizeof(err)), 0);
}

// family-fallback-ms: an attempt with the other family still to try is cut short; the last one of
// a family, or one through the proxy, keeps the whole connect timeout.
static void test_family_fallback(void) {
	hw_server srv;
	memset(&srv, 0, sizeof(srv));
	hw_server_config_defaults(&srv.cfg);
	hw_worker w;
	memset(&w, 0, sizeof(w));
	w.server = &srv;
	hw_conn c;
	memset(&c, 0, sizeof(c));
	c.w = &w;
	hw_stream s;
	memset(&s, 0, sizeof(s));
	s.conn = &c;
	struct sockaddr_in6 v6 = {.sin6_family = AF_INET6};
	struct sockaddr_in v4 = {.sin_family = AF_INET};
	memcpy(&s.addrs[0], &v6, sizeof(v6));
	memcpy(&s.addrs[1], &v6, sizeof(v6));
	memcpy(&s.addrs[2], &v4, sizeof(v4));
	s.naddrs = 3;
	const struct sockaddr *a6 = (const struct sockaddr *)&v6, *a4 = (const struct sockaddr *)&v4;
	s.addr_idx = 1; // dialling addrs[0]: IPv4 is still ahead
	CHECK_EQ(stream_attempt_timeout_ms(&s, a6), 3000);
	s.addr_idx = 2;
	CHECK_EQ(stream_attempt_timeout_ms(&s, a6), 3000);
	s.addr_idx = 3; // the IPv4 address, the last: all of it
	CHECK_EQ(stream_attempt_timeout_ms(&s, a4), 15000);
	s.naddrs = 2; // IPv6 only: nothing to fall back to
	s.addr_idx = 1;
	CHECK_EQ(stream_attempt_timeout_ms(&s, a6), 15000);
	s.naddrs = 3;
	srv.cfg.family_fallback_ms = 0; // off
	CHECK_EQ(stream_attempt_timeout_ms(&s, a6), 15000);
	srv.cfg.family_fallback_ms = 3000;
	s.via_proxy = 1; // the proxy dials, not us
	CHECK_EQ(stream_attempt_timeout_ms(&s, a6), 15000);
}

int main(void) {
	hw_log_set_level(HW_LOG_NONE);
	if (!hw_sys_has_mark()) {
		printf("skip: this platform cannot mark sockets\n");
		return 0;
	}
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	g_can_mark = fd >= 0 && hw_sys_set_mark(fd, 0x7701) == 0;
	if (fd >= 0) close(fd);
	char dir[] = "/tmp/hw-udp-warp-XXXXXX";
	CHECK(mkdtemp(dir) != NULL, "mkdtemp: %s", strerror(errno));
	snprintf(g_state, sizeof(g_state), "%s/warp.json", dir);
	start_udp_echo();
	start_tcp_echo();
	RUN(test_unprivileged_start);
	RUN(test_state_tracking);
	RUN(test_udp_streams);
	RUN(test_tcp_streams);
	RUN(test_family_fallback);
	unlink(g_state);
	rmdir(dir);
	return 0;
}
