/*
 * holywisp/server.h implementation: configuration defaults, the shared security machinery
 * (limiters, reputation, DNS cache, upstream proxy), listeners, worker threads, stats.
 *
 * Every worker has its own SO_REUSEPORT listener on the same port, so the kernel spreads incoming
 * connections across threads and no lock is involved in accepting; a worker that has more
 * connections than another then gives the one it just accepted to the one with the fewest (see
 * "Which worker gets a connection"). The limiters, the reputation
 * table and the DNS cache are process-wide and lock internally. One maintenance thread does the
 * periodic evictions, reputation decay and saves, and DNS cache expiry.
 */
#include "holywisp/hw.h"
#include "holywisp/log.h"
#include "holywisp/sys.h"
#include "holywisp/wisp.h"

#include "internal.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/stat.h>

void hw_server_config_defaults(hw_server_config *cfg) {
	memset(cfg, 0, sizeof(*cfg));
	cfg->port = 6001;
	cfg->udp_warp_state_max_age_s = 60;
	cfg->workers = 0;
	cfg->allow_tcp = 1;
	cfg->allow_udp = 1;
	cfg->enable_v2 = 1;
	cfg->parse_real_ip = 1;
	// One header by default, and the one every proxy rewrites. A header a proxy passes through
	// untouched (CF-Connecting-IP behind anything but Cloudflare) would let the client name itself.
	snprintf(cfg->trusted_headers[0], sizeof(cfg->trusted_headers[0]), "X-Forwarded-For");
	cfg->trusted_header_count = 1;
	cfg->connections_limit_per_ip = 200;
	cfg->connection_window_s = 10;
	cfg->buffer_remaining = 128;
	cfg->max_message_size = 1024 * 1024 + 5; // one max DATA payload plus its Wisp header
	cfg->ws_write_high_water = 8u * 1024 * 1024;
	cfg->stream_queue_max = 128u * 1024 * 1024;
	cfg->conn_queue_max = 256u * 1024 * 1024;
	cfg->client_recv_buffer = 8u * 1024 * 1024;
	cfg->max_streams_per_conn = 2048;
	cfg->connect_timeout_ms = 15000;
	cfg->family_fallback_ms = 3000;
	cfg->handshake_timeout_ms = 10000;
	cfg->client_write_timeout_s = 120;
	cfg->resolver_threads = 4;
	cfg->dns_ttl_s = 120;
	cfg->dns_negative_ttl_s = 10;
	cfg->dns_order = HW_DNS_IPV4_FIRST;
	cfg->dns_timeout_ms = 3000;
	cfg->tcp_nodelay = 1;
	cfg->tcp_quickack = 1;
	cfg->listen_backlog = 1024;

	// Flood protection on by default, matching wispurr's shipped numbers.
	cfg->flood.enabled = 1;
	cfg->flood.max_connects_per_source_per_second = 500;
	cfg->flood.max_connects_per_dest_per_second = 100;
	cfg->flood.max_connects_per_dest_per_minute = 3000;
	cfg->flood.max_in_flight_syns = 4096;
	cfg->flood.max_in_flight_syns_per_ip = 512;
	cfg->flood.max_concurrent_connections = 50000;
	cfg->flood.max_concurrent_connections_per_ip = 5000;
	cfg->flood.syn_signature_enabled = 1;
	cfg->flood.syn_signature_window_ms = 2000;
	cfg->flood.syn_signature_min_samples = 128;
	cfg->flood.syn_signature_failed_ratio = 0.75;
	cfg->flood.ws_close_after_violations = 64;

	cfg->reputation_enabled = 1;
	hw_reputation_config_defaults(&cfg->reputation);

	static const char banner[] = "holyWisp: a Wisp server. Connect with a WebSocket client.\n";
	memcpy(cfg->non_ws_response, banner, sizeof(banner));
	cfg->serve_webclient = 1;
	cfg->log_level = HW_LOG_INFO;
}

int hw_server_config_add_user(hw_server_config *cfg, const char *user, const char *pass) {
	if (cfg->password_user_count >= HW_MAX_PASSWORD_USERS) {
		errno = ENOSPC;
		return -1;
	}
	hw_password_user *u = &cfg->password_users[cfg->password_user_count];
	// An empty password is not a password: it would let anyone who knows the name in.
	if (strlen(user) >= sizeof(u->user) || strlen(pass) >= sizeof(u->pass) || !*user || !*pass) {
		errno = EINVAL;
		return -1;
	}
	memcpy(u->user, user, strlen(user) + 1);
	memcpy(u->pass, pass, strlen(pass) + 1);
	cfg->password_user_count++;
	return 0;
}

int hw_server_config_validate(const hw_server_config *cfg, char *err, size_t err_cap) {
	if (cfg->buffer_remaining == 0) {
		snprintf(err, err_cap, "buffer-remaining must be greater than zero");
		return -1;
	}
	// The same floor as the config file's: a message that holds a Wisp header and nothing else
	// leaves no room for a payload, and the relay paths divide a read by that room.
	if (cfg->max_message_size < 1024) {
		snprintf(err, err_cap, "max-message-size must be at least 1024");
		return -1;
	}
	if (cfg->conn_queue_max < cfg->stream_queue_max) {
		snprintf(err, err_cap, "conn-queue-max must be at least stream-queue-max");
		return -1;
	}
	if (cfg->password_required && cfg->password_user_count == 0) {
		snprintf(err, err_cap, "password-required needs at least one password-user");
		return -1;
	}
	for (int i = 0; i < cfg->password_user_count && !hw_sys_has_crypt(); i++) {
		if (cfg->password_users[i].pass[0] != '$') continue;
		// Never the value: the config that holds passwords is not logged.
		snprintf(err, err_cap, "password-user '%s': this platform has no crypt(3) to check a hashed password with",
		         cfg->password_users[i].user);
		return -1;
	}
	if (cfg->enable_twisp && cfg->password_user_count == 0) {
		snprintf(err, err_cap, "enable-twisp needs password auth: add a password-user");
		return -1;
	}
	if (cfg->enable_twisp && !hw_sys_has_pty()) {
		snprintf(err, err_cap, "enable-twisp: this platform has no pseudo-terminals");
		return -1;
	}
	if (cfg->enable_twisp && !cfg->enable_v2) {
		snprintf(err, err_cap, "enable-twisp needs enable-v2");
		return -1;
	}
	if ((cfg->udp_warp_mark_count > 0) != (cfg->udp_warp_state[0] != '\0')) {
		snprintf(err, err_cap, "udp-warp-marks and udp-warp-state must both be set or both be empty");
		return -1;
	}
	if (cfg->proxy_client_key && !cfg->proxy[0] && cfg->udp_warp_mark_count == 0) {
		snprintf(err, err_cap, "proxy-client-key needs a proxy or udp-warp-marks to give the key to");
		return -1;
	}
	if (cfg->proxy_client_key_secret[0] && strlen(cfg->proxy_client_key_secret) < 16) {
		// Never the value: it is a secret.
		snprintf(err, err_cap, "proxy-client-key-secret must be at least 16 characters");
		return -1;
	}
	if (cfg->proxy_only_to_count > 0 && !cfg->proxy[0]) {
		snprintf(err, err_cap, "proxy-only-to needs a proxy");
		return -1;
	}
	if (cfg->tcp_warp && cfg->udp_warp_mark_count == 0) {
		snprintf(err, err_cap, "tcp-warp needs udp-warp-marks and udp-warp-state: they are its tunnels");
		return -1;
	}
	if (cfg->tcp_warp && cfg->proxy[0] && cfg->proxy_only_to_count == 0) {
		snprintf(err, err_cap, "tcp-warp marks TCP dialled here, and with a proxy and no proxy-only-to there is none");
		return -1;
	}
	if (cfg->udp_warp_mark_count > 0 && !hw_sys_has_mark()) {
		snprintf(err, err_cap, "udp-warp-marks: this platform cannot mark sockets");
		return -1;
	}
	if ((cfg->connections_limit_per_ip == 0) != (cfg->connection_window_s == 0)) {
		snprintf(err, err_cap, "connections-limit-per-ip and connection-window-s must both be set or both be zero");
		return -1;
	}
	if (cfg->flood.syn_signature_failed_ratio < 0 || cfg->flood.syn_signature_failed_ratio > 1) {
		snprintf(err, err_cap, "syn-signature-failed-ratio must be between 0 and 1");
		return -1;
	}
	char perr[256];
	if (cfg->webclient_wisp_url[0]) {
		const char *u = cfg->webclient_wisp_url;
		if (strncmp(u, "ws://", 5) != 0 && strncmp(u, "wss://", 6) != 0) {
			snprintf(err, err_cap, "webclient-wisp-url must start with ws:// or wss://");
			return -1;
		}
		// It is spliced into a <script> string literal: nothing that could end the literal, the
		// element, or be a control character.
		for (const char *p = u; *p; p++) {
			if ((unsigned char)*p <= ' ' || *p == '"' || *p == '\'' || *p == '\\' || *p == '<' || *p == '>') {
				snprintf(err, err_cap, "webclient-wisp-url contains a character that cannot go into the page");
				return -1;
			}
		}
	}
	hw_proxy_config pc;
	if (proxy_config_parse(cfg->proxy, &pc, perr, sizeof(perr)) != 0) {
		snprintf(err, err_cap, "%s", perr);
		return -1;
	}
	return 0;
}

// The window is counted in packets but the per-stream queue toward a slow remote is counted in
// bytes. A client that spends a whole window of maximum-size packets into a remote that is not
// draining must land inside stream-queue-max, or it is closed 0x49 before flow control ever slowed
// it (wispurr patch 0004). A CONTINUE is only handed out once the queue is empty (continue_due), so
// the queue never holds more than one window: the whole of stream-queue-max is the budget.
static uint32_t server_ingress_window(const hw_server_config *cfg) {
	size_t payload = cfg->max_message_size > HW_WISP_HEADER_LEN ? cfg->max_message_size - HW_WISP_HEADER_LEN : 1;
	size_t by_mem = cfg->stream_queue_max / payload;
	if (by_mem < 1) by_mem = 1;
	return by_mem < cfg->buffer_remaining ? (uint32_t)by_mem : cfg->buffer_remaining;
}

// ---------------------------------------------------------------------------------- socket tuning

// The `field`-th whitespace-separated integer of a /proc/sys file, or -1.
static long read_sysctl_long(const char *path, int field) {
	char line[128];
	FILE *f = fopen(path, "r");
	if (!f) return -1;
	char *got = fgets(line, sizeof(line), f);
	fclose(f);
	if (!got) return -1;
	char *p = line;
	long v = -1;
	for (int i = 0; i <= field; i++) {
		char *end;
		errno = 0;
		v = strtol(p, &end, 10);
		if (end == p || errno != 0) return -1;
		p = end;
	}
	return v;
}

// A client that uploads in bursts is served best by a receive window that is large from the first
// byte: the bytes wait in the kernel, arrive here in big reads and leave in few writes. Autotuning
// gets there too, but slowly and per connection. An explicit SO_RCVBUF is capped by
// net.core.rmem_max (and doubled by the kernel), and it switches autotuning off for the socket, so
// on a host with the stock 208 KiB cap it would pin the window small. It is applied only when the
// buffer the kernel will really grant is at least CLIENT_RCVBUF_FLOOR, and never when
// socket-buffer-size already sets both buffers.
#define CLIENT_RCVBUF_FLOOR (4L * 1024 * 1024)

// `want` capped by the sysctl at `cap_path`, or 0 when the kernel would grant under the floor.
static int server_fixed_buffer(const hw_server_config *cfg, size_t want_cfg, const char *cap_path, const char *key) {
	if (cfg->socket_buffer_size > 0 || want_cfg == 0) return 0;
	long cap = read_sysctl_long(cap_path, 0);
	if (cap <= 0) return 0;
	long want = (long)want_cfg < cap ? (long)want_cfg : cap;
	if (want > INT32_MAX / 2) want = INT32_MAX / 2;
	if (want * 2 < CLIENT_RCVBUF_FLOOR) {
		HW_INFO("server", "%s not applied: %s is %ld, which grants under %ld bytes", key, cap_path, cap,
		        CLIENT_RCVBUF_FLOOR);
		return 0;
	}
	return (int)want;
}

void server_tune_socket(const hw_server *s, int fd, int is_tcp) {
	if (is_tcp) {
		int one = 1;
		if (s->cfg.tcp_nodelay) setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
#ifdef TCP_QUICKACK
		if (s->cfg.tcp_quickack) setsockopt(fd, IPPROTO_TCP, TCP_QUICKACK, &one, sizeof(one));
#endif
		setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one));
	}
	if (s->cfg.socket_buffer_size > 0) {
		int sz = (int)s->cfg.socket_buffer_size;
		setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &sz, sizeof(sz));
		setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sz, sizeof(sz));
	}
}

// ---------------------------------------------------------------------------------- workers

#define ACCEPT_RETRY_MS 100  // how long a listener rests after accept ran out of descriptors
#define SWEEP_MS        5000 // how often, at most, a worker looks for clients to time out (conn_sweep)

static void accept_resume_cb(hw_loop *loop, void *ud) {
	hw_worker *w = ud;
	hw_loop_mod_fd(loop, w->listen_fd, HW_EV_READ);
}

static void sweep_cb(hw_loop *loop, void *ud) {
	conn_sweep(ud);
}

// Which worker gets a connection.
//
// Each worker has a listener of its own and the kernel picks one per connection by a hash of its
// addresses. Over thousands of connections that is even. Over eight it is not: two of them on one
// worker while others sit idle is the usual outcome, and those two then share one core for as
// long as they live. So the worker that accepted keeps a connection only if no other worker has
// fewer; otherwise it gives the descriptor, still untouched, to the one with the fewest. The
// connection is created on the loop that receives it and belongs to that loop from then on, so
// nothing about who may touch a connection changes: only a descriptor and an address cross.
typedef struct hw_handoff {
	struct hw_handoff *next;
	int fd;
	struct sockaddr_storage peer;
} hw_handoff;

// Loop thread of the receiving worker.
static void inbox_task(hw_loop *loop, void *ud) {
	hw_worker *w = ud;
	pthread_mutex_lock(&w->inbox_lock);
	hw_handoff *h = w->inbox;
	w->inbox = NULL;
	pthread_mutex_unlock(&w->inbox_lock);
	while (h) {
		hw_handoff *next = h->next;
		conn_accept(w, h->fd, (struct sockaddr *)&h->peer);
		free(h);
		h = next;
	}
}

// What is still in an inbox when the workers have stopped was never anyone's connection.
static void inbox_drop(hw_worker *w) {
	hw_handoff *h = w->inbox;
	w->inbox = NULL;
	while (h) {
		hw_handoff *next = h->next;
		close(h->fd);
		free(h);
		h = next;
	}
}

// 1 when `to` has the connection (its load already counts it), 0 when it could not be given.
static int hand_off(hw_worker *to, int fd, const struct sockaddr_storage *peer) {
	hw_handoff *h = malloc(sizeof(*h));
	if (!h) return 0;
	h->fd = fd;
	h->peer = *peer;
	pthread_mutex_lock(&to->inbox_lock);
	h->next = to->inbox;
	to->inbox = h;
	pthread_mutex_unlock(&to->inbox_lock);
	if (hw_loop_post(to->loop, inbox_task, to) == 0) return 1;
	// No task to announce it. Unless an earlier task has taken it meanwhile, take it back.
	int taken = 1;
	pthread_mutex_lock(&to->inbox_lock);
	for (hw_handoff **p = &to->inbox; *p; p = &(*p)->next) {
		if (*p == h) {
			*p = h->next;
			taken = 0;
			break;
		}
	}
	pthread_mutex_unlock(&to->inbox_lock);
	if (!taken) free(h);
	return taken;
}

// The worker with the fewest connections, `self` when none has fewer than it.
static hw_worker *least_loaded(hw_worker *self) {
	hw_server *s = self->server;
	hw_worker *best = self;
	int low = atomic_load_explicit(&self->load, memory_order_relaxed);
	for (int i = 0; i < s->nworkers && low > 0; i++) {
		int load = atomic_load_explicit(&s->workers[i].load, memory_order_relaxed);
		if (load < low) {
			low = load;
			best = &s->workers[i];
		}
	}
	return best;
}

static void accept_cb(hw_loop *loop, int fd, unsigned events, void *ud) {
	hw_worker *w = ud;
	for (;;) {
		struct sockaddr_storage ss;
		socklen_t sl = sizeof(ss);
		int cfd = hw_accept_nb(fd, &ss, &sl);
		if (cfd < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) return;
			if (errno == EMFILE || errno == ENFILE) {
				// The connection stays in the backlog and the listener stays readable, so returning
				// here would bring the loop straight back: stop listening for a moment instead, and
				// say so once in a while, not once per turn.
				uint64_t now = hw_now_ms();
				if (now - w->accept_warn_ms >= 5000) {
					w->accept_warn_ms = now;
					HW_WARN("accept", "worker %d: out of file descriptors, not accepting", w->index);
				}
				hw_loop_mod_fd(loop, fd, 0);
				hw_loop_add_timer(loop, ACCEPT_RETRY_MS, 0, accept_resume_cb, w);
				return;
			}
			if (errno == ECONNABORTED) continue;
			HW_ERROR("accept", "worker %d: accept: %s", w->index, strerror(errno));
			return;
		}
		// Counted where it is going before it gets there, so that a burst accepted in one pass
		// is spread and not sent to whichever worker was idle when the pass began.
		hw_worker *to = least_loaded(w);
		atomic_fetch_add(&to->load, 1);
		if (to != w && hand_off(to, cfd, &ss)) continue;
		if (to != w) {
			atomic_fetch_sub(&to->load, 1);
			atomic_fetch_add(&w->load, 1);
		}
		conn_accept(w, cfd, (struct sockaddr *)&ss);
	}
}

static void *worker_main(void *arg) {
	hw_worker *w = arg;
	HW_DEBUG("worker", "worker %d running", w->index);
	// A loop that gives up takes its connections with it; never silently.
	if (hw_loop_run(w->loop) != 0) HW_ERROR("worker", "worker %d: event loop failed: %s", w->index, strerror(errno));
	HW_DEBUG("worker", "worker %d stopped", w->index);
	return NULL;
}

static int worker_init(hw_server *s, hw_worker *w, int index, uint16_t port) {
	w->server = s;
	w->index = index;
	w->listen_fd = -1;
	pthread_mutex_init(&w->inbox_lock, NULL);
	w->loop = hw_loop_new();
	w->scratch = malloc(HW_READ_CHUNK);
	if (!w->loop || !w->scratch) return -1;
	hw_loop_set_batch_end(w->loop, conn_batch_end, w);
	hw_loop_set_busy_poll(w->loop, (unsigned)s->cfg.busy_poll_us);
	// The first worker binds the address; the rest get a listener of their own for it.
	w->listen_fd = index == 0 ? hw_listen_tcp(s->cfg.host, port, 1, s->cfg.listen_backlog, &s->port)
	                          : hw_sys_listen_more(s->workers[0].listen_fd, s->cfg.host, port, s->cfg.listen_backlog);
	if (w->listen_fd < 0) return -1;
	if (hw_loop_add_fd(w->loop, w->listen_fd, HW_EV_READ, accept_cb, w) != 0) return -1;
	// Half the shorter of the two timeouts, so that a timeout is never late by more than half of
	// itself, and no more often than a few times a second.
	int shortest = s->cfg.client_write_timeout_s;
	if (s->cfg.idle_timeout_s > 0 && (shortest <= 0 || s->cfg.idle_timeout_s < shortest)) {
		shortest = s->cfg.idle_timeout_s;
	}
	if (shortest > 0) {
		uint64_t every = (uint64_t)shortest * 500;
		if (every > SWEEP_MS) every = SWEEP_MS;
		if (!hw_loop_add_timer(w->loop, every, every, sweep_cb, w)) return -1;
	}
	return 0;
}

static void worker_destroy(hw_worker *w) {
	inbox_drop(w);
	pthread_mutex_destroy(&w->inbox_lock);
	if (w->listen_fd >= 0) close(w->listen_fd);
	hw_loop_free(w->loop); // runs any swap still posted, so the last copy is the one to free
	free(w->warp);
	w->warp = NULL;
	free(w->scratch);
}

// ---------------------------------------------------------------------------------- UDP on WARP
//
// udp-warp-state is the edge router's list of the tunnels that are healthy, per address family.
// The maintenance thread looks at it once a second (one stat), reads it only when it is another
// file than last time (the router replaces it atomically, so a rewrite is a new inode), and gives
// every worker a copy of what it now means whenever that changes, by a posted task: a worker only
// ever reads its own copy, and the data path takes no lock. A file that is missing, unreadable,
// malformed or older than udp-warp-state-max-age-s means no marks at all, which is UDP as it is
// without these keys; the router rewrites the file on every probe round, so an old one means the
// router is not running.

#define WARP_STATE_MAX (64 * 1024)

typedef struct {
	hw_worker *w;
	hw_warp_state *st;
} warp_msg;

static void warp_swap_task(hw_loop *loop, void *ud) {
	(void)loop;
	warp_msg *m = ud;
	free(m->w->warp);
	m->w->warp = m->st;
	free(m);
}

// Every worker its own copy of st (NULL: unmarked): in place before the workers run, by a posted
// task after. 0, or -1 when a copy or a post failed, and the next look tries again.
static int warp_publish(hw_server *s, const hw_warp_state *st, int running) {
	int rc = 0;
	for (int i = 0; i < s->nworkers; i++) {
		hw_worker *w = &s->workers[i];
		hw_warp_state *copy = NULL;
		if (st) {
			copy = malloc(sizeof(*copy));
			if (!copy) {
				rc = -1;
				continue;
			}
			memcpy(copy, st, sizeof(*copy));
		}
		if (!running) {
			free(w->warp);
			w->warp = copy;
			continue;
		}
		warp_msg *m = malloc(sizeof(*m));
		if (m) {
			m->w = w;
			m->st = copy;
		}
		if (!m || hw_loop_post(w->loop, warp_swap_task, m) != 0) {
			free(m);
			free(copy);
			rc = -1;
		}
	}
	return rc;
}

// The state file into s->warp_read, or NULL there and the reason in s->warp_why.
static void warp_read_file(hw_server *s) {
	free(s->warp_read);
	s->warp_read = NULL;
	s->warp_why[0] = '\0';
	char *buf = malloc(WARP_STATE_MAX + 1);
	hw_warp_state *st = malloc(sizeof(*st));
	int fd = open(s->cfg.udp_warp_state, O_RDONLY);
	if (!buf || !st || fd < 0) {
		snprintf(s->warp_why, sizeof(s->warp_why), "%s", strerror(!buf || !st ? ENOMEM : errno));
		goto done;
	}
	size_t len = 0;
	for (;;) {
		ssize_t n = read(fd, buf + len, WARP_STATE_MAX + 1 - len);
		if (n < 0 && errno == EINTR) continue;
		if (n < 0) {
			snprintf(s->warp_why, sizeof(s->warp_why), "%s", strerror(errno));
			goto done;
		}
		if (n == 0) break;
		len += (size_t)n;
		if (len > WARP_STATE_MAX) {
			snprintf(s->warp_why, sizeof(s->warp_why), "larger than %d bytes", WARP_STATE_MAX);
			goto done;
		}
	}
	char err[64];
	if (hw_warp_state_parse(buf, len, st, err, sizeof(err)) != 0) {
		snprintf(s->warp_why, sizeof(s->warp_why), "not a tunnel list (%s)", err);
		goto done;
	}
	int dropped = hw_warp_state_restrict(st, s->cfg.udp_warp_marks, s->cfg.udp_warp_mark_count);
	if (dropped > 0) {
		HW_WARN("warp", "udp-warp-state %s: %d tunnel%s with a mark not in udp-warp-marks ignored",
		        s->cfg.udp_warp_state, dropped, dropped == 1 ? "" : "s");
	}
	s->warp_read = st;
	st = NULL;
done:
	if (fd >= 0) close(fd);
	free(buf);
	free(st);
}

void server_warp_refresh(hw_server *s, int running) {
	const hw_server_config *cfg = &s->cfg;
	const hw_warp_state *want = NULL;
	char why[160];
	struct stat sb;
	if (stat(cfg->udp_warp_state, &sb) != 0) {
		snprintf(why, sizeof(why), "%s", strerror(errno));
		s->warp_seen = 0;
		free(s->warp_read);
		s->warp_read = NULL;
	} else {
		if (!s->warp_seen || (int64_t)sb.st_mtime != s->warp_mtime || (uint64_t)sb.st_ino != s->warp_ino ||
		    (uint64_t)sb.st_size != s->warp_size) {
			s->warp_seen = 1;
			s->warp_mtime = (int64_t)sb.st_mtime;
			s->warp_ino = (uint64_t)sb.st_ino;
			s->warp_size = (uint64_t)sb.st_size;
			warp_read_file(s);
		}
		long long age = (long long)time(NULL) - (long long)sb.st_mtime;
		if (!s->warp_read) {
			snprintf(why, sizeof(why), "%s", s->warp_why);
		} else if (cfg->udp_warp_state_max_age_s > 0 && age > cfg->udp_warp_state_max_age_s) {
			snprintf(why, sizeof(why), "not rewritten for %lld s", age);
		} else {
			want = s->warp_read;
		}
	}
	int same = want ? s->warp_given && memcmp(want, s->warp_given, sizeof(*want)) == 0 : !s->warp_given;
	if (same && s->warp_published) return;
	if (!same) {
		hw_warp_state *next = NULL;
		if (want) {
			next = malloc(sizeof(*next));
			if (!next) return; // the next look tries again
			memcpy(next, want, sizeof(*next));
			HW_INFO("warp", "udp-warp-state: UDP goes through %d IPv4 and %d IPv6 tunnel%s", want->n4, want->n6,
			        want->n6 == 1 ? "" : "s");
		} else {
			HW_WARN("warp", "udp-warp-state %s: %s; UDP streams go out unmarked", cfg->udp_warp_state, why);
		}
		free(s->warp_given);
		s->warp_given = next;
	}
	s->warp_published = warp_publish(s, s->warp_given, running) == 0;
}

// Marking takes CAP_NET_ADMIN. Without it the server still runs, and its UDP goes out unmarked, as
// it did before these keys existed: refusing to start would take the whole relay down over its
// UDP's exit address. The log says so once, loudly.
static void warp_init(hw_server *s) {
	if (s->cfg.udp_warp_mark_count == 0) return;
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	int ok = fd >= 0 && hw_sys_set_mark(fd, s->cfg.udp_warp_marks[0]) == 0;
	int e = errno;
	if (fd >= 0) close(fd);
	if (!ok) {
		HW_ERROR("warp",
		         "udp-warp-marks: this process cannot mark sockets (%s; it needs CAP_NET_ADMIN), so UDP "
		         "streams go out unmarked%s",
		         strerror(e),
		         !s->cfg.tcp_warp                  ? ""
		         : s->cfg.tcp_warp_fallback_direct ? ", and so does TCP dialled here (tcp-warp-fallback direct)"
		                                           : ", and TCP dialled here is refused (tcp-warp-fallback refuse)");
		return;
	}
	s->warp_on = 1;
	server_warp_refresh(s, 0);
}

// ---------------------------------------------------------------------------------- maintenance

static void *maint_main(void *arg) {
	hw_server *s = arg;
	for (;;) {
		pthread_mutex_lock(&s->maint_lock);
		if (!s->maint_stop) {
			struct timespec ts;
			clock_gettime(CLOCK_REALTIME, &ts);
			ts.tv_sec += 1;
			pthread_cond_timedwait(&s->maint_cond, &s->maint_lock, &ts);
		}
		int stop = s->maint_stop;
		pthread_mutex_unlock(&s->maint_lock);

		uint64_t now = hw_now_ms();
		if (now - s->maint_last_slow >= 60000 || stop) {
			s->maint_last_slow = now;
			hw_window_evict(s->conn_rate, 2 * (uint64_t)s->cfg.connection_window_s * 1000 + 120000);
			hw_window_evict(s->per_source, 120000);
			hw_window_evict(s->per_dest_sec, 120000);
			hw_window_evict(s->per_dest_min, 120000);
			hw_bandwidth_evict(s->bandwidth, 600000);
			hw_dns_cache_expire(s->dns_cache);
			if (s->reputation) {
				hw_reputation_decay(s->reputation);
				hw_reputation_evict(s->reputation);
			}
		}
		// Reputation save on its own cadence.
		if (s->reputation && s->cfg.reputation.save_interval_s > 0) {
			if (now - s->maint_last_save >= (uint64_t)s->cfg.reputation.save_interval_s * 1000 || stop) {
				s->maint_last_save = now;
				if (hw_reputation_save(s->reputation) != 0) {
					HW_WARN("reputation", "save to %s: %s", s->cfg.reputation.store_path, strerror(errno));
				}
			}
		}
		if (s->warp_on && !stop) server_warp_refresh(s, 1);
		if (stop) return NULL;
	}
}

// ---------------------------------------------------------------------------------- lifecycle

static int build_limiters(hw_server *s) {
	const hw_server_config *cfg = &s->cfg;
	if (cfg->connections_limit_per_ip > 0 && cfg->connection_window_s > 0) {
		s->conn_rate = hw_window_new(cfg->connections_limit_per_ip, (uint64_t)cfg->connection_window_s * 1000);
		if (!s->conn_rate) return -1;
	}
	if (cfg->bandwidth_limit_kbps > 0) {
		s->bandwidth = hw_bandwidth_new((uint64_t)cfg->bandwidth_limit_kbps * 1000 / 8);
		if (!s->bandwidth) return -1;
	}
	if (cfg->flood.enabled) {
		const hw_flood_config *f = &cfg->flood;
		if (f->max_connects_per_source_per_second > 0) {
			s->per_source = hw_window_new(f->max_connects_per_source_per_second, 1000);
			if (!s->per_source) return -1;
		}
		if (f->max_connects_per_dest_per_second > 0) {
			s->per_dest_sec = hw_window_new(f->max_connects_per_dest_per_second, 1000);
			if (!s->per_dest_sec) return -1;
		}
		if (f->max_connects_per_dest_per_minute > 0) {
			s->per_dest_min = hw_window_new(f->max_connects_per_dest_per_minute, 60000);
			if (!s->per_dest_min) return -1;
		}
		hw_semaphore_init(&s->in_flight_syns, f->max_in_flight_syns);
		hw_semaphore_init(&s->connections, f->max_concurrent_connections);
		if (f->max_in_flight_syns_per_ip > 0) {
			s->syns_per_ip = hw_gauge_new(f->max_in_flight_syns_per_ip);
			if (!s->syns_per_ip) return -1;
		}
		if (f->max_concurrent_connections_per_ip > 0) {
			s->conns_per_ip = hw_gauge_new(f->max_concurrent_connections_per_ip);
			if (!s->conns_per_ip) return -1;
		}
	} else {
		hw_semaphore_init(&s->in_flight_syns, 0);
		hw_semaphore_init(&s->connections, 0);
	}
	if (cfg->reputation_enabled) {
		s->reputation = hw_reputation_new(&cfg->reputation);
		if (!s->reputation) return -1;
		if (hw_reputation_load(s->reputation) != 0) {
			HW_WARN("reputation", "load from %s: %s", cfg->reputation.store_path, strerror(errno));
		}
	}
	return 0;
}

hw_server *hw_server_new(const hw_server_config *cfg) {
	char err[256];
	if (hw_server_config_validate(cfg, err, sizeof(err)) != 0) {
		HW_ERROR("config", "%s", err);
		errno = EINVAL;
		return NULL;
	}
	hw_server *s = calloc(1, sizeof(*s));
	if (!s) return NULL;
	s->cfg = *cfg;
	s->started_ms = hw_now_ms();
	pthread_mutex_init(&s->maint_lock, NULL);
	pthread_cond_init(&s->maint_cond, NULL);
	hw_log_set_level(cfg->log_level);
	s->nworkers = cfg->workers > 0 ? cfg->workers : (int)sysconf(_SC_NPROCESSORS_ONLN);
	if (s->nworkers < 1) s->nworkers = 1;
	s->workers = calloc((size_t)s->nworkers, sizeof(*s->workers));
	if (!s->workers) goto fail;

	if (proxy_config_parse(cfg->proxy, &s->proxy, err, sizeof(err)) != 0) goto fail;
	if (proxy_config_resolve(&s->proxy) != 0) {
		HW_ERROR("proxy", "cannot resolve %s: %s", s->proxy.host, strerror(errno));
		goto fail;
	}
	if (cfg->proxy_client_key_secret[0]) {
		s->client_key_secret_len = strlen(cfg->proxy_client_key_secret);
		memcpy(s->client_key_secret, cfg->proxy_client_key_secret, s->client_key_secret_len);
	} else if (cfg->proxy_client_key) {
		s->client_key_secret_len = 32;
		if (hw_sys_random(s->client_key_secret, s->client_key_secret_len) != 0) {
			HW_ERROR("server", "proxy-client-key: no random bytes for its secret");
			goto fail;
		}
		HW_INFO("server", "proxy-client-key: no proxy-client-key-secret, so client keys change with every start");
	}
	if (build_limiters(s) != 0) goto fail;
	if (webclient_page_build(s) != 0) goto fail;
	s->window = server_ingress_window(cfg);
	s->client_rcvbuf = server_fixed_buffer(cfg, cfg->client_recv_buffer, "/proc/sys/net/core/rmem_max",
	                                       "client-recv-buffer");
	if (s->window < cfg->buffer_remaining) {
		HW_INFO("server",
		        "buffer-remaining %u capped to %u: a window of %zu-byte packets must fit in stream-queue-max %zu",
		        cfg->buffer_remaining, s->window, cfg->max_message_size - HW_WISP_HEADER_LEN, cfg->stream_queue_max);
	}

	s->dns_cache = hw_dns_cache_new((uint32_t)cfg->dns_ttl_s, (uint32_t)cfg->dns_negative_ttl_s, 0);

	hw_resolver_config rc;
	memset(&rc, 0, sizeof(rc));
	rc.threads = cfg->resolver_threads;
	rc.timeout_ms = cfg->dns_timeout_ms;
	rc.order = cfg->dns_order;
	rc.cache = s->dns_cache;
	for (int i = 0; i < cfg->dns_server_count && rc.nservers < HW_DNS_MAX_SERVERS; i++) {
		char buf[64];
		uint16_t port = 53;
		snprintf(buf, sizeof(buf), "%s", cfg->dns_servers[i]);
		char *host = buf;
		char *colon = NULL;
		// "[v6]:port", "v4:port", or a bare address keeping port 53.
		if (buf[0] == '[') {
			char *close = strchr(buf, ']');
			if (close) {
				*close = '\0';
				host = buf + 1;
				colon = close[1] == ':' ? close + 1 : NULL;
			}
		} else {
			colon = strrchr(buf, ':');
			if (colon) *colon = '\0';
		}
		if (colon) port = (uint16_t)strtol(colon + 1, NULL, 10);
		socklen_t sl;
		if (hw_addr_parse(host, port, &rc.servers[rc.nservers], &sl) == 1) {
			rc.server_lens[rc.nservers] = sl;
			rc.nservers++;
		} else {
			HW_WARN("dns", "ignoring malformed dns-server '%s'", cfg->dns_servers[i]);
		}
	}
	s->resolver = hw_resolver_new(&rc);
	if (!s->resolver) goto fail;
	// Hashed passwords are checked on threads of their own (auth.c); a server with none has no use
	// for them.
	for (int i = 0; i < cfg->password_user_count && !s->auth; i++) {
		if (cfg->password_users[i].pass[0] != '$') continue;
		s->auth = auth_new();
		if (!s->auth) goto fail;
	}

	s->port = cfg->port;
	for (int i = 0; i < s->nworkers; i++) {
		// The first worker may pick an ephemeral port; the rest join it with SO_REUSEPORT.
		if (worker_init(s, &s->workers[i], i, s->port) != 0) {
			int saved = errno;
			for (int j = 0; j <= i; j++) worker_destroy(&s->workers[j]);
			errno = saved;
			goto fail;
		}
	}
	warp_init(s);
	return s;
fail: {
	int saved = errno;
	hw_resolver_free(s->resolver);
	auth_free(s->auth);
	hw_dns_cache_free(s->dns_cache);
	hw_window_free(s->conn_rate);
	hw_window_free(s->per_source);
	hw_window_free(s->per_dest_sec);
	hw_window_free(s->per_dest_min);
	hw_bandwidth_free(s->bandwidth);
	hw_gauge_free(s->syns_per_ip);
	hw_gauge_free(s->conns_per_ip);
	hw_reputation_free(s->reputation);
	pthread_mutex_destroy(&s->maint_lock);
	pthread_cond_destroy(&s->maint_cond);
	free(s->webclient_page);
	free(s->workers);
	free(s);
	errno = saved ? saved : EINVAL;
	return NULL;
}
}

uint16_t hw_server_port(const hw_server *s) {
	return s->port;
}

hw_reputation *hw_server_reputation(const hw_server *s) {
	return s->reputation;
}

int hw_server_start(hw_server *s) {
	if (s->started) return 0;
	signal(SIGPIPE, SIG_IGN);
	s->started = 1;
	if (pthread_create(&s->maint_thread, NULL, maint_main, s) == 0) s->maint_started = 1;
	for (int i = 0; i < s->nworkers; i++) {
		hw_worker *w = &s->workers[i];
		if (pthread_create(&w->thread, NULL, worker_main, w) != 0) {
			HW_ERROR("server", "pthread_create: %s", strerror(errno));
			hw_server_stop(s);
			return -1;
		}
		w->thread_started = 1;
	}
	HW_INFO("server", "listening on %s:%u with %d worker%s%s%s", s->cfg.host[0] ? s->cfg.host : "*", s->port,
	        s->nworkers, s->nworkers == 1 ? "" : "s", s->cfg.flood.enabled ? ", flood protection on" : "",
	        s->reputation ? ", reputation on" : "");
	return 0;
}

static void server_join(hw_server *s) {
	for (int i = 0; i < s->nworkers; i++) {
		hw_worker *w = &s->workers[i];
		if (w->thread_started) {
			pthread_join(w->thread, NULL);
			w->thread_started = 0;
		}
	}
}

int hw_server_run(hw_server *s) {
	int r = hw_server_start(s);
	if (r != 0) return r;
	server_join(s);
	return 0;
}

void hw_server_stop(hw_server *s) {
	if (atomic_exchange(&s->stopped, 1)) return;
	for (int i = 0; i < s->nworkers; i++) hw_loop_stop(s->workers[i].loop);
	pthread_mutex_lock(&s->maint_lock);
	s->maint_stop = 1;
	pthread_cond_signal(&s->maint_cond);
	pthread_mutex_unlock(&s->maint_lock);
}

void hw_server_free(hw_server *s) {
	if (!s) return;
	hw_server_stop(s);
	server_join(s);
	if (s->maint_started) pthread_join(s->maint_thread, NULL);
	// The worker threads have joined, so any connection still open was never closed by its peer.
	// Free them in place; nothing else touches these workers now.
	for (int i = 0; i < s->nworkers; i++) {
		while (s->workers[i].conns) conn_shutdown_free(s->workers[i].conns);
	}
	hw_resolver_free(s->resolver);
	auth_free(s->auth);
	hw_dns_cache_free(s->dns_cache);
	hw_window_free(s->conn_rate);
	hw_window_free(s->per_source);
	hw_window_free(s->per_dest_sec);
	hw_window_free(s->per_dest_min);
	hw_bandwidth_free(s->bandwidth);
	hw_gauge_free(s->syns_per_ip);
	hw_gauge_free(s->conns_per_ip);
	hw_reputation_free(s->reputation);
	pthread_mutex_destroy(&s->maint_lock);
	pthread_cond_destroy(&s->maint_cond);
	for (int i = 0; i < s->nworkers; i++) worker_destroy(&s->workers[i]);
	free(s->warp_read);
	free(s->warp_given);
	free(s->webclient_page);
	free(s->workers);
	free(s);
}

void hw_server_stats_get(const hw_server *s, hw_server_stats *out) {
	memset(out, 0, sizeof(*out));
	out->uptime_s = (hw_now_ms() - s->started_ms) / 1000;
	out->connections_total = atomic_load(&s->connections_total);
	out->connections_active = atomic_load(&s->connections_active);
	out->streams_total = atomic_load(&s->streams_total);
	out->streams_active = atomic_load(&s->streams_active);
	out->worker_connections_min = UINT64_MAX;
	for (int i = 0; i < s->nworkers; i++) {
		out->bytes_in += atomic_load(&s->workers[i].bytes_in);
		out->bytes_out += atomic_load(&s->workers[i].bytes_out);
		int load = atomic_load(&s->workers[i].load);
		uint64_t n = load > 0 ? (uint64_t)load : 0;
		if (n < out->worker_connections_min) out->worker_connections_min = n;
		if (n > out->worker_connections_max) out->worker_connections_max = n;
	}
	if (s->nworkers == 0) out->worker_connections_min = 0;
	out->refused_connection_rate = atomic_load(&s->refused_connection_rate);
	out->refused_connection_limit = atomic_load(&s->refused_connection_limit);
	out->refused_reputation = atomic_load(&s->refused_reputation);
	out->blocked_filter = atomic_load(&s->blocked_filter);
	out->blocked_egress = atomic_load(&s->blocked_egress);
	out->throttled_source = atomic_load(&s->throttled_source);
	out->throttled_dest = atomic_load(&s->throttled_dest);
	out->throttled_syns = atomic_load(&s->throttled_syns);
	out->udp_warp_marked = atomic_load(&s->udp_warp_marked);
	out->udp_warp_direct = atomic_load(&s->udp_warp_direct);
	out->udp_warp_refused = atomic_load(&s->udp_warp_refused);
	out->tcp_warp_marked = atomic_load(&s->tcp_warp_marked);
	out->tcp_warp_direct = atomic_load(&s->tcp_warp_direct);
	out->tcp_warp_refused = atomic_load(&s->tcp_warp_refused);
	out->tcp_proxied = atomic_load(&s->tcp_proxied);
	out->tcp_direct = atomic_load(&s->tcp_direct);
	out->syn_signatures = atomic_load(&s->syn_signatures);
	out->ws_closed_violations = atomic_load(&s->ws_closed_violations);
	out->auth_failures = atomic_load(&s->auth_failures);
	out->dns_cache_entries = hw_dns_cache_count(s->dns_cache);
	if (s->reputation) {
		size_t src, dst;
		hw_reputation_counts(s->reputation, &src, &dst);
		out->reputation_sources = src;
		out->reputation_dests = dst;
	}
}
