/*
 * holywisp/server.h implementation: configuration defaults, the shared security machinery
 * (limiters, reputation, DNS cache, upstream proxy), listeners, worker threads, stats.
 *
 * Every worker has its own SO_REUSEPORT listener on the same port, so the kernel spreads incoming
 * connections across threads and no lock is involved in accepting. The limiters, the reputation
 * table and the DNS cache are process-wide and lock internally. One maintenance thread does the
 * periodic evictions, reputation decay and saves, and DNS cache expiry.
 */
#include "holywisp/hw.h"
#include "holywisp/log.h"

#include "internal.h"

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/sysinfo.h>

void hw_server_config_defaults(hw_server_config *cfg) {
	memset(cfg, 0, sizeof(*cfg));
	cfg->port = 6001;
	cfg->workers = 0;
	cfg->allow_tcp = 1;
	cfg->allow_udp = 1;
	cfg->enable_v2 = 1;
	cfg->parse_real_ip = 1;
	snprintf(cfg->trusted_headers[0], sizeof(cfg->trusted_headers[0]), "CF-Connecting-IP");
	snprintf(cfg->trusted_headers[1], sizeof(cfg->trusted_headers[1]), "X-Forwarded-For");
	cfg->trusted_header_count = 2;
	cfg->connections_limit_per_ip = 200;
	cfg->connection_window_s = 10;
	cfg->buffer_remaining = 128;
	cfg->max_message_size = 1024 * 1024 + 5; // one max DATA payload plus its Wisp header
	cfg->ws_write_high_water = 8u * 1024 * 1024;
	cfg->stream_queue_max = 16u * 1024 * 1024;
	cfg->max_streams_per_conn = 2048;
	cfg->connect_timeout_ms = 15000;
	cfg->handshake_timeout_ms = 10000;
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
	cfg->flood.max_concurrent_connections = 50000;
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
	if (strlen(user) >= sizeof(u->user) || strlen(pass) >= sizeof(u->pass) || !*user) {
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
	if (cfg->max_message_size < 5) {
		snprintf(err, err_cap, "max-message-size must be at least 5");
		return -1;
	}
	if (cfg->password_required && cfg->password_user_count == 0) {
		snprintf(err, err_cap, "password-required needs at least one password-user");
		return -1;
	}
	if (cfg->enable_twisp && cfg->password_user_count == 0) {
		snprintf(err, err_cap, "enable-twisp needs password auth: add a password-user");
		return -1;
	}
	if (cfg->enable_twisp && !cfg->enable_v2) {
		snprintf(err, err_cap, "enable-twisp needs enable-v2");
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
	hw_proxy_config pc;
	if (proxy_config_parse(cfg->proxy, &pc, perr, sizeof(perr)) != 0) {
		snprintf(err, err_cap, "%s", perr);
		return -1;
	}
	return 0;
}

// ---------------------------------------------------------------------------------- socket tuning

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

static void accept_cb(hw_loop *loop, int fd, unsigned events, void *ud) {
	hw_worker *w = ud;
	for (;;) {
		struct sockaddr_storage ss;
		socklen_t sl = sizeof(ss);
		int cfd = hw_accept_nb(fd, &ss, &sl);
		if (cfd < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) return;
			if (errno == EMFILE || errno == ENFILE) {
				HW_WARN("accept", "worker %d: out of file descriptors", w->index);
				return;
			}
			if (errno == ECONNABORTED) continue;
			HW_ERROR("accept", "worker %d: accept: %s", w->index, strerror(errno));
			return;
		}
		conn_accept(w, cfd, (struct sockaddr *)&ss);
	}
}

static void *worker_main(void *arg) {
	hw_worker *w = arg;
	HW_DEBUG("worker", "worker %d running", w->index);
	hw_loop_run(w->loop);
	HW_DEBUG("worker", "worker %d stopped", w->index);
	return NULL;
}

static int worker_init(hw_server *s, hw_worker *w, int index, uint16_t port) {
	w->server = s;
	w->index = index;
	w->listen_fd = -1;
	w->loop = hw_loop_new();
	w->scratch = malloc(HW_READ_CHUNK);
	if (!w->loop || !w->scratch) return -1;
	w->listen_fd = hw_listen_tcp(s->cfg.host, port, 1, s->cfg.listen_backlog, &s->port);
	if (w->listen_fd < 0) return -1;
	if (hw_loop_add_fd(w->loop, w->listen_fd, HW_EV_READ, accept_cb, w) != 0) return -1;
	return 0;
}

static void worker_destroy(hw_worker *w) {
	if (w->listen_fd >= 0) close(w->listen_fd);
	hw_loop_free(w->loop);
	free(w->scratch);
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
			hw_window_evict(s->per_dest_min, 7200000);
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
	s->nworkers = cfg->workers > 0 ? cfg->workers : get_nprocs();
	if (s->nworkers < 1) s->nworkers = 1;
	s->workers = calloc((size_t)s->nworkers, sizeof(*s->workers));
	if (!s->workers) goto fail;

	if (proxy_config_parse(cfg->proxy, &s->proxy, err, sizeof(err)) != 0) goto fail;
	if (proxy_config_resolve(&s->proxy) != 0) {
		HW_ERROR("proxy", "cannot resolve %s: %s", s->proxy.host, strerror(errno));
		goto fail;
	}
	if (build_limiters(s) != 0) goto fail;

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
	return s;
fail: {
	int saved = errno;
	hw_resolver_free(s->resolver);
	hw_dns_cache_free(s->dns_cache);
	hw_window_free(s->conn_rate);
	hw_window_free(s->per_source);
	hw_window_free(s->per_dest_sec);
	hw_window_free(s->per_dest_min);
	hw_bandwidth_free(s->bandwidth);
	hw_reputation_free(s->reputation);
	pthread_mutex_destroy(&s->maint_lock);
	pthread_cond_destroy(&s->maint_cond);
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
	hw_dns_cache_free(s->dns_cache);
	hw_window_free(s->conn_rate);
	hw_window_free(s->per_source);
	hw_window_free(s->per_dest_sec);
	hw_window_free(s->per_dest_min);
	hw_bandwidth_free(s->bandwidth);
	hw_reputation_free(s->reputation);
	pthread_mutex_destroy(&s->maint_lock);
	pthread_cond_destroy(&s->maint_cond);
	for (int i = 0; i < s->nworkers; i++) worker_destroy(&s->workers[i]);
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
	out->bytes_in = atomic_load(&s->bytes_in);
	out->bytes_out = atomic_load(&s->bytes_out);
	out->refused_connection_rate = atomic_load(&s->refused_connection_rate);
	out->refused_connection_limit = atomic_load(&s->refused_connection_limit);
	out->refused_reputation = atomic_load(&s->refused_reputation);
	out->blocked_filter = atomic_load(&s->blocked_filter);
	out->blocked_egress = atomic_load(&s->blocked_egress);
	out->throttled_source = atomic_load(&s->throttled_source);
	out->throttled_dest = atomic_load(&s->throttled_dest);
	out->throttled_syns = atomic_load(&s->throttled_syns);
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
