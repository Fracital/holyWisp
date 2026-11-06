/*
 * holywisp/server.h implementation: configuration defaults, listeners, worker threads, stats.
 *
 * Every worker has its own SO_REUSEPORT listener on the same port, so the kernel spreads incoming
 * connections across threads and no lock is involved in accepting.
 */
#include "holywisp/hw.h"
#include "holywisp/log.h"

#include "internal.h"

#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/sysinfo.h>

void hw_server_config_defaults(hw_server_config *cfg) {
	memset(cfg, 0, sizeof(*cfg));
	cfg->port = 6001;
	cfg->workers = 0;
	cfg->allow_tcp = 1;
	cfg->allow_udp = 1;
	cfg->enable_v2 = 1;
	cfg->buffer_remaining = 128;
	cfg->max_message_size = 1024 * 1024 + 5; // one max DATA payload plus its Wisp header
	cfg->ws_write_high_water = 8u * 1024 * 1024;
	cfg->stream_queue_max = 16u * 1024 * 1024;
	cfg->max_streams_per_conn = 2048;
	cfg->connect_timeout_ms = 15000;
	cfg->handshake_timeout_ms = 10000;
	cfg->resolver_threads = 4;
	cfg->tcp_nodelay = 1;
	cfg->listen_backlog = 1024;
	static const char banner[] = "holyWisp: a Wisp server. Connect with a WebSocket client.\n";
	memcpy(cfg->non_ws_response, banner, sizeof(banner));
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

// ---------------------------------------------------------------------------------- lifecycle

hw_server *hw_server_new(const hw_server_config *cfg) {
	hw_server *s = calloc(1, sizeof(*s));
	if (!s) return NULL;
	s->cfg = *cfg;
	hw_log_set_level(cfg->log_level);
	s->nworkers = cfg->workers > 0 ? cfg->workers : get_nprocs();
	if (s->nworkers < 1) s->nworkers = 1;
	s->workers = calloc((size_t)s->nworkers, sizeof(*s->workers));
	if (!s->workers) {
		free(s);
		return NULL;
	}
	s->resolver = hw_resolver_new(cfg->resolver_threads);
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
fail:
	hw_resolver_free(s->resolver);
	free(s->workers);
	free(s);
	return NULL;
}

uint16_t hw_server_port(const hw_server *s) {
	return s->port;
}

int hw_server_start(hw_server *s) {
	if (s->started) return 0;
	// Writing to a client that went away must be an EPIPE, not a process death.
	signal(SIGPIPE, SIG_IGN);
	s->started = 1;
	for (int i = 0; i < s->nworkers; i++) {
		hw_worker *w = &s->workers[i];
		if (pthread_create(&w->thread, NULL, worker_main, w) != 0) {
			HW_ERROR("server", "pthread_create: %s", strerror(errno));
			hw_server_stop(s);
			return -1;
		}
		w->thread_started = 1;
	}
	HW_INFO("server", "listening on %s:%u with %d worker%s", s->cfg.host[0] ? s->cfg.host : "*", s->port, s->nworkers,
	        s->nworkers == 1 ? "" : "s");
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
}

void hw_server_free(hw_server *s) {
	if (!s) return;
	hw_server_stop(s);
	server_join(s);
	// Connections still open when the loops stopped are released by their loop's final task run
	// (hw_loop_run drains posted frees); anything the resolver still holds goes with it.
	hw_resolver_free(s->resolver);
	for (int i = 0; i < s->nworkers; i++) worker_destroy(&s->workers[i]);
	free(s->workers);
	free(s);
}

void hw_server_stats_get(const hw_server *s, hw_server_stats *out) {
	out->connections_total = atomic_load(&s->connections_total);
	out->connections_active = atomic_load(&s->connections_active);
	out->streams_total = atomic_load(&s->streams_total);
	out->streams_active = atomic_load(&s->streams_active);
	out->bytes_in = atomic_load(&s->bytes_in);
	out->bytes_out = atomic_load(&s->bytes_out);
}
