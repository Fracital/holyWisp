/*
 * holywisp: the server binary. Config file + flags in, SIGINT/SIGTERM out.
 */
#include "holywisp/hw.h"
#include "holywisp/log.h"
#include "holywisp/server.h"

#include "config.h"

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static hw_server *g_server;
// Held by the stdin watcher while it stops the server and by main while it takes the server away
// to free it: the two can coincide when the parent sends SIGTERM and then dies.
static pthread_mutex_t g_server_lock = PTHREAD_MUTEX_INITIALIZER;

static void on_signal(int signo) {
	// hw_server_stop only flips atomics and writes to eventfds: async-signal-safe enough.
	if (g_server) hw_server_stop(g_server);
}

// stop-on-stdin-eof: a parent that holds the other end of our stdin cannot die without the kernel
// closing it, whatever killed the parent. Bytes that arrive are ignored; only the end matters.
static void *stdin_watch(void *arg) {
	char buf[256];
	for (;;) {
		ssize_t n = read(STDIN_FILENO, buf, sizeof(buf));
		if (n > 0 || (n < 0 && errno == EINTR)) continue;
		if (n < 0) {
			HW_WARN("server", "stop-on-stdin-eof: cannot read stdin (%s); not watching it", strerror(errno));
			return NULL;
		}
		break;
	}
	pthread_mutex_lock(&g_server_lock);
	if (g_server) {
		HW_INFO("server", "stdin closed: the parent process is gone");
		hw_server_stop(g_server);
	}
	pthread_mutex_unlock(&g_server_lock);
	return NULL;
}

int main(int argc, char **argv) {
	hw_server_config cfg;
	hw_server_config_defaults(&cfg);
	char err[512];
	int r = hw_config_parse_args(&cfg, argc, argv, err, sizeof(err));
	if (r > 0) return 0;
	if (r < 0) {
		fprintf(stderr, "holywisp: %s\n", err);
		fprintf(stderr, "try '%s --help'\n", argv[0]);
		return 2;
	}
	hw_log_set_level(cfg.log_level);

	g_server = hw_server_new(&cfg);
	if (!g_server) {
		fprintf(stderr, "holywisp: cannot start: %s\n", strerror(errno));
		return 1;
	}
	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = on_signal;
	sigemptyset(&sa.sa_mask);
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	if (cfg.stop_on_stdin_eof) {
		pthread_t watcher;
		if (pthread_create(&watcher, NULL, stdin_watch, NULL) == 0) {
			pthread_detach(watcher);
		} else {
			HW_WARN("server", "stop-on-stdin-eof: cannot start the watcher thread");
		}
	}

	HW_INFO("server", "holywisp %s starting", HW_VERSION);
	r = hw_server_run(g_server);
	HW_INFO("server", "shutting down");
	pthread_mutex_lock(&g_server_lock);
	hw_server *server = g_server;
	g_server = NULL;
	pthread_mutex_unlock(&g_server_lock);
	hw_server_free(server);
	return r == 0 ? 0 : 1;
}
