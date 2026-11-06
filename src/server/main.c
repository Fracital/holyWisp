/*
 * holywisp: the server binary. Config file + flags in, SIGINT/SIGTERM out.
 */
#include "holywisp/hw.h"
#include "holywisp/log.h"
#include "holywisp/server.h"

#include "config.h"

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static hw_server *g_server;

static void on_signal(int signo) {
	// hw_server_stop only flips atomics and writes to eventfds: async-signal-safe enough.
	if (g_server) hw_server_stop(g_server);
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

	HW_INFO("server", "holywisp %s starting", HW_VERSION);
	r = hw_server_run(g_server);
	HW_INFO("server", "shutting down");
	hw_server_free(g_server);
	g_server = NULL;
	return r == 0 ? 0 : 1;
}
