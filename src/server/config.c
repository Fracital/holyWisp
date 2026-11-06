/*
 * server/config.h implementation.
 */
#include "config.h"

#include "holywisp/hw.h"
#include "holywisp/log.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int parse_bool(const char *v, int *out) {
	if (!strcmp(v, "1") || !strcmp(v, "true") || !strcmp(v, "yes") || !strcmp(v, "on")) {
		*out = 1;
		return 0;
	}
	if (!strcmp(v, "0") || !strcmp(v, "false") || !strcmp(v, "no") || !strcmp(v, "off")) {
		*out = 0;
		return 0;
	}
	return -1;
}

static int parse_long(const char *v, long min, long max, long *out) {
	char *end;
	errno = 0;
	long n = strtol(v, &end, 10);
	if (errno || end == v || *end || n < min || n > max) return -1;
	*out = n;
	return 0;
}

static int set_str(char *dst, size_t cap, const char *v) {
	size_t n = strlen(v);
	if (n >= cap) return -1;
	memcpy(dst, v, n + 1);
	return 0;
}

int hw_config_set(hw_server_config *cfg, const char *key, const char *value, char *err, size_t err_cap) {
	long n;
	int b;
#define BOOL_KEY(name, field)                           \
	if (!strcmp(key, name)) {                           \
		if (parse_bool(value, &b) != 0) goto bad_value; \
		cfg->field = b;                                 \
		return 0;                                       \
	}
#define INT_KEY(name, field, lo, hi)                            \
	if (!strcmp(key, name)) {                                   \
		if (parse_long(value, lo, hi, &n) != 0) goto bad_value; \
		cfg->field = (__typeof__(cfg->field))n;                 \
		return 0;                                               \
	}
#define STR_KEY(name, field)                                                     \
	if (!strcmp(key, name)) {                                                    \
		if (set_str(cfg->field, sizeof(cfg->field), value) != 0) goto bad_value; \
		return 0;                                                                \
	}

	STR_KEY("host", host)
	INT_KEY("port", port, 0, 65535)
	INT_KEY("workers", workers, 0, 1024)
	BOOL_KEY("allow-tcp", allow_tcp)
	BOOL_KEY("allow-udp", allow_udp)
	BOOL_KEY("allow-direct-ip", allow_direct_ip)
	BOOL_KEY("allow-private", allow_private)
	BOOL_KEY("allow-loopback", allow_loopback)
	BOOL_KEY("allow-link-local", allow_link_local)
	BOOL_KEY("enable-v2", enable_v2)
	STR_KEY("motd", motd)
	BOOL_KEY("password-required", password_required)
	INT_KEY("buffer-remaining", buffer_remaining, 1, 1 << 24)
	INT_KEY("max-message-size", max_message_size, 1024, 1L << 30)
	INT_KEY("ws-write-high-water", ws_write_high_water, 4096, 1L << 31)
	INT_KEY("stream-queue-max", stream_queue_max, 4096, 1L << 31)
	INT_KEY("max-streams-per-conn", max_streams_per_conn, 0, 1 << 20)
	INT_KEY("connect-timeout-ms", connect_timeout_ms, 100, 600000)
	INT_KEY("handshake-timeout-ms", handshake_timeout_ms, 100, 600000)
	INT_KEY("resolver-threads", resolver_threads, 1, 256)
	BOOL_KEY("tcp-nodelay", tcp_nodelay)
	INT_KEY("listen-backlog", listen_backlog, 1, 65535)
	STR_KEY("non-ws-response", non_ws_response)
#undef BOOL_KEY
#undef INT_KEY
#undef STR_KEY

	if (!strcmp(key, "log-level")) {
		int lvl = hw_log_level_parse(value);
		if (lvl < 0) goto bad_value;
		cfg->log_level = lvl;
		return 0;
	}
	if (!strcmp(key, "password-user")) {
		const char *colon = strchr(value, ':');
		if (!colon || colon == value) goto bad_value;
		char user[64];
		size_t ulen = (size_t)(colon - value);
		if (ulen >= sizeof(user)) goto bad_value;
		memcpy(user, value, ulen);
		user[ulen] = '\0';
		if (hw_server_config_add_user(cfg, user, colon + 1) != 0) {
			snprintf(err, err_cap, "password-user: %s", errno == ENOSPC ? "too many users" : "field too long");
			return -1;
		}
		return 0;
	}
	snprintf(err, err_cap, "unknown option '%s'", key);
	return -1;
bad_value:
	snprintf(err, err_cap, "bad value '%s' for '%s'", value, key);
	return -1;
}

static char *trim(char *s) {
	while (*s == ' ' || *s == '\t') s++;
	size_t n = strlen(s);
	while (n > 0 && (s[n - 1] == ' ' || s[n - 1] == '\t' || s[n - 1] == '\r' || s[n - 1] == '\n')) s[--n] = '\0';
	return s;
}

int hw_config_load_file(hw_server_config *cfg, const char *path, char *err, size_t err_cap) {
	FILE *f = fopen(path, "r");
	if (!f) {
		snprintf(err, err_cap, "%s: %s", path, strerror(errno));
		return -1;
	}
	char line[1024];
	int lineno = 0;
	while (fgets(line, sizeof(line), f)) {
		lineno++;
		char *s = trim(line);
		if (!*s || *s == '#') continue;
		char *eq = strchr(s, '=');
		if (!eq) {
			snprintf(err, err_cap, "%s:%d: expected key = value", path, lineno);
			fclose(f);
			return -1;
		}
		*eq = '\0';
		char *key = trim(s);
		char *value = trim(eq + 1);
		// Strip one layer of quotes so values may contain leading/trailing spaces.
		size_t vl = strlen(value);
		if (vl >= 2 && value[0] == '"' && value[vl - 1] == '"') {
			value[vl - 1] = '\0';
			value++;
		}
		char inner[256];
		if (hw_config_set(cfg, key, value, inner, sizeof(inner)) != 0) {
			snprintf(err, err_cap, "%s:%d: %s", path, lineno, inner);
			fclose(f);
			return -1;
		}
	}
	fclose(f);
	return 0;
}

void hw_config_usage(const char *argv0) {
	printf("usage: %s [--config FILE] [--KEY VALUE | --KEY=VALUE]...\n"
	       "\n"
	       "A Wisp v1/v2 server. Every KEY below is also a `KEY = VALUE` line in the config file.\n"
	       "\n"
	       "  host, port, workers                       bind address, port (6001), worker threads (0 = CPUs)\n"
	       "  allow-tcp, allow-udp                      stream types (both on)\n"
	       "  allow-direct-ip                           literal IPs in CONNECT (off)\n"
	       "  allow-private, allow-loopback,            egress to RFC 1918 / 127.0.0.0/8 / 169.254.0.0/16 (all off)\n"
	       "  allow-link-local\n"
	       "  enable-v2, motd                           Wisp v2 handshake (on), message of the day\n"
	       "  password-user USER:PASS                   add a v2 password-auth user (repeatable)\n"
	       "  password-required                         refuse unauthenticated v2 clients (off)\n"
	       "  buffer-remaining                          CONTINUE window in packets (128)\n"
	       "  max-message-size                          largest WebSocket message (1 MiB + 5)\n"
	       "  ws-write-high-water                       pause remote reads past this many queued bytes (8 MiB)\n"
	       "  stream-queue-max                          bytes queued toward a remote before throttling (16 MiB)\n"
	       "  max-streams-per-conn                      0 = unlimited (2048)\n"
	       "  connect-timeout-ms, handshake-timeout-ms  15000, 10000\n"
	       "  resolver-threads, tcp-nodelay, listen-backlog, non-ws-response\n"
	       "  log-level                                 debug|info|warn|error|none (info)\n"
	       "\n"
	       "  --version, --help\n",
	       argv0);
}

int hw_config_parse_args(hw_server_config *cfg, int argc, char **argv, char *err, size_t err_cap) {
	// First pass: --config, so flags given alongside it override the file regardless of order.
	for (int i = 1; i < argc; i++) {
		const char *a = argv[i];
		if (!a) break;
		const char *path = NULL;
		if (!strcmp(a, "--config") || !strcmp(a, "-c")) {
			if (i + 1 >= argc) {
				snprintf(err, err_cap, "--config needs a path");
				return -1;
			}
			path = argv[++i];
		} else if (!strncmp(a, "--config=", 9)) {
			path = a + 9;
		}
		if (path && hw_config_load_file(cfg, path, err, err_cap) != 0) return -1;
	}
	for (int i = 1; i < argc; i++) {
		const char *a = argv[i];
		if (!a) break;
		if (!strcmp(a, "--help") || !strcmp(a, "-h")) {
			hw_config_usage(argv[0]);
			return 1;
		}
		if (!strcmp(a, "--version") || !strcmp(a, "-V")) {
			printf("holywisp %s\n", HW_VERSION);
			return 1;
		}
		if (!strcmp(a, "--config") || !strcmp(a, "-c")) {
			i++;
			continue;
		}
		if (!strncmp(a, "--config=", 9)) continue;
		if (strncmp(a, "--", 2) != 0) {
			snprintf(err, err_cap, "unexpected argument '%s'", a);
			return -1;
		}
		char key[64];
		const char *value;
		const char *eq = strchr(a, '=');
		if (eq) {
			size_t kl = (size_t)(eq - a - 2);
			if (kl >= sizeof(key)) {
				snprintf(err, err_cap, "option too long: %s", a);
				return -1;
			}
			memcpy(key, a + 2, kl);
			key[kl] = '\0';
			value = eq + 1;
		} else {
			size_t kl = strlen(a + 2);
			if (kl >= sizeof(key)) {
				snprintf(err, err_cap, "option too long: %s", a);
				return -1;
			}
			memcpy(key, a + 2, kl + 1);
			// Boolean flags may stand alone: --allow-loopback means true.
			if (i + 1 < argc && argv[i + 1] && strncmp(argv[i + 1], "--", 2) != 0) {
				value = argv[++i];
			} else {
				value = "true";
			}
		}
		if (hw_config_set(cfg, key, value, err, err_cap) != 0) return -1;
	}
	return 0;
}
