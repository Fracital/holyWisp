/*
 * server/config.h implementation.
 */
#include "config.h"

#include "holywisp/dns.h"
#include "holywisp/hw.h"
#include "holywisp/limits.h"
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

// long long, not long: the size limits below reach 2^31, which a 32-bit long (Windows) cannot hold.
static int parse_long(const char *v, long long min, long long max, long long *out) {
	char *end;
	errno = 0;
	long long n = strtoll(v, &end, 10);
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
	long long n;
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

#define DBL_KEY(name, field, lo, hi)                                          \
	if (!strcmp(key, name)) {                                                 \
		char *dend;                                                           \
		double dv = strtod(value, &dend);                                     \
		if (dend == value || *dend || dv < (lo) || dv > (hi)) goto bad_value; \
		cfg->field = dv;                                                      \
		return 0;                                                             \
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
	BOOL_KEY("enable-twisp", enable_twisp)
	STR_KEY("motd", motd)
	BOOL_KEY("password-required", password_required)
	BOOL_KEY("parse-real-ip", parse_real_ip)
	INT_KEY("connections-limit-per-ip", connections_limit_per_ip, 0, 1 << 24)
	INT_KEY("connection-window-s", connection_window_s, 0, 86400)
	INT_KEY("bandwidth-limit-kbps", bandwidth_limit_kbps, 0, 1000000000)
	// Flood protection.
	BOOL_KEY("flood-protection", flood.enabled)
	INT_KEY("max-connects-per-source-per-second", flood.max_connects_per_source_per_second, 0, 1 << 24)
	INT_KEY("max-connects-per-dest-per-second", flood.max_connects_per_dest_per_second, 0, 1 << 24)
	INT_KEY("max-connects-per-dest-per-minute", flood.max_connects_per_dest_per_minute, 0, 1 << 24)
	INT_KEY("max-in-flight-syns", flood.max_in_flight_syns, 0, 1 << 24)
	INT_KEY("max-in-flight-syns-per-ip", flood.max_in_flight_syns_per_ip, 0, 1 << 24)
	INT_KEY("max-concurrent-connections", flood.max_concurrent_connections, 0, 1 << 24)
	INT_KEY("max-concurrent-connections-per-ip", flood.max_concurrent_connections_per_ip, 0, 1 << 24)
	BOOL_KEY("syn-signature", flood.syn_signature_enabled)
	INT_KEY("syn-signature-window-ms", flood.syn_signature_window_ms, 1, 600000)
	INT_KEY("syn-signature-min-samples", flood.syn_signature_min_samples, 1, HW_SIGDET_RING)
	DBL_KEY("syn-signature-failed-ratio", flood.syn_signature_failed_ratio, 0.0, 1.0)
	INT_KEY("ws-close-after-violations", flood.ws_close_after_violations, 0, 1 << 24)
	BOOL_KEY("log-blocked-dials", flood.log_blocked_dials)
	// Reputation.
	BOOL_KEY("reputation", reputation_enabled)
	STR_KEY("reputation-store", reputation.store_path)
	INT_KEY("reputation-save-interval-s", reputation.save_interval_s, 0, 86400)
	INT_KEY("reputation-decay-per-hour", reputation.decay_per_hour, 0, 100)
	INT_KEY("reputation-evict-after-days", reputation.evict_after_days, 0, 3650)
	INT_KEY("reputation-warn", reputation.warn, 0, 100)
	INT_KEY("reputation-throttle", reputation.throttle, 0, 100)
	INT_KEY("reputation-strict", reputation.strict, 0, 100)
	// DNS.
	INT_KEY("dns-ttl-s", dns_ttl_s, 0, 604800)
	INT_KEY("dns-negative-ttl-s", dns_negative_ttl_s, 0, 604800)
	INT_KEY("dns-timeout-ms", dns_timeout_ms, 100, 60000)
	// Where streams go.
	STR_KEY("proxy", proxy)
	BOOL_KEY("proxy-client-key", proxy_client_key)
	BOOL_KEY("tcp-warp", tcp_warp)
	STR_KEY("proxy-client-key-secret", proxy_client_key_secret)
	STR_KEY("udp-warp-state", udp_warp_state)
	INT_KEY("udp-warp-state-max-age-s", udp_warp_state_max_age_s, 0, 86400)
	STR_KEY("trusted-proxy-secret", trusted_proxy_secret)
	INT_KEY("buffer-remaining", buffer_remaining, 1, 1 << 24)
	INT_KEY("max-message-size", max_message_size, 1024, 1LL << 30)
	INT_KEY("ws-write-high-water", ws_write_high_water, 4096, 1LL << 31)
	INT_KEY("stream-queue-max", stream_queue_max, 4096, 1LL << 31)
	INT_KEY("conn-queue-max", conn_queue_max, 4096, 1LL << 31)
	INT_KEY("socket-buffer-size", socket_buffer_size, 0, 1LL << 30)
	INT_KEY("client-recv-buffer", client_recv_buffer, 0, 1LL << 30)
	INT_KEY("max-streams-per-conn", max_streams_per_conn, 0, 1 << 20)
	INT_KEY("connect-timeout-ms", connect_timeout_ms, 100, 600000)
	INT_KEY("family-fallback-ms", family_fallback_ms, 0, 600000)
	INT_KEY("handshake-timeout-ms", handshake_timeout_ms, 100, 600000)
	INT_KEY("client-write-timeout-s", client_write_timeout_s, 0, 86400)
	INT_KEY("idle-timeout-s", idle_timeout_s, 0, 86400 * 30)
	INT_KEY("resolver-threads", resolver_threads, 1, 256)
	INT_KEY("busy-poll-us", busy_poll_us, 0, 10000)
	BOOL_KEY("tcp-nodelay", tcp_nodelay)
	BOOL_KEY("tcp-quickack", tcp_quickack)
	INT_KEY("listen-backlog", listen_backlog, 1, 65535)
	STR_KEY("non-ws-response", non_ws_response)
	BOOL_KEY("serve-webclient", serve_webclient)
	STR_KEY("webclient-wisp-url", webclient_wisp_url)
	BOOL_KEY("stop-on-stdin-eof", stop_on_stdin_eof)
#undef BOOL_KEY
#undef INT_KEY
#undef STR_KEY
#undef DBL_KEY

	if (!strcmp(key, "log-level")) {
		int lvl = hw_log_level_parse(value);
		if (lvl < 0) goto bad_value;
		cfg->log_level = lvl;
		return 0;
	}
	if (!strcmp(key, "proxy-udp")) {
		if (!strcmp(value, "direct")) {
			cfg->proxy_udp_direct = 1;
		} else if (!strcmp(value, "refuse")) {
			cfg->proxy_udp_direct = 0;
		} else {
			goto bad_value;
		}
		return 0;
	}
	if (!strcmp(key, "udp-warp-marks")) {
		int count = hw_warp_marks_parse(value, cfg->udp_warp_marks, HW_WARP_MAX_TUNNELS);
		if (count < 0) goto bad_value;
		cfg->udp_warp_mark_count = count;
		return 0;
	}
	if (!strcmp(key, "proxy-only-to")) {
		if (cfg->proxy_only_to_count >= HW_MAX_CIDRS) {
			snprintf(err, err_cap, "too many proxy-only-to entries");
			return -1;
		}
		if (hw_cidr_parse(value, &cfg->proxy_only_to[cfg->proxy_only_to_count]) != 0) goto bad_value;
		cfg->proxy_only_to_count++;
		return 0;
	}
	if (!strcmp(key, "tcp-warp-fallback")) {
		if (!strcmp(value, "direct")) {
			cfg->tcp_warp_fallback_direct = 1;
		} else if (!strcmp(value, "refuse")) {
			cfg->tcp_warp_fallback_direct = 0;
		} else {
			goto bad_value;
		}
		return 0;
	}
	if (!strcmp(key, "udp-warp-fallback")) {
		if (!strcmp(value, "direct")) {
			cfg->udp_warp_fallback_direct = 1;
		} else if (!strcmp(value, "refuse")) {
			cfg->udp_warp_fallback_direct = 0;
		} else {
			goto bad_value;
		}
		return 0;
	}
	if (!strcmp(key, "dns-order")) {
		if (!strcmp(value, "ipv4first")) {
			cfg->dns_order = HW_DNS_IPV4_FIRST;
		} else if (!strcmp(value, "ipv6first")) {
			cfg->dns_order = HW_DNS_IPV6_FIRST;
		} else if (!strcmp(value, "verbatim")) {
			cfg->dns_order = HW_DNS_VERBATIM;
		} else {
			goto bad_value;
		}
		return 0;
	}
	if (!strcmp(key, "allow-host") || !strcmp(key, "block-host")) {
		hw_hostlist *l = key[0] == 'a' ? &cfg->allow_hosts : &cfg->block_hosts;
		if (hw_hostlist_add(l, value) != 0) {
			snprintf(err, err_cap, "%s: list full or invalid host '%s'", key, value);
			return -1;
		}
		return 0;
	}
	if (!strcmp(key, "allow-port") || !strcmp(key, "block-port")) {
		hw_portset *s = key[0] == 'a' ? &cfg->allow_ports : &cfg->block_ports;
		if (hw_portset_add(s, value) != 0) goto bad_value;
		return 0;
	}
	if (!strcmp(key, "trusted-proxy")) {
		if (cfg->trusted_proxy_count >= HW_MAX_CIDRS) {
			snprintf(err, err_cap, "too many trusted-proxy entries");
			return -1;
		}
		if (hw_cidr_parse(value, &cfg->trusted_proxies[cfg->trusted_proxy_count]) != 0) goto bad_value;
		cfg->trusted_proxy_count++;
		return 0;
	}
	if (!strcmp(key, "allow-origin")) {
		if (cfg->allow_origin_count >= HW_MAX_ORIGINS) {
			snprintf(err, err_cap, "too many allow-origin entries");
			return -1;
		}
		// What a browser sends: scheme://host[:port], nothing after it.
		const char *rest = strstr(value, "://");
		if (!rest || rest == value || rest[3] == '\0' || strpbrk(rest + 3, "/ \t") != NULL) {
			snprintf(err, err_cap, "allow-origin: expected scheme://host[:port], as in https://example.com");
			return -1;
		}
		if (set_str(cfg->allow_origins[cfg->allow_origin_count], 128, value) != 0) goto bad_value;
		cfg->allow_origin_count++;
		return 0;
	}
	if (!strcmp(key, "trusted-header")) {
		if (cfg->trusted_header_count >= HW_MAX_TRUSTED_HEADERS) {
			snprintf(err, err_cap, "too many trusted-header entries");
			return -1;
		}
		if (set_str(cfg->trusted_headers[cfg->trusted_header_count], 64, value) != 0) goto bad_value;
		cfg->trusted_header_count++;
		return 0;
	}
	if (!strcmp(key, "dns-server")) {
		if (cfg->dns_server_count >= HW_MAX_DNS_SERVERS) {
			snprintf(err, err_cap, "too many dns-server entries");
			return -1;
		}
		if (set_str(cfg->dns_servers[cfg->dns_server_count], 64, value) != 0) goto bad_value;
		cfg->dns_server_count++;
		return 0;
	}
	if (!strcmp(key, "reputation-weight") || !strcmp(key, "reputation-dest-weight")) {
		const char *colon = strrchr(value, ':');
		if (!colon) goto bad_value;
		char name[32];
		size_t nl = (size_t)(colon - value);
		if (nl >= sizeof(name)) goto bad_value;
		memcpy(name, value, nl);
		name[nl] = '\0';
		int ev = hw_rep_event_parse(name);
		if (ev < 0) {
			snprintf(err, err_cap, "%s: unknown event '%s'", key, name);
			return -1;
		}
		char *wend;
		long w = strtol(colon + 1, &wend, 10);
		if (wend == colon + 1 || *wend || w < -100 || w > 100) goto bad_value;
		if (key[11] == 'd') {
			cfg->reputation.dest_weights[ev] = (int)w;
		} else {
			cfg->reputation.source_weights[ev] = (int)w;
		}
		return 0;
	}
	if (!strcmp(key, "trusted-headers-reset")) {
		cfg->trusted_header_count = 0;
		return 0;
	}
	if (!strcmp(key, "password-user")) {
		// The value holds a password: an error names the key, never the value.
		const char *colon = strchr(value, ':');
		char user[64];
		size_t ulen = colon ? (size_t)(colon - value) : 0;
		if (!colon || colon == value || ulen >= sizeof(user)) {
			snprintf(err, err_cap, "password-user: expected USER:PASS with a user name of 1 to 63 bytes");
			return -1;
		}
		memcpy(user, value, ulen);
		user[ulen] = '\0';
		if (hw_server_config_add_user(cfg, user, colon + 1) != 0) {
			snprintf(err, err_cap, "password-user: %s",
			         errno == ENOSPC ? "too many users" : "the password is empty, or a field is too long");
			return -1;
		}
		return 0;
	}
	snprintf(err, err_cap, "unknown option '%s'", key);
	return -1;
bad_value:
	// A value that may hold a credential is never repeated: this text goes to the log.
	if (!strcmp(key, "proxy") || !strcmp(key, "trusted-proxy-secret") || !strcmp(key, "proxy-client-key-secret")) {
		snprintf(err, err_cap, "bad value for '%s' (not shown: it may hold a secret)", key);
	} else {
		snprintf(err, err_cap, "bad value '%s' for '%s'", value, key);
	}
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
		if (value[0] == '"') {
			// Quoted value: keep everything up to the closing quote (so it may hold '#' or spaces),
			// then drop the quotes. Anything after the close quote (e.g. a comment) is ignored.
			char *close = strchr(value + 1, '"');
			if (close) {
				*close = '\0';
				value++;
			}
		} else {
			// Strip an inline comment: the first '#' that starts the token or follows whitespace.
			for (char *p = value; *p; p++) {
				if (*p == '#' && (p == value || p[-1] == ' ' || p[-1] == '\t')) {
					*p = '\0';
					break;
				}
			}
			value = trim(value);
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
	printf(
	    "usage: %s [--config FILE] [--KEY VALUE | --KEY=VALUE]...\n"
	    "\n"
	    "A Wisp v1/v2 server. Every KEY below is also a `KEY = VALUE` line in the config file.\n"
	    "\n"
	    "  host, port, workers                       bind address, port (6001), worker threads (0 = CPUs)\n"
	    "  allow-tcp, allow-udp                      stream types (both on)\n"
	    "  allow-direct-ip                           literal IPs in CONNECT (off)\n"
	    "  allow-private, allow-loopback,            egress to RFC 1918 / 127.0.0.0/8 / 169.254.0.0/16 (all off)\n"
	    "  allow-link-local\n"
	    "  allow-host, block-host                    hostname allow/block lists; '*.suffix' matches subdomains\n"
	    "  allow-port, block-port                    port allow/block lists; 'N' or 'LO-HI' (repeatable)\n"
	    "  enable-v2, motd                           Wisp v2 handshake (on), message of the day\n"
	    "  enable-twisp                              PTY terminal streams; needs v2 + an authenticated client (off)\n"
	    "  password-user USER:PASS                   v2 auth user; PASS may be a crypt(3) hash (repeatable)\n"
	    "  password-required                         refuse unauthenticated v2 clients (off)\n"
	    "  parse-real-ip, trusted-proxy CIDR,        honour proxy headers from trusted sources\n"
	    "  trusted-header NAME                       (default header: X-Forwarded-For)\n"
	    "  trusted-proxy-secret VALUE                a trusted proxy must also send X-HolyWisp-Proxy-Secret: VALUE\n"
	    "  allow-origin ORIGIN                       only pages of these origins may connect, e.g.\n"
	    "                                            https://example.com (repeatable; default: any page)\n"
	    "  connections-limit-per-ip, connection-window-s   new WebSockets per IP per window (200 / 10s)\n"
	    "  bandwidth-limit-kbps                      per-IP bandwidth cap, each direction (0 = off)\n"
	    "  flood-protection                          master switch for the limits below (on)\n",
	    argv0);
	// Three calls: one string literal may not be longer than 4095 bytes.
	printf(
	    "  max-connects-per-source-per-second        per client IP (500)\n"
	    "  max-connects-per-dest-per-second/-minute  per destination ip:port (100 / 3000)\n"
	    "  max-in-flight-syns, max-concurrent-connections   server-wide caps (4096 / 50000)\n"
	    "  max-in-flight-syns-per-ip,                the same per client IP, so one client cannot hold them\n"
	    "  max-concurrent-connections-per-ip         all (512 / 5000)\n"
	    "  syn-signature, syn-signature-window-ms,   SYN-flood heuristic (on, 2000ms, 128, 0.75)\n"
	    "  syn-signature-min-samples, syn-signature-failed-ratio\n"
	    "  ws-close-after-violations                 drop a client after this many flood hits (64)\n"
	    "  reputation, reputation-store,             IP reputation scoring, persisted as JSON\n"
	    "  reputation-{warn,throttle,strict},        score thresholds (21 / 51 / 81)\n"
	    "  reputation-decay-per-hour, reputation-evict-after-days,\n"
	    "  reputation-weight EVENT:N, reputation-dest-weight EVENT:N\n"
	    "  proxy URL                                 upstream socks5:// (socks5h://) or http:// for outbound TCP\n"
	    "  proxy-udp direct|refuse                   with a proxy: relay UDP directly, or refuse it (refuse)\n"
	    "  proxy-only-to CIDR                        with a proxy: only TCP that resolved into these goes through it;\n"
	    "                                            the rest is dialled here (repeatable; none = all TCP proxied)\n"
	    "  proxy-client-key BOOL                     give the proxy a key per client as its user name, and pick\n"
	    "                                            a WARP tunnel for UDP by client and site (off)\n"
	    "  proxy-client-key-secret S                 what the keys are made with, 16+ characters (random per start)\n"
	    "  udp-warp-marks M,M,...                    UDP through WARP (Linux, CAP_NET_ADMIN): the tunnels' fwmarks\n"
	    "  udp-warp-state PATH                       the router's healthy tunnels (JSON), re-read when it changes\n"
	    "  udp-warp-state-max-age-s                  an older state file is ignored: UDP goes unmarked (60; 0 = never)\n"
	    "  udp-warp-fallback direct|refuse           no healthy tunnel for the family: unmarked, or refuse (refuse)\n"
	    "  tcp-warp BOOL                             mark TCP dialled here (not proxied) from the same state (off)\n"
	    "  tcp-warp-fallback direct|refuse           TCP with no tunnel, no usable state or no mark (refuse)\n"
	    "  dns-server, dns-ttl-s, dns-negative-ttl-s, dns-order, dns-timeout-ms\n");
	printf("  buffer-remaining                          CONTINUE window in packets (128)\n"
	       "  stream-queue-max, conn-queue-max          bytes queued toward remotes: per stream (128 MiB, closes\n"
	       "                                            0x49), per client (256 MiB, pauses its reads)\n"
	       "  max-message-size, ws-write-high-water, socket-buffer-size\n"
	       "  client-recv-buffer                        SO_RCVBUF for client sockets when the host's rmem_max allows\n"
	       "                                            it (8 MiB; 0 = leave to the kernel)\n"
	       "  max-streams-per-conn                      0 = unlimited (2048)\n"
	       "  connect-timeout-ms, handshake-timeout-ms  15000, 10000\n"
	       "  family-fallback-ms                        a connect with the other family still to try: at most (3000)\n"
	       "  client-write-timeout-s                    close a client that has read nothing of what is queued\n"
	       "                                            for it for this long (120; 0 = never)\n"
	       "  idle-timeout-s                            close a client with no streams that sent nothing for\n"
	       "                                            this long (0 = never)\n"
	       "  busy-poll-us                              after a busy loop iteration, poll this many microseconds\n"
	       "                                            before sleeping: lower latency, more CPU (0 = off)\n"
	       "  resolver-threads, tcp-nodelay, tcp-quickack, listen-backlog, non-ws-response\n"
	       "  serve-webclient                           serve the built-in browser client on GET / (on)\n"
	       "  webclient-wisp-url URL                    ws(s):// URL the web client offers by default (its origin)\n"
	       "  log-level                                 debug|info|warn|error|none (info)\n"
	       "  stop-on-stdin-eof                         shut down when stdin closes: for a parent process that\n"
	       "                                            holds a pipe to it, never under a service manager (off)\n"
	       "\n"
	       "  --version, --help\n");
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
			printf("holywisp %s%s\n", HW_VERSION, HW_VERSION_SUFFIX);
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
