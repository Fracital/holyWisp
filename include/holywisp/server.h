/*
 * holywisp/server.h - the Wisp server as a library.
 *
 * hw_server_new() binds the listeners (so the port is known before anything runs), hw_server_run()
 * or hw_server_start() spins up the workers, hw_server_stop() is callable from any thread or a
 * signal handler's deferred path, hw_server_free() joins and releases everything.
 */
#ifndef HOLYWISP_SERVER_H
#define HOLYWISP_SERVER_H

#include "holywisp/dns.h"
#include "holywisp/filter.h"
#include "holywisp/reputation.h"

#include <stddef.h>
#include <stdint.h>

#define HW_MAX_PASSWORD_USERS  64
#define HW_MAX_TRUSTED_HEADERS 8
#define HW_MAX_DNS_SERVERS     8

typedef struct hw_password_user {
	char user[64];
	char pass[128]; // plain text, or a crypt(3) hash starting with '$' ($2b$, $6$, $y$ ...)
} hw_password_user;

typedef struct hw_flood_config {
	int enabled;
	int max_connects_per_source_per_second; // CONNECT packets per client IP
	int max_connects_per_dest_per_second;   // keyed by resolved ip:port
	int max_connects_per_dest_per_minute;
	int max_in_flight_syns;         // TCP connects in progress, server-wide
	int max_concurrent_connections; // WebSocket clients, server-wide
	int syn_signature_enabled;
	int syn_signature_window_ms;
	int syn_signature_min_samples;
	double syn_signature_failed_ratio;
	int ws_close_after_violations; // 0 = never
	int log_blocked_dials;
} hw_flood_config;

typedef struct hw_server_config {
	char host[256]; // bind address; "" = all interfaces
	uint16_t port;
	int workers; // 0 = one per CPU

	// What clients may reach.
	int allow_tcp;
	int allow_udp;
	int allow_direct_ip; // literal IPs in CONNECT
	int allow_private;   // RFC 1918 etc.
	int allow_loopback;
	int allow_link_local;
	hw_hostlist allow_hosts; // when non-empty, only these
	hw_hostlist block_hosts;
	hw_portset allow_ports; // when non-empty, only these
	hw_portset block_ports;

	// Protocol.
	int enable_v2;
	int enable_twisp; // PTY streams; needs v2 + password auth
	char motd[512];
	hw_password_user password_users[HW_MAX_PASSWORD_USERS];
	int password_user_count;
	int password_required;

	// Who the client is.
	int parse_real_ip;
	hw_cidr trusted_proxies[HW_MAX_CIDRS];
	int trusted_proxy_count;
	char trusted_headers[HW_MAX_TRUSTED_HEADERS][64];
	int trusted_header_count;

	// Per-client limits.
	int connections_limit_per_ip; // new WebSockets per IP per window; 0 = off
	int connection_window_s;
	int bandwidth_limit_kbps; // per IP, both directions; 0 = off
	hw_flood_config flood;
	int reputation_enabled;
	hw_reputation_config reputation;

	// Where streams go.
	char proxy[256]; // socks5://[user:pass@]host:port or http://[user:pass@]host:port; "" = direct
	char dns_servers[HW_MAX_DNS_SERVERS][64]; // "ip" or "ip:port"; empty = system resolver
	int dns_server_count;
	int dns_ttl_s;          // cache lifetime cap
	int dns_negative_ttl_s; // failed lookups
	int dns_order;          // enum hw_dns_order
	int dns_timeout_ms;

	// Limits and tuning.
	uint32_t buffer_remaining;  // CONTINUE window in packets (Wisp "buffer size")
	size_t max_message_size;    // largest WebSocket message accepted
	size_t ws_write_high_water; // pause remote reads when a client's send queue grows past this
	size_t stream_queue_max;    // bytes queued toward a remote before the stream is throttled
	size_t socket_buffer_size;  // SO_RCVBUF/SO_SNDBUF; 0 = kernel default
	int max_streams_per_conn;   // 0 = unlimited
	int connect_timeout_ms;     // remote TCP connect
	int handshake_timeout_ms;   // HTTP upgrade + v2 INFO exchange
	int resolver_threads;
	int tcp_nodelay;
	int tcp_quickack;
	int listen_backlog;
	char non_ws_response[256]; // body for plain HTTP GETs that are not the web client
	int serve_webclient;       // serve the built-in browser client on GET /
	int log_level;
} hw_server_config;

typedef struct hw_server_stats {
	uint64_t uptime_s;
	uint64_t connections_total;
	uint64_t connections_active;
	uint64_t streams_total;
	uint64_t streams_active;
	uint64_t bytes_in;  // client -> remote
	uint64_t bytes_out; // remote -> client
	// Refusals, by cause.
	uint64_t refused_connection_rate;
	uint64_t refused_connection_limit;
	uint64_t refused_reputation;
	uint64_t blocked_filter;   // host/port lists
	uint64_t blocked_egress;   // address policy
	uint64_t throttled_source; // per-source connect rate
	uint64_t throttled_dest;   // per-destination connect rate
	uint64_t throttled_syns;   // in-flight SYN cap
	uint64_t syn_signatures;   // SYN-flood matches
	uint64_t ws_closed_violations;
	uint64_t auth_failures;
	uint64_t dns_cache_entries;
	uint64_t reputation_sources;
	uint64_t reputation_dests;
} hw_server_stats;

typedef struct hw_server hw_server;

void hw_server_config_defaults(hw_server_config *cfg);
// Add a password user. -1 (ENOSPC / EINVAL) when the table is full or a field is too long.
int hw_server_config_add_user(hw_server_config *cfg, const char *user, const char *pass);
// Cross-field checks. 0 ok, -1 with a message in err.
int hw_server_config_validate(const hw_server_config *cfg, char *err, size_t err_cap);

// Binds the listeners. NULL with errno on failure.
hw_server *hw_server_new(const hw_server_config *cfg);
uint16_t hw_server_port(const hw_server *s);
// Spawn the workers and return. 0 on success.
int hw_server_start(hw_server *s);
// Start, then block until stopped. Returns what hw_server_start returned.
int hw_server_run(hw_server *s);
// Stop the workers. Thread-safe and idempotent.
void hw_server_stop(hw_server *s);
// Joins the workers if they are running, closes everything.
void hw_server_free(hw_server *s);
void hw_server_stats_get(const hw_server *s, hw_server_stats *out);
// The live reputation table (NULL when disabled), for tests and tooling.
hw_reputation *hw_server_reputation(const hw_server *s);

#endif
