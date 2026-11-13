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
#include "holywisp/warp.h"

#include <stddef.h>
#include <stdint.h>

#define HW_MAX_PASSWORD_USERS  64
#define HW_MAX_TRUSTED_HEADERS 8
#define HW_MAX_ORIGINS         32
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
	int max_in_flight_syns;                // TCP connects in progress, server-wide
	int max_in_flight_syns_per_ip;         // ... and per client IP, so one client cannot hold them all
	int max_concurrent_connections;        // WebSocket clients, server-wide
	int max_concurrent_connections_per_ip; // ... and per client IP
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
	// When set, a trusted proxy is believed only on a request that carries this value in
	// X-HolyWisp-Proxy-Secret: an address in trusted_proxies is then not enough, which matters
	// when the proxy is on loopback and any local process shares its address.
	char trusted_proxy_secret[128];

	// Pages that may open a connection, as the browser names them in Origin ("https://host[:port]",
	// compared without regard to case). Empty: any page. A request with no Origin header is not
	// from a browser and is always let through.
	char allow_origins[HW_MAX_ORIGINS][128];
	int allow_origin_count;

	// Per-client limits.
	int connections_limit_per_ip; // new WebSockets per IP per window; 0 = off
	int connection_window_s;
	int bandwidth_limit_kbps; // per IP, both directions; 0 = off
	hw_flood_config flood;
	int reputation_enabled;
	hw_reputation_config reputation;

	// Where streams go.
	char proxy[256];      // socks5://[user:pass@]host:port or http://[user:pass@]host:port; "" = direct
	int proxy_udp_direct; // with a proxy: relay UDP directly (1) instead of refusing it (0)
	// Exit per client and site: the proxy is given each client's key (hw_warp_client_key) as its
	// user name, and the UDP WARP pick hashes "key/site". The secret makes the keys; empty means a
	// random one per process, and then a restart gives every client a new key.
	int proxy_client_key;
	char proxy_client_key_secret[128];
	// UDP through WARP tunnels (Linux, CAP_NET_ADMIN): a UDP socket is given the firewall mark of
	// the tunnel the edge router would send its site through (holywisp/warp.h). The marks the
	// state file may choose from, and the file the router publishes its healthy tunnels in. Both,
	// or neither. A file that is missing, unreadable, malformed or older than the max age means
	// no marks: UDP goes out directly, as it does without these keys.
	uint32_t udp_warp_marks[HW_WARP_MAX_TUNNELS];
	int udp_warp_mark_count;
	char udp_warp_state[256];
	int udp_warp_state_max_age_s;             // 0 = never too old
	int udp_warp_fallback_direct;             // the file lists no tunnel for the family: direct (1) or refuse (0)
	char dns_servers[HW_MAX_DNS_SERVERS][64]; // "ip" or "ip:port"; empty = system resolver
	int dns_server_count;
	int dns_ttl_s;          // cache lifetime cap
	int dns_negative_ttl_s; // failed lookups
	int dns_order;          // enum hw_dns_order
	int dns_timeout_ms;

	// Limits and tuning.
	uint32_t buffer_remaining;  // CONTINUE window in packets (Wisp "buffer size")
	size_t max_message_size;    // largest WebSocket message accepted (1024 or more)
	size_t ws_write_high_water; // pause remote reads when a client's send queue grows past this
	size_t stream_queue_max;    // bytes queued toward a remote before the stream is throttled
	size_t conn_queue_max;      // bytes queued toward remotes across one client before its reads pause
	size_t socket_buffer_size;  // SO_RCVBUF/SO_SNDBUF; 0 = kernel default
	size_t client_recv_buffer;  // SO_RCVBUF on client sockets when socket_buffer_size is 0; 0 = kernel
	int max_streams_per_conn;   // 0 = unlimited
	int connect_timeout_ms;     // remote TCP connect
	int handshake_timeout_ms;   // HTTP upgrade + v2 INFO exchange
	// A client whose send queue holds bytes and has taken none of them for this long is closed:
	// it is not reading, and everything the server keeps for it is memory it will never free.
	// 0 = never.
	int client_write_timeout_s;
	// A client with no streams that has sent nothing for this long is closed. 0 = never (default).
	int idle_timeout_s;
	int resolver_threads;
	// Microseconds a worker keeps polling after an iteration that had events before it sleeps.
	// Lowers round-trip latency under load at the cost of CPU time spent waiting; 0 = always sleep.
	int busy_poll_us;
	int tcp_nodelay;
	int tcp_quickack;
	int listen_backlog;
	char non_ws_response[256]; // body for plain HTTP GETs that are not the web client
	int serve_webclient;       // serve the built-in browser client on GET /
	// ws:// or wss:// URL the web client offers as its default Wisp server. Empty: the client's own
	// origin. For when the relay is not the origin that served the page. Spliced into the page as
	// window.HOLYWISP_CONFIG.wisp; a value that cannot go into a script string is rejected.
	char webclient_wisp_url[256];
	int log_level;
	// For the `holywisp` binary when another program runs it: stop when standard input reaches end
	// of file, which is what a child holding a pipe from its parent sees when the parent dies, however
	// it dies. Not for a service manager, whose stdin is /dev/null and at end of file from the start.
	int stop_on_stdin_eof;
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
	uint64_t udp_warp_marked;  // UDP streams dialled through a WARP tunnel
	uint64_t udp_warp_direct;  // UDP streams with udp-warp-marks dialled unmarked: no usable state, or fallback
	uint64_t udp_warp_refused; // UDP streams refused: no tunnel for the family and udp-warp-fallback refuse
	uint64_t syn_signatures;   // SYN-flood matches
	uint64_t ws_closed_violations;
	uint64_t auth_failures;
	uint64_t dns_cache_entries;
	uint64_t reputation_sources;
	uint64_t reputation_dests;
	// Connections on the worker that has the fewest and on the one that has the most. A new
	// connection goes to the worker with the fewest, so these stay within one of each other
	// while connections only arrive.
	uint64_t worker_connections_min;
	uint64_t worker_connections_max;
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
