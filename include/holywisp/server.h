/*
 * holywisp/server.h - the Wisp server as a library.
 *
 * hw_server_new() binds the listeners (so the port is known before anything runs), hw_server_run()
 * or hw_server_start() spins up the workers, hw_server_stop() is callable from any thread or a
 * signal handler's deferred path, hw_server_free() joins and releases everything.
 */
#ifndef HOLYWISP_SERVER_H
#define HOLYWISP_SERVER_H

#include <stddef.h>
#include <stdint.h>

#define HW_MAX_PASSWORD_USERS 32

typedef struct hw_password_user {
	char user[64];
	char pass[128];
} hw_password_user;

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

	// Protocol.
	int enable_v2;
	char motd[512];
	hw_password_user password_users[HW_MAX_PASSWORD_USERS];
	int password_user_count;
	int password_required;

	// Limits and tuning.
	uint32_t buffer_remaining;  // CONTINUE window in packets (Wisp "buffer size")
	size_t max_message_size;    // largest WebSocket message accepted
	size_t ws_write_high_water; // pause remote reads when a client's send queue grows past this
	size_t stream_queue_max;    // bytes queued toward a remote before the stream is throttled
	int max_streams_per_conn;   // 0 = unlimited
	int connect_timeout_ms;     // remote TCP connect
	int handshake_timeout_ms;   // HTTP upgrade + v2 INFO exchange
	int resolver_threads;
	int tcp_nodelay;
	int listen_backlog;
	char non_ws_response[256]; // body for plain HTTP GETs
	int log_level;
} hw_server_config;

typedef struct hw_server_stats {
	uint64_t connections_total;
	uint64_t connections_active;
	uint64_t streams_total;
	uint64_t streams_active;
	uint64_t bytes_in;  // client -> remote
	uint64_t bytes_out; // remote -> client
} hw_server_stats;

typedef struct hw_server hw_server;

void hw_server_config_defaults(hw_server_config *cfg);
// Add a password user. -1 (ENOSPC / EINVAL) when the table is full or a field is too long.
int hw_server_config_add_user(hw_server_config *cfg, const char *user, const char *pass);

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

#endif
