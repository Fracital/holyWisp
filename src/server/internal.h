/*
 * server/internal.h - the server's private structures, shared by server.c, conn.c, stream.c,
 * proxy.c, twisp.c and egress.c. Not installed.
 *
 * Threads: hw_server is created and torn down by the controlling thread. Each hw_worker runs its
 * own loop thread and owns every hw_conn and hw_stream it accepted. The limiters, the reputation
 * table and the DNS cache are shared and lock internally; the _Atomic counters are the only other
 * thing touched from more than one thread.
 */
#ifndef HOLYWISP_SERVER_INTERNAL_H
#define HOLYWISP_SERVER_INTERNAL_H

#include "holywisp/buf.h"
#include "holywisp/filter.h"
#include "holywisp/limits.h"
#include "holywisp/loop.h"
#include "holywisp/map.h"
#include "holywisp/net.h"
#include "holywisp/reputation.h"
#include "holywisp/server.h"
#include "holywisp/smap.h"

#include <pthread.h>
#include <stdatomic.h>

#include <sys/types.h>

#define HW_READ_CHUNK       (64 * 1024) // one recv(2) from a remote or a client
#define HW_STREAM_MAX_ADDRS 8           // addresses tried per CONNECT, in resolver order

typedef struct hw_worker {
	hw_server *server;
	hw_loop *loop;
	int listen_fd;
	int index;
	pthread_t thread;
	int thread_started;
	uint8_t *scratch;      // HW_READ_CHUNK bytes for remote reads
	struct hw_conn *conns; // every live connection on this worker, for shutdown cleanup
} hw_worker;

enum proxy_kind {
	PROXY_NONE = 0,
	PROXY_SOCKS5,
	PROXY_HTTP
};

typedef struct hw_proxy_config {
	enum proxy_kind kind;
	char host[256];
	uint16_t port;
	char user[128];
	char pass[128];
	struct sockaddr_storage addr; // resolved once at startup
	socklen_t addr_len;
} hw_proxy_config;

struct hw_server {
	hw_server_config cfg;
	hw_worker *workers;
	int nworkers;
	hw_resolver *resolver;
	hw_dns_cache *dns_cache;
	hw_proxy_config proxy;
	uint16_t port;
	int started;
	_Atomic int stopped;
	uint64_t started_ms;

	// Shared limiters (NULL / max 0 when disabled).
	hw_window *conn_rate;    // new WebSockets per client IP
	hw_window *per_source;   // CONNECTs per client IP per second
	hw_window *per_dest_sec; // CONNECTs per destination per second
	hw_window *per_dest_min; // ... per minute
	hw_semaphore in_flight_syns;
	hw_semaphore connections;
	hw_bandwidth *bandwidth;
	hw_reputation *reputation;

	// Maintenance thread: evictions, reputation decay and saves, DNS cache expiry.
	pthread_t maint_thread;
	int maint_started;
	pthread_mutex_t maint_lock;
	pthread_cond_t maint_cond;
	int maint_stop;
	uint64_t maint_last_slow; // last eviction/decay pass (ms)
	uint64_t maint_last_save; // last reputation save (ms)

	_Atomic uint64_t connections_total;
	_Atomic uint64_t connections_active;
	_Atomic uint64_t streams_total;
	_Atomic uint64_t streams_active;
	_Atomic uint64_t bytes_in;
	_Atomic uint64_t bytes_out;
	_Atomic uint64_t refused_connection_rate;
	_Atomic uint64_t refused_connection_limit;
	_Atomic uint64_t refused_reputation;
	_Atomic uint64_t blocked_filter;
	_Atomic uint64_t blocked_egress;
	_Atomic uint64_t throttled_source;
	_Atomic uint64_t throttled_dest;
	_Atomic uint64_t throttled_syns;
	_Atomic uint64_t syn_signatures;
	_Atomic uint64_t ws_closed_violations;
	_Atomic uint64_t auth_failures;
};

#define HW_STAT_INC(server, field) atomic_fetch_add(&(server)->field, 1)

enum conn_state {
	CONN_HTTP = 0,   // reading the request head
	CONN_HTTP_REPLY, // plain HTTP response queued; close once flushed
	CONN_WS,         // WebSocket established
	CONN_CLOSED
};

// One WebSocket client. Owned by its worker's loop thread.
typedef struct hw_conn {
	hw_worker *w;
	int fd;
	enum conn_state state;
	hw_buf rbuf; // bytes from the client not yet parsed
	hw_buf wbuf; // frames to the client not yet written
	hw_buf frag; // reassembly of a fragmented binary message
	int frag_active;
	hw_map streams;  // stream_id -> hw_stream
	hw_smap sigdets; // "ip:port" -> hw_sigdet (SYN-flood signature per destination)
	int is_v2;
	int handshake_done; // v2: client INFO received; v1: always
	int stream_confirm; // v2 extension: CONTINUE a stream once it connects
	int authenticated;
	hw_timer *handshake_timer;
	hw_timer *throttle_timer; // bandwidth pause
	int throttled;            // reads suspended until throttle_timer fires
	int write_armed;          // HW_EV_WRITE requested
	int paused;               // remote reads suspended: wbuf past the high-water mark
	int closing;
	int violations;
	int conn_slot;  // holds one of server->connections
	int stream_cap; // effective max streams (reputation THROTTLE tier lowers it)
	enum hw_rep_tier tier;
	char peer[HW_ADDR_STR_LEN]; // socket peer, with port, for logs
	char ip[HW_IP_STR_LEN];     // client IP after trusted-proxy headers, for policy
	struct sockaddr_storage peer_addr;
	struct hw_conn *lprev, *lnext; // worker->conns list
} hw_conn;

enum stream_state {
	STREAM_RESOLVING = 0,
	STREAM_CONNECTING,
	STREAM_PROXY, // TCP to the proxy is up; SOCKS5/CONNECT handshake in progress
	STREAM_OPEN,
	STREAM_CLOSED
};

enum proxy_phase {
	PROXY_PHASE_GREETING = 0, // SOCKS5: waiting for the method choice
	PROXY_PHASE_AUTH,         // SOCKS5: waiting for the username/password result
	PROXY_PHASE_CONNECT       // SOCKS5: waiting for the reply; HTTP: waiting for the status
};

// One relayed TCP, UDP or PTY stream. Owned by its connection's loop thread.
typedef struct hw_stream {
	hw_conn *conn;
	uint32_t id;
	uint8_t type; // HW_STREAM_TCP / HW_STREAM_UDP / HW_STREAM_TERM
	enum stream_state state;
	int fd;
	hw_buf out;         // toward the remote; UDP entries are [u32 len][datagram]
	uint32_t remaining; // DATA packets left before we owe the client a CONTINUE
	int continue_due;   // the window closed while `out` still had bytes queued
	int read_armed;
	int syn_held; // holds one of server->in_flight_syns
	hw_resolve_req *resolve;
	hw_timer *connect_timer;
	struct sockaddr_storage addrs[HW_STREAM_MAX_ADDRS];
	socklen_t addr_lens[HW_STREAM_MAX_ADDRS];
	int naddrs;
	int addr_idx;
	char dest[HW_IP_STR_LEN + 8]; // "ip:port" of the address being tried
	char host[256];
	uint16_t port;
	// Upstream proxy handshake.
	enum proxy_phase proxy_phase;
	hw_buf pin;
	// Twisp.
	pid_t pid;
} hw_stream;

// conn.c
void conn_accept(hw_worker *w, int fd, const struct sockaddr *peer);
// Queue one Wisp packet (already laid out) as a binary WebSocket frame.
int conn_send_packet(hw_conn *c, const uint8_t *packet, size_t len);
// Queue a DATA packet for stream_id with `len` payload bytes copied from `data`.
int conn_send_data(hw_conn *c, uint32_t stream_id, const uint8_t *data, size_t len);
int conn_send_continue(hw_conn *c, uint32_t stream_id, uint32_t remaining);
int conn_send_close(hw_conn *c, uint32_t stream_id, uint8_t reason);
// Flush what can be written now; arms HW_EV_WRITE for the rest. Closes the conn on error.
void conn_flush(hw_conn *c);
// Tear down the client and all its streams; the memory is released on the next loop iteration.
void conn_close(hw_conn *c);
// Shutdown only: tear down and free a connection synchronously (the loop is no longer running).
void conn_shutdown_free(hw_conn *c);
// Flood-protection violation: counts toward ws-close-after-violations. Returns 1 if that closed
// the connection.
int conn_violation(hw_conn *c, const char *reason);
// Bandwidth accounting for `bytes` in either direction; pauses the connection when over budget.
void conn_charge_bandwidth(hw_conn *c, size_t bytes);
// Reputation shortcuts (no-ops when disabled).
void conn_rep_source(hw_conn *c, enum hw_rep_event e);
void conn_rep_dest(hw_conn *c, const char *dest, enum hw_rep_event e);

// stream.c
void stream_open(hw_conn *c, uint32_t id, uint8_t type, const char *host, size_t host_len, uint16_t port);
// DATA from the client. Takes care of flow control and queuing.
void stream_on_data(hw_stream *s, const uint8_t *data, size_t len);
// Close the remote side, tell the client when send_close, remove from the connection, free.
void stream_close(hw_stream *s, uint8_t reason, int send_close);
// Stop/resume reading from the remote (connection-level backpressure).
void stream_pause(hw_stream *s);
void stream_resume(hw_stream *s);
// The remote (or proxy handshake) is up: finish opening the stream toward the client.
void stream_connected(hw_stream *s);
// Adopt an already-connected fd (a PTY master for Twisp): register it on the loop and open the
// stream. Closes the stream on failure.
void stream_adopt(hw_stream *s, int fd);
// Allocate and register a stream in state RESOLVING with no fd. NULL when the connection refused
// it (a CLOSE has been sent).
hw_stream *stream_new(hw_conn *c, uint32_t id, uint8_t type, const char *host, size_t host_len, uint16_t port);

// proxy.c
// Parse "socks5://[user:pass@]host[:port]" / "http://..." into out. -1 with err on a bad URL.
int proxy_config_parse(const char *url, hw_proxy_config *out, char *err, size_t err_cap);
// Resolve the proxy host once. -1 with errno when it cannot be resolved.
int proxy_config_resolve(hw_proxy_config *p);
// The TCP connection to the proxy is up: send the first handshake bytes. -1 = stream closed.
int proxy_start(hw_stream *s);
// Bytes arrived from the proxy during the handshake. 1 = done (stream_connected was called),
// 0 = need more, -1 = failed (stream closed).
int proxy_on_data(hw_stream *s, const uint8_t *data, size_t len);

// twisp.c
// CONNECT with stream type TERM: fork a PTY running `command`. Sends CLOSE on failure.
void twisp_open(hw_conn *c, uint32_t id, const char *command, size_t len);
void twisp_resize(hw_stream *s, uint16_t rows, uint16_t cols);
// Called from stream_close for TERM streams: kill and forget the child.
void twisp_kill(hw_stream *s);

// egress.c: 0 when the policy lets a remote address through, -1 (with the class in *why) when not.
int egress_allowed(const hw_server_config *cfg, const struct sockaddr *sa, enum hw_addr_class *why);

// server.c
void server_tune_socket(const hw_server *s, int fd, int is_tcp);

#endif
